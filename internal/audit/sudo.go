package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

const (
	sudoersFile = "/etc/sudoers"
	// maxSudoDepth — вложенность include.
	maxSudoDepth = 8
	// maxSudoFiles — сколько файлов sudoers читать.
	maxSudoFiles = 256
	// maxAliasDepth — глубина раскрытия алиасов (алиас из алиасов).
	maxAliasDepth = 8
)

// sudoCmd — одна разрешённая (или запрещённая через «!») команда.
type sudoCmd struct {
	Raw      string // как записано (после раскрытия алиаса)
	Path     string // первое слово
	Args     string // остальное
	All      bool   // ALL — любая команда
	Runas    string // «(root)», «(ALL : ALL)»; "" — root по умолчанию
	NoPasswd bool
	Negated  bool
}

// sudoSpec — правило «кто где = что».
type sudoSpec struct {
	File string
	Line int
	Text string
	Who  []string
	Cmds []sudoCmd
}

// sudoDefault — строка Defaults.
type sudoDefault struct {
	File   string
	Line   int
	Text   string
	Params []string
}

// sudoers — разобранная конфигурация sudo.
type sudoers struct {
	Found      bool
	Unreadable bool
	Files      []string
	Hashes     map[string]string // путь → SHA-256 содержимого
	Specs      []sudoSpec
	Defaults   []sudoDefault
	CmndAlias  map[string][]string
	UserAlias  map[string][]string
}

// sudoTags — теги команд. PASSWD отменяет NOPASSWD.
var sudoTags = map[string]bool{"NOPASSWD": true, "PASSWD": true, "NOEXEC": true, "EXEC": true, "SETENV": true, "NOSETENV": true,
	"LOG_INPUT": true, "NOLOG_INPUT": true, "LOG_OUTPUT": true, "NOLOG_OUTPUT": true, "MAIL": true, "NOMAIL": true,
	"FOLLOW": true, "NOFOLLOW": true, "INTERCEPT": true, "NOINTERCEPT": true}

var (
	aliasLine   = regexp.MustCompile(`^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|Cmd_Alias)\s+(.+)$`)
	aliasDef    = regexp.MustCompile(`^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*)$`)
	defaultLine = regexp.MustCompile(`^Defaults([:@>!]\S+)?\s+(.+)$`)
	tagPrefix   = regexp.MustCompile(`^([A-Z_]+):\s*`)
	optPrefix   = regexp.MustCompile(`^[A-Z_]+=\S+\s+`)
	includeLine = regexp.MustCompile(`^[#@](include|includedir)\s+(.+)$`)
)

func (a *auditor) parseSudoers() *sudoers {
	s := &sudoers{Hashes: map[string]string{}, CmndAlias: map[string][]string{}, UserAlias: map[string][]string{}}
	data, err := a.read(sudoersFile, true)
	if err != nil {
		s.Unreadable = isPerm(err)
		return s
	}
	s.Found = true
	a.parseSudoFile(s, sudoersFile, data, 0)
	return s
}

func (a *auditor) parseSudoFile(s *sudoers, file string, data []byte, depth int) {
	if slices.Contains(s.Files, file) || len(s.Files) >= maxSudoFiles {
		return
	}
	s.Files = append(s.Files, file)
	sum := sha256.Sum256(data)
	s.Hashes[file] = hex.EncodeToString(sum[:])
	for _, ln := range logicalLines(string(data)) {
		text := ln.text
		if m := includeLine.FindStringSubmatch(text); m != nil {
			if depth < maxSudoDepth {
				a.sudoInclude(s, file, m[1], strings.Trim(strings.TrimSpace(m[2]), `"`), depth)
			}
			continue
		}
		text = stripSudoComment(text)
		if text == "" {
			continue
		}
		switch {
		case aliasLine.MatchString(text):
			m := aliasLine.FindStringSubmatch(text)
			for _, def := range splitAliasDefs(m[2]) {
				d := aliasDef.FindStringSubmatch(def)
				if d == nil {
					continue
				}
				items := splitTop(d[2], ',')
				switch m[1] {
				case "Cmnd_Alias", "Cmd_Alias":
					s.CmndAlias[d[1]] = items
				case "User_Alias":
					s.UserAlias[d[1]] = items
				}
			}
		case defaultLine.MatchString(text):
			m := defaultLine.FindStringSubmatch(text)
			var params []string
			for _, p := range splitTop(m[2], ',') {
				params = append(params, strings.TrimSpace(p))
			}
			s.Defaults = append(s.Defaults, sudoDefault{File: file, Line: ln.line, Text: text, Params: params})
		case strings.Contains(text, "="):
			if spec, ok := s.parseSpec(text); ok {
				spec.File, spec.Line, spec.Text = file, ln.line, text
				s.Specs = append(s.Specs, spec)
			}
		}
	}
}

// sudoInclude раскрывает @include / @includedir. Относительный путь —
// от каталога текущего файла. В includedir sudo пропускает файлы с
// точкой в имени и оканчивающиеся на «~».
func (a *auditor) sudoInclude(s *sudoers, from, kind, target string, depth int) {
	if strings.Contains(target, "%") { // %h — имя хоста, не раскрываем
		return
	}
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(from), target)
	}
	if kind == "include" {
		if data, err := a.read(target, true); err == nil {
			a.parseSudoFile(s, target, data, depth+1)
		}
		return
	}
	entries, err := os.ReadDir(a.host(target))
	if err != nil {
		return
	}
	for _, e := range entries { // ReadDir сортирует по имени
		name := e.Name()
		if e.IsDir() || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			continue
		}
		f := path.Join(target, name)
		if data, err := a.read(f, true); err == nil {
			a.parseSudoFile(s, f, data, depth+1)
		}
	}
}

type logicalLine struct {
	text string
	line int // номер первой физической строки
}

// logicalLines склеивает строки, продолженные обратной косой чертой.
func logicalLines(data string) []logicalLine {
	var out []logicalLine
	var cur strings.Builder
	start := 0
	for i, raw := range strings.Split(data, "\n") {
		if cur.Len() == 0 {
			start = i + 1
		}
		t := strings.TrimRight(raw, " \t\r")
		if strings.HasSuffix(t, "\\") {
			cur.WriteString(strings.TrimSuffix(t, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(t)
		if line := strings.TrimSpace(cur.String()); line != "" {
			out = append(out, logicalLine{text: line, line: start})
		}
		cur.Reset()
	}
	if line := strings.TrimSpace(cur.String()); line != "" {
		out = append(out, logicalLine{text: line, line: start})
	}
	return out
}

// stripSudoComment убирает комментарий. «#» с цифрой после него — это
// UID (#1000), а не комментарий.
func stripSudoComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if inQuote || (i > 0 && s[i-1] != ' ' && s[i-1] != '\t' && s[i-1] != ',' && s[i-1] != '(') {
				continue
			}
			if i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
				continue
			}
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

// splitTop делит по разделителю вне кавычек и скобок; «\,» —
// экранированная запятая внутри команды.
func splitTop(s string, sep byte) []string {
	var out []string
	depth, inQuote, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case c == '(' && !inQuote:
			depth++
		case c == ')' && !inQuote && depth > 0:
			depth--
		case c == sep && depth == 0 && !inQuote:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if t := strings.TrimSpace(s[start:]); t != "" {
		out = append(out, t)
	}
	return out
}

// splitAliasDefs делит «A = x, y : B = z» на определения.
func splitAliasDefs(s string) []string {
	parts := splitTop(s, ':')
	var out []string
	for _, p := range parts {
		if aliasDef.MatchString(p) || len(out) == 0 {
			out = append(out, p)
		} else {
			out[len(out)-1] += ":" + p
		}
	}
	return out
}

// parseSpec разбирает правило «кто хосты = [(runas)] [ТЕГИ:] команды».
func (s *sudoers) parseSpec(text string) (sudoSpec, bool) {
	left, right, _ := strings.Cut(text, "=")
	// «alice, bob ALL» → кто: alice,bob; хосты: ALL.
	left = strings.Join(strings.Fields(strings.ReplaceAll(left, ", ", ",")), " ")
	f := strings.Fields(left)
	if len(f) < 2 {
		return sudoSpec{}, false
	}
	var spec sudoSpec
	for _, w := range splitTop(strings.Join(f[:len(f)-1], ""), ',') {
		spec.Who = append(spec.Who, s.expandUser(w, 0)...)
	}
	runas, nopasswd := "", false
	for _, item := range splitTop(right, ',') {
		item = strings.TrimSpace(item)
		if strings.HasPrefix(item, "(") {
			if end := strings.IndexByte(item, ')'); end > 0 {
				runas = strings.TrimSpace(item[1:end])
				item = strings.TrimSpace(item[end+1:])
			}
		}
		for {
			if m := tagPrefix.FindStringSubmatch(item); m != nil && sudoTags[m[1]] {
				switch m[1] {
				case "NOPASSWD":
					nopasswd = true
				case "PASSWD":
					nopasswd = false
				}
				item = item[len(m[0]):]
				continue
			}
			if m := optPrefix.FindString(item); m != "" {
				item = item[len(m):]
				continue
			}
			break
		}
		neg := false
		for strings.HasPrefix(item, "!") {
			neg = !neg
			item = strings.TrimSpace(item[1:])
		}
		for _, c := range s.expandCmd(item, 0) {
			c.Runas, c.NoPasswd = runas, nopasswd
			c.Negated = c.Negated != neg
			spec.Cmds = append(spec.Cmds, c)
		}
	}
	return spec, true
}

func (s *sudoers) expandUser(w string, depth int) []string {
	neg := strings.HasPrefix(w, "!")
	name := strings.TrimPrefix(w, "!")
	if items, ok := s.UserAlias[name]; ok && !neg && depth < maxAliasDepth {
		var out []string
		for _, it := range items {
			out = append(out, s.expandUser(it, depth+1)...)
		}
		return out
	}
	return []string{w}
}

func (s *sudoers) expandCmd(item string, depth int) []sudoCmd {
	item = strings.TrimSpace(item)
	if item == "" {
		return nil
	}
	if items, ok := s.CmndAlias[item]; ok && depth < maxAliasDepth {
		var out []sudoCmd
		for _, it := range items {
			neg := false
			for strings.HasPrefix(it, "!") {
				neg = !neg
				it = strings.TrimSpace(it[1:])
			}
			for _, c := range s.expandCmd(it, depth+1) {
				c.Negated = c.Negated != neg
				out = append(out, c)
			}
		}
		return out
	}
	p, args, _ := strings.Cut(item, " ")
	return []sudoCmd{{Raw: item, Path: p, Args: strings.TrimSpace(args), All: item == "ALL"}}
}

// cloudUsers — пользователи, которым облачные образы по умолчанию дают
// NOPASSWD: ALL (cloud-init). Это распространённая практика, поэтому
// уровень ниже, но её нужно показать.
var cloudUsers = map[string]bool{"ubuntu": true, "debian": true, "admin": true, "ec2-user": true, "centos": true, "cloud-user": true,
	"fedora": true, "rocky": true, "almalinux": true, "azureuser": true, "opc": true}

// gtfoBins — программы, через которые из sudo легко получить
// root-оболочку (по данным GTFOBins, https://gtfobins.github.io).
var gtfoBins = map[string]bool{
	"vi": true, "vim": true, "nvim": true, "nano": true, "pico": true, "ed": true, "emacs": true, "less": true, "more": true, "man": true,
	"find": true, "awk": true, "gawk": true, "mawk": true, "nawk": true, "sed": true, "python": true, "perl": true, "ruby": true,
	"node": true, "lua": true, "php": true, "tclsh": true, "expect": true, "bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true,
	"csh": true, "tcsh": true, "fish": true, "ash": true, "busybox": true, "tar": true, "zip": true, "unzip": true, "git": true, "env": true,
	"nmap": true, "docker": true, "podman": true, "systemctl": true, "journalctl": true, "apt": true, "apt-get": true, "dpkg": true,
	"rpm": true, "yum": true, "dnf": true, "pip": true, "npm": true, "cp": true, "mv": true, "tee": true, "chmod": true, "chown": true,
	"dd": true, "rsync": true, "scp": true, "ssh": true, "ftp": true, "gdb": true, "strace": true, "socat": true, "nc": true, "ncat": true,
	"wget": true, "curl": true, "openssl": true, "mount": true, "crontab": true, "screen": true, "tmux": true, "script": true,
	"flock": true, "nice": true, "timeout": true, "xargs": true, "taskset": true, "ionice": true, "stdbuf": true, "watch": true,
	"make": true, "install": true, "ln": true,
}

// versionSuffix — номер версии в имени (python3.12, perl5.36, vim.basic).
var versionSuffix = regexp.MustCompile(`^([a-z-]+?)[0-9.]*(\.(basic|tiny|nox|gtk3?))?$`)

func gtfoName(cmdPath string) (string, bool) {
	base := filepath.Base(cmdPath)
	if gtfoBins[base] {
		return base, true
	}
	if m := versionSuffix.FindStringSubmatch(base); m != nil && gtfoBins[m[1]] {
		return m[1], true
	}
	return base, false
}

// interactiveBins — программы, из которых выходят в оболочку командой
// внутри них (:!sh, !sh): фиксированные аргументы не помогают.
var interactiveBins = map[string]bool{"vi": true, "vim": true, "nvim": true, "nano": true, "pico": true, "ed": true, "emacs": true,
	"less": true, "more": true, "man": true, "ftp": true, "gdb": true, "screen": true, "tmux": true, "script": true, "journalctl": true,
	"python": true, "perl": true, "ruby": true, "node": true, "lua": true, "php": true, "tclsh": true, "expect": true,
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true, "fish": true, "ash": true, "busybox": true,
	"socat": true, "nc": true, "ncat": true, "env": true, "watch": true, "nice": true, "timeout": true, "flock": true, "stdbuf": true,
	"taskset": true, "ionice": true, "xargs": true}

// gtfoEscapes — разрешённая команда даёт оболочку. Интерактивные
// программы дают её при любых аргументах. Остальные (find, tar,
// systemctl, apt-get) — только если аргументы не зафиксированы: пустые
// (разрешены любые) или с шаблонами. «systemctl restart nginx» безопасна.
func gtfoEscapes(name, args string) bool {
	if interactiveBins[name] {
		return true
	}
	return args == "" || strings.ContainsAny(args, "*?[")
}

// runsAsRoot — команда выполняется от root: runas не указан, ALL или root.
func runsAsRoot(runas string) bool {
	if runas == "" {
		return true
	}
	users, _, _ := strings.Cut(runas, ":")
	for u := range strings.SplitSeq(users, ",") {
		u = strings.TrimSpace(u)
		if u == "" || u == "ALL" || u == "root" || u == "#0" {
			return true
		}
	}
	return false
}

// dangerousEnv — переменные, с которыми sudo выполнит чужой код.
var dangerousEnv = []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONSTARTUP", "PERL5LIB", "PERL5OPT", "RUBYLIB", "NODE_OPTIONS", "BASH_ENV", "ENV"}

// sudoChecks — проверки sudo (раздел 1.3 плана).
func (a *auditor) sudoChecks() []model.AuditCheck {
	g := model.AuditGroupSudo
	nopass := newCheck("sudo_nopasswd_all", g, model.RiskHigh, "audit.sudo_nopasswd_all.title", "T1548.003")
	noauth := newCheck("sudo_no_auth", g, model.RiskCritical, "audit.sudo_no_auth.title", "T1548.003")
	gtfo := newCheck("sudo_gtfobins", g, model.RiskHigh, "audit.sudo_gtfobins.title", "T1548.003")
	wild := newCheck("sudo_wildcard", g, model.RiskMedium, "audit.sudo_wildcard.title")
	writable := newCheck("sudo_writable_cmd", g, model.RiskCritical, "audit.sudo_writable_cmd.title", "T1548.003")
	env := newCheck("sudo_env_keep", g, model.RiskHigh, "audit.sudo_env_keep.title", "T1574.006")
	perms := newCheck("sudo_files_perms", g, model.RiskHigh, "audit.sudo_files_perms.title")
	changed := newCheck("sudo_changed", g, model.RiskHigh, "audit.sudo_changed.title", "T1548.003")
	all := []*model.AuditCheck{&nopass, &noauth, &gtfo, &wild, &writable, &env, &perms, &changed}
	result := func() []model.AuditCheck {
		out := make([]model.AuditCheck, len(all))
		for i, c := range all {
			out[i] = *c
		}
		return out
	}

	s := a.parseSudoers()
	if !s.Found {
		st, ev := model.AuditNA, i18n.T("ev.audit_sudo_absent")
		if s.Unreadable {
			st, ev = model.AuditUnknown, i18n.T("ev.audit_no_access", sudoersFile)
		}
		for _, c := range all {
			c.Status = st
			addEv(c, ev)
		}
		return result()
	}
	a.sudoRead = true
	for f, h := range s.Hashes {
		a.next.Sudoers[f] = h
	}

	nopass.Severity = 0
	seenWritable := map[string]bool{}
	// Строка правила добавляется в факты проверки один раз, даже если в
	// ней несколько подходящих команд.
	seenSpec := map[*model.AuditCheck]map[int]bool{}
	specEv := func(c *model.AuditCheck, i int, spec sudoSpec) {
		if seenSpec[c] == nil {
			seenSpec[c] = map[int]bool{}
		}
		if !seenSpec[c][i] {
			seenSpec[c][i] = true
			addEv(c, at(spec.File, spec.Line, spec.Text))
		}
	}
	for si, spec := range s.Specs {
		for _, c := range spec.Cmds {
			if c.Negated {
				continue
			}
			if c.All && c.NoPasswd {
				nopass.Status = model.AuditFail
				specEv(&nopass, si, spec)
				sev := model.RiskMedium
				for _, w := range spec.Who {
					if !cloudUsers[w] {
						sev = model.RiskHigh
					}
				}
				nopass.Severity = max(nopass.Severity, sev)
			}
			if c.All {
				continue
			}
			if name, ok := gtfoName(c.Path); ok && gtfoEscapes(name, c.Args) {
				// От root — провал; от другого пользователя — оболочка
				// этого пользователя, а не root: требует внимания.
				st, ev := model.AuditFail, i18n.T("ev.audit_gtfo", name, c.Raw)
				if !runsAsRoot(c.Runas) {
					st, ev = model.AuditWarn, i18n.T("ev.audit_gtfo_user", name, c.Raw, c.Runas)
				}
				if worse(st, gtfo.Status) {
					gtfo.Status = st
				}
				specEv(&gtfo, si, spec)
				addEv(&gtfo, ev)
			}
			if strings.ContainsAny(c.Args, "*?[") || strings.ContainsAny(c.Path, "*?[") {
				wild.Status = model.AuditWarn
				specEv(&wild, si, spec)
			}
			if path.IsAbs(c.Path) && !seenWritable[c.Path] {
				seenWritable[c.Path] = true
				if p, fi, ok := a.writableChain(c.Path); ok {
					writable.Status = model.AuditFail
					specEv(&writable, si, spec)
					addEv(&writable, i18n.T("ev.audit_writable", p, describe(fi)))
				}
			}
		}
	}
	if nopass.Severity == 0 {
		nopass.Severity = model.RiskHigh
	}
	for _, d := range s.Defaults {
		for _, p := range d.Params {
			key, val, _ := strings.Cut(p, "=")
			key = strings.TrimSpace(strings.TrimRight(key, "+-"))
			switch {
			case p == "!authenticate":
				noauth.Status = model.AuditFail
				addEv(&noauth, at(d.File, d.Line, d.Text))
			case p == "!env_reset":
				env.Status = model.AuditFail
				addEv(&env, at(d.File, d.Line, d.Text))
				addEv(&env, i18n.T("ev.audit_env_reset_off"))
			case key == "env_keep" || key == "env_check":
				for _, v := range dangerousEnv {
					if slices.Contains(strings.Fields(strings.Trim(val, `" `)), v) {
						env.Status = model.AuditFail
						addEv(&env, at(d.File, d.Line, d.Text))
						break
					}
				}
			}
		}
	}

	for _, f := range s.Files {
		fi, err := a.lstat(f)
		if err != nil {
			continue
		}
		switch {
		case a.writableByOthers(fi):
			perms.Status = model.AuditFail
			addEv(&perms, i18n.T("ev.audit_writable", f, describe(fi)))
		case fi.Mode().Perm()&0o004 != 0:
			if perms.Status == model.AuditPass {
				perms.Status = model.AuditWarn
			}
			addEv(&perms, i18n.T("ev.audit_world_readable", f, describe(fi)))
		}
	}
	if perms.Status == model.AuditWarn {
		perms.Severity = model.RiskLow
	}

	a.sudoChanges(s, &changed)

	set := func(c *model.AuditCheck, recKey string) {
		if c.Status != model.AuditPass {
			c.Recommendation = i18n.T(recKey)
		}
	}
	set(&nopass, "audit.sudo_nopasswd_all.rec")
	set(&noauth, "audit.sudo_no_auth.rec")
	set(&gtfo, "audit.sudo_gtfobins.rec")
	set(&wild, "audit.sudo_wildcard.rec")
	set(&writable, "audit.sudo_writable_cmd.rec")
	set(&env, "audit.sudo_env_keep.rec")
	set(&perms, "audit.sudo_files_perms.rec")
	if perms.Status != model.AuditPass {
		perms.FixCommand = "chown root:root /etc/sudoers /etc/sudoers.d/* && chmod 440 /etc/sudoers /etc/sudoers.d/* && visudo -c"
	}
	for _, c := range []*model.AuditCheck{&nopass, &noauth, &gtfo, &wild, &writable, &env} {
		if c.Status == model.AuditPass {
			addEv(c, i18n.T("ev.audit_sudo_ok", len(s.Files)))
		}
	}
	return result()
}

// writableChain — команда или один из каталогов на пути к ней доступны
// на запись не root: подменив файл, пользователь получит root через sudo.
//
// Файла может не быть: разрешённая, но удалённая команда в каталоге,
// куда пишет пользователь, — тоже root (создай файл и запусти через
// sudo). Поэтому каталоги проверяются и тогда.
func (a *auditor) writableChain(cmd string) (string, os.FileInfo, bool) {
	fi, err := a.stat(cmd)
	switch {
	case err == nil && a.writableByOthers(fi):
		return cmd, fi, true
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return "", nil, false
	}
	for dir := path.Dir(cmd); ; dir = path.Dir(dir) {
		if fi, err := a.lstat(dir); err == nil && fi.IsDir() && a.writableByOthers(fi) && fi.Mode()&os.ModeSticky == 0 {
			return dir, fi, true
		}
		if dir == "/" || dir == "." {
			break
		}
	}
	return "", nil, false
}

// sudoChanges — изменения файлов sudoers с прошлого запуска.
//
// Как и для пользователей, изменение держит проверку в fail ChangeWindow.
func (a *auditor) sudoChanges(s *sudoers, c *model.AuditCheck) {
	c.Change = true
	b := a.opt.Baseline
	if b == nil {
		c.Status = model.AuditNA
		addEv(c, i18n.T("ev.audit_no_baseline"))
		return
	}
	if b.Init {
		for _, f := range sortedKeys(s.Hashes) {
			old, ok := b.Sudoers[f]
			switch {
			case !ok:
				a.change(c.ID, true, i18n.T("ev.audit_sudo_added", f))
			case old != s.Hashes[f]:
				a.change(c.ID, true, i18n.T("ev.audit_sudo_modified", f))
			}
		}
		for _, f := range sortedKeys(b.Sudoers) {
			if _, ok := s.Hashes[f]; !ok {
				a.change(c.ID, true, i18n.T("ev.audit_sudo_removed", f))
			}
		}
	}
	switch {
	case a.applyRecent(c):
		c.Recommendation = i18n.T("audit.sudo_changed.rec")
	case !b.Init:
		addEv(c, i18n.T("ev.audit_sudo_baseline", len(s.Files)))
	default:
		addEv(c, i18n.T("ev.audit_sudo_unchanged"))
	}
}

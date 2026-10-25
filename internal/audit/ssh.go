package audit

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

const (
	sshdConfig = "/etc/ssh/sshd_config"
	// maxIncludeDepth — вложенность Include (у sshd тот же предел).
	maxIncludeDepth = 16
	// maxSSHFiles — сколько файлов конфигурации читать за раз.
	maxSSHFiles = 256
)

// sshDirective — одна строка конфигурации sshd.
type sshDirective struct {
	Key   string   // ключ в нижнем регистре
	Args  []string // значения (кавычки сняты)
	Raw   string   // строка как в файле (для доказательств)
	File  string   // путь относительно корня хоста
	Line  int
	Match string // условие блока Match; "" — глобальная настройка
}

func (d sshDirective) value() string { return strings.Join(d.Args, " ") }

// ev — доказательство «файл:строка  Ключ значение».
func (d sshDirective) ev() i18n.Msg {
	text := d.Raw
	if d.Match != "" {
		text += "  (Match " + d.Match + ")"
	}
	return at(d.File, d.Line, text)
}

// sshConfig — разобранная конфигурация sshd.
type sshConfig struct {
	Found      bool           // основной файл прочитан
	Unreadable bool           // основной файл есть, но нет прав
	Files      []string       // прочитанные файлы по порядку
	Directives []sshDirective // все строки по порядку чтения
	// DropInFirst — Include каталога sshd_config.d стоит в основном файле
	// раньше собственных настроек: значения из .d имеют приоритет.
	DropInFirst bool
}

// get — действующее глобальное значение: у sshd побеждает первое.
func (c *sshConfig) get(keys ...string) (sshDirective, bool) {
	for _, d := range c.Directives {
		if d.Match == "" && slices.Contains(keys, d.Key) {
			return d, true
		}
	}
	return sshDirective{}, false
}

// overrides — значения ключа в блоках Match (первое в каждом блоке).
func (c *sshConfig) overrides(keys ...string) []sshDirective {
	seen := map[string]bool{}
	var out []sshDirective
	for _, d := range c.Directives {
		if d.Match != "" && slices.Contains(keys, d.Key) && !seen[d.Match] {
			seen[d.Match] = true
			out = append(out, d)
		}
	}
	return out
}

// parseSSHD читает sshd_config с раскрытием Include.
func (a *auditor) parseSSHD() *sshConfig {
	c := &sshConfig{}
	data, err := a.read(sshdConfig, true)
	if err != nil {
		c.Unreadable = isPerm(err)
		return c
	}
	c.Found = true
	a.parseSSHFile(c, sshdConfig, data, "", 0)
	// Значения из sshd_config.d действуют, если их Include стоит раньше
	// любой собственной настройки основного файла.
	for _, d := range c.Directives {
		if d.File != sshdConfig {
			continue
		}
		if d.Key == "include" {
			for _, arg := range d.Args {
				if strings.Contains(arg, "sshd_config.d") {
					c.DropInFirst = true
				}
			}
		}
		break
	}
	return c
}

func (a *auditor) parseSSHFile(c *sshConfig, file string, data []byte, match string, depth int) {
	c.Files = append(c.Files, file)
	for i, raw := range strings.Split(string(data), "\n") {
		key, args := splitSSHLine(raw)
		if key == "" {
			continue
		}
		if key == "match" {
			match = strings.Join(args, " ")
			if strings.EqualFold(match, "all") {
				match = "all"
			}
			continue
		}
		d := sshDirective{Key: key, Args: args, Raw: strings.TrimSpace(raw), File: file, Line: i + 1, Match: match}
		c.Directives = append(c.Directives, d)
		if key != "include" || depth >= maxIncludeDepth {
			continue
		}
		for _, pat := range args {
			if !path.IsAbs(pat) {
				pat = path.Join("/etc/ssh", pat)
			}
			matches, _ := filepath.Glob(a.host(pat)) // отсортированы
			for _, m := range matches {
				if len(c.Files) >= maxSSHFiles {
					return
				}
				inc := a.rel(m)
				if slices.Contains(c.Files, inc) {
					continue // защита от циклов
				}
				if body, err := a.read(inc, true); err == nil {
					a.parseSSHFile(c, inc, body, match, depth+1)
				}
			}
		}
	}
}

// splitSSHLine разбирает строку: ключ (в нижнем регистре) и значения.
// Ключ отделяется пробелом или «=», значения могут быть в кавычках.
func splitSSHLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	i := strings.IndexAny(line, " \t=")
	switch {
	case i < 0:
		return strings.ToLower(line), nil
	case i == 0: // «=значение» без ключа — не настройка
		return "", nil
	}
	key := strings.ToLower(line[:i])
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	var args []string
	var cur strings.Builder
	inQuote, has := false, false
	for _, r := range rest {
		switch {
		case r == '"':
			inQuote = !inQuote
			has = true
		case (r == ' ' || r == '\t') && !inQuote:
			if has {
				args = append(args, cur.String())
				cur.Reset()
				has = false
			}
		case r == '#' && !inQuote && !has:
			// Комментарий в конце строки.
			return key, args
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		args = append(args, cur.String())
	}
	return key, args
}

// sshDefaults — значения OpenSSH по умолчанию (sshd_config(5)); для
// DebianBanner — значение патча Debian/Ubuntu.
var sshDefaults = map[string]string{
	"permitrootlogin":              "prohibit-password",
	"passwordauthentication":       "yes",
	"permitemptypasswords":         "no",
	"kbdinteractiveauthentication": "yes",
	"usepam":                       "no",
	"maxauthtries":                 "6",
	"x11forwarding":                "no",
	"allowtcpforwarding":           "yes",
	"gatewayports":                 "no",
	"authorizedkeysfile":           ".ssh/authorized_keys .ssh/authorized_keys2",
	"debianbanner":                 "yes",
	"port":                         "22",
}

// sshNames — написание ключей как в документации (для доказательств).
var sshNames = map[string]string{
	"permitrootlogin": "PermitRootLogin", "passwordauthentication": "PasswordAuthentication", "permitemptypasswords": "PermitEmptyPasswords",
	"kbdinteractiveauthentication": "KbdInteractiveAuthentication", "usepam": "UsePAM", "maxauthtries": "MaxAuthTries",
	"x11forwarding": "X11Forwarding", "allowtcpforwarding": "AllowTcpForwarding", "gatewayports": "GatewayPorts",
	"authorizedkeysfile": "AuthorizedKeysFile", "debianbanner": "DebianBanner", "port": "Port",
}

// setting — действующее значение ключа и доказательство его источника.
type setting struct {
	val   string
	ev    i18n.Msg
	dflt  bool // значение по умолчанию (ключ не задан)
	found sshDirective
}

func (c *sshConfig) setting(keys ...string) setting {
	if d, ok := c.get(keys...); ok {
		return setting{val: strings.ToLower(d.value()), ev: d.ev(), found: d}
	}
	v := sshDefaults[keys[0]]
	name := sshNames[keys[0]]
	if name == "" {
		name = keys[0]
	}
	return setting{val: v, ev: i18n.T("ev.audit_ssh_default", name, v), dflt: true}
}

// sshChecks — проверки SSH (раздел 1.1 плана).
func (a *auditor) sshChecks() []model.AuditCheck {
	c := a.parseSSHD()
	installed := c.Found || c.Unreadable
	if !installed {
		if _, err := a.lstat("/usr/sbin/sshd"); err == nil {
			installed = true
		}
	}
	checks := []model.AuditCheck{
		newCheck("ssh_root_login", model.AuditGroupSSH, model.RiskHigh, "audit.ssh_root_login.title", "T1110"),
		newCheck("ssh_password_auth", model.AuditGroupSSH, model.RiskHigh, "audit.ssh_password_auth.title", "T1110"),
		newCheck("ssh_empty_passwords", model.AuditGroupSSH, model.RiskCritical, "audit.ssh_empty_passwords.title", "T1110"),
		newCheck("ssh_kbd_interactive", model.AuditGroupSSH, model.RiskMedium, "audit.ssh_kbd_interactive.title", "T1110"),
		newCheck("ssh_max_auth_tries", model.AuditGroupSSH, model.RiskLow, "audit.ssh_max_auth_tries.title"),
		newCheck("ssh_x11_forwarding", model.AuditGroupSSH, model.RiskLow, "audit.ssh_x11_forwarding.title"),
		newCheck("ssh_tcp_forwarding", model.AuditGroupSSH, model.RiskMedium, "audit.ssh_tcp_forwarding.title"),
		newCheck("ssh_weak_crypto", model.AuditGroupSSH, model.RiskMedium, "audit.ssh_weak_crypto.title"),
		newCheck("ssh_authkeys_file", model.AuditGroupSSH, model.RiskHigh, "audit.ssh_authkeys_file.title", "T1098.004"),
		newCheck("ssh_host_keys_perms", model.AuditGroupSSH, model.RiskHigh, "audit.ssh_host_keys_perms.title"),
		newCheck("ssh_config_perms", model.AuditGroupSSH, model.RiskHigh, "audit.ssh_config_perms.title"),
		newCheck("ssh_allow_users", model.AuditGroupSSH, model.RiskInfo, "audit.ssh_allow_users.title"),
		newCheck("ssh_banner_version", model.AuditGroupSSH, model.RiskInfo, "audit.ssh_banner_version.title"),
		newCheck("ssh_port", model.AuditGroupSSH, model.RiskInfo, "audit.ssh_port.title"),
	}
	if !installed {
		for i := range checks {
			checks[i].Status = model.AuditNA
			checks[i].Evidence = []i18n.Msg{i18n.T("ev.audit_ssh_absent")}
		}
		return checks
	}
	if c.Unreadable {
		for i := range checks {
			checks[i].Status = model.AuditUnknown
			checks[i].Evidence = []i18n.Msg{i18n.T("ev.audit_no_access", sshdConfig)}
		}
		return checks
	}
	if !c.Found {
		// sshd установлен без файла настроек: действуют значения по
		// умолчанию OpenSSH.
		for i := range checks {
			checks[i].Evidence = []i18n.Msg{i18n.T("ev.audit_ssh_no_config")}
		}
	}
	for i := range checks {
		ch := &checks[i]
		switch ch.ID {
		case "ssh_root_login":
			a.sshRootLogin(c, ch)
		case "ssh_password_auth":
			a.sshYesNo(c, ch, "passwordauthentication", "PasswordAuthentication", "no", model.AuditFail, "audit.ssh_password_auth.rec")
		case "ssh_empty_passwords":
			a.sshYesNo(c, ch, "permitemptypasswords", "PermitEmptyPasswords", "no", model.AuditFail, "audit.ssh_empty_passwords.rec")
		case "ssh_kbd_interactive":
			a.sshKbd(c, ch)
		case "ssh_max_auth_tries":
			s := c.setting("maxauthtries")
			addEv(ch, s.ev)
			if n, err := strconv.Atoi(s.val); err == nil && n > 4 {
				ch.Status = model.AuditWarn
				ch.Recommendation = i18n.T("audit.ssh_max_auth_tries.rec")
				ch.FixCommand = sshFix(c, "MaxAuthTries", "3")
			}
		case "ssh_x11_forwarding":
			a.sshYesNo(c, ch, "x11forwarding", "X11Forwarding", "no", model.AuditWarn, "audit.ssh_x11_forwarding.rec")
		case "ssh_tcp_forwarding":
			s := c.setting("gatewayports")
			addEv(ch, s.ev)
			addEv(ch, c.setting("allowtcpforwarding").ev)
			if s.val == "yes" || s.val == "clientspecified" {
				ch.Status = model.AuditFail
				ch.Recommendation = i18n.T("audit.ssh_tcp_forwarding.rec")
				ch.FixCommand = sshFix(c, "GatewayPorts", "no")
			}
		case "ssh_weak_crypto":
			a.sshCrypto(c, ch)
		case "ssh_authkeys_file":
			a.sshAuthKeys(c, ch)
		case "ssh_host_keys_perms":
			a.sshHostKeys(c, ch)
		case "ssh_config_perms":
			a.sshConfigPerms(c, ch)
		case "ssh_allow_users":
			if d, ok := c.get("allowusers", "allowgroups"); ok {
				addEv(ch, d.ev())
			} else {
				ch.Status = model.AuditInfo
				addEv(ch, i18n.T("ev.audit_ssh_no_allow"))
				ch.Recommendation = i18n.T("audit.ssh_allow_users.rec")
			}
		case "ssh_banner_version":
			if !a.debianFamily() {
				ch.Status = model.AuditNA
				addEv(ch, i18n.T("ev.audit_not_debian"))
				continue
			}
			s := c.setting("debianbanner")
			addEv(ch, s.ev)
			if s.val == "yes" {
				ch.Status = model.AuditInfo
				ch.Recommendation = i18n.T("audit.ssh_banner_version.rec")
				ch.FixCommand = sshFix(c, "DebianBanner", "no")
			}
		case "ssh_port":
			s := c.setting("port")
			addEv(ch, s.ev)
			if s.val == "22" {
				ch.Status = model.AuditInfo
				ch.Recommendation = i18n.T("audit.ssh_port.rec")
			}
		}
	}
	return checks
}

// sshYesNo — проверка «ключ должен быть равен want». Блоки Match со
// значением хуже глобального показываются отдельно: для части
// подключений настройка всё равно опасна.
func (a *auditor) sshYesNo(c *sshConfig, ch *model.AuditCheck, key, name, want, bad, recKey string) {
	s := c.setting(key)
	addEv(ch, s.ev)
	globalBad := s.val != want
	if globalBad {
		ch.Status = bad
	}
	var badMatch []sshDirective
	for _, d := range c.overrides(key) {
		if strings.ToLower(d.value()) != want {
			badMatch = append(badMatch, d)
			addEv(ch, d.ev())
			if d.Match == "all" {
				ch.Status = bad
			} else if ch.Status == model.AuditPass {
				ch.Status = model.AuditWarn
			}
		}
	}
	if ch.Status != model.AuditPass {
		ch.Recommendation = i18n.T(recKey)
		matchFix(c, ch, globalBad, badMatch, name, want)
	}
}

// matchFix — команда исправления. Глобальная строка не перекрывает
// значение внутри Match (там оно важнее), поэтому для блоков Match
// команды нет, а в фактах указано, где исправить.
func matchFix(c *sshConfig, ch *model.AuditCheck, globalBad bool, badMatch []sshDirective, name, want string) {
	if globalBad {
		ch.FixCommand = sshFix(c, name, want)
	}
	for _, d := range badMatch {
		addEv(ch, i18n.T("ev.audit_match_fix", fmt.Sprintf("%s:%d", d.File, d.Line)))
	}
}

func (a *auditor) sshRootLogin(c *sshConfig, ch *model.AuditCheck) {
	s := c.setting("permitrootlogin")
	addEv(ch, s.ev)
	globalBad := s.val == "yes"
	switch s.val {
	case "yes":
		ch.Status = model.AuditFail
	case "prohibit-password", "without-password":
		addEv(ch, i18n.T("ev.audit_root_keys_only"))
	}
	var badMatch []sshDirective
	for _, d := range c.overrides("permitrootlogin") {
		if strings.ToLower(d.value()) == "yes" {
			badMatch = append(badMatch, d)
			addEv(ch, d.ev())
			if d.Match == "all" {
				ch.Status = model.AuditFail
			} else if ch.Status == model.AuditPass {
				ch.Status = model.AuditWarn
			}
		}
	}
	if ch.Status != model.AuditPass {
		ch.Recommendation = i18n.T("audit.ssh_root_login.rec")
		matchFix(c, ch, globalBad, badMatch, "PermitRootLogin", "prohibit-password")
	}
}

// sshKbd — вход «клавиатурой» (keyboard-interactive) через PAM — это
// тот же вход по паролю, даже если PasswordAuthentication no.
func (a *auditor) sshKbd(c *sshConfig, ch *model.AuditCheck) {
	kbd := c.setting("kbdinteractiveauthentication", "challengeresponseauthentication")
	pam := c.setting("usepam")
	addEv(ch, kbd.ev)
	addEv(ch, pam.ev)
	if kbd.val == "yes" && pam.val == "yes" {
		ch.Status = model.AuditFail
		ch.Recommendation = i18n.T("audit.ssh_kbd_interactive.rec")
		ch.FixCommand = sshFix(c, "KbdInteractiveAuthentication", "no")
	}
}

// weakAlgo — устаревшие алгоритмы: SHA-1, MD5, CBC, RC4, 3DES, DSA.
func weakAlgo(name string) bool {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "3des"), strings.Contains(n, "arcfour"), strings.HasSuffix(n, "-cbc"), strings.Contains(n, "-cbc@"),
		strings.HasPrefix(n, "hmac-md5"), strings.HasPrefix(n, "hmac-sha1"), strings.HasPrefix(n, "umac-64"),
		n == "diffie-hellman-group1-sha1", n == "diffie-hellman-group14-sha1", n == "diffie-hellman-group-exchange-sha1",
		strings.HasPrefix(n, "ssh-dss"), n == "ssh-rsa", n == "ssh-rsa-cert-v01@openssh.com":
		return true
	}
	return false
}

func (a *auditor) sshCrypto(c *sshConfig, ch *model.AuditCheck) {
	keys := []string{"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes", "casignaturealgorithms"}
	for _, key := range keys {
		d, ok := c.get(key)
		if !ok {
			continue
		}
		var weak []string
		for algo := range strings.SplitSeq(d.value(), ",") {
			algo = strings.TrimSpace(algo)
			if strings.HasPrefix(algo, "-") { // удаление из списка по умолчанию
				continue
			}
			algo = strings.TrimLeft(algo, "+^")
			if weakAlgo(algo) {
				weak = append(weak, algo)
			}
		}
		if len(weak) > 0 {
			ch.Status = model.AuditFail
			addEv(ch, d.ev())
			addEv(ch, i18n.T("ev.audit_weak_algos", strings.Join(weak, ", ")))
		}
	}
	if ch.Status == model.AuditFail {
		ch.Recommendation = i18n.T("audit.ssh_weak_crypto.rec")
	} else {
		addEv(ch, i18n.T("ev.audit_crypto_ok"))
	}
}

// defaultKeyFiles — стандартные значения AuthorizedKeysFile.
var defaultKeyFiles = map[string]bool{
	".ssh/authorized_keys": true, ".ssh/authorized_keys2": true, "%h/.ssh/authorized_keys": true, "%h/.ssh/authorized_keys2": true,
	"/home/%u/.ssh/authorized_keys": true, "none": true,
}

// tempPrefixes — каталоги, куда может писать любой пользователь.
var tempPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}

func inTemp(p string) bool {
	for _, t := range tempPrefixes {
		if strings.HasPrefix(p, t) {
			return true
		}
	}
	return false
}

// sshAuthKeys — нестандартный файл ключей или команда выдачи ключей:
// так закрепляются, подсовывая свой ключ для любого пользователя.
func (a *auditor) sshAuthKeys(c *sshConfig, ch *model.AuditCheck) {
	s := c.setting("authorizedkeysfile")
	addEv(ch, s.ev)
	for _, f := range strings.Fields(s.val) {
		switch {
		case inTemp(f):
			ch.Status = model.AuditFail
			addEv(ch, i18n.T("ev.audit_keys_temp", f))
		case !defaultKeyFiles[f]:
			if worse(model.AuditWarn, ch.Status) {
				ch.Status = model.AuditWarn
			}
			addEv(ch, i18n.T("ev.audit_keys_nonstd", f))
		}
	}
	if d, ok := c.get("authorizedkeyscommand"); ok && !strings.EqualFold(d.value(), "none") {
		addEv(ch, d.ev())
		cmd := ""
		if len(d.Args) > 0 {
			cmd = d.Args[0]
		}
		st := model.AuditWarn
		if inTemp(cmd) {
			st = model.AuditFail
			addEv(ch, i18n.T("ev.audit_keys_temp", cmd))
		} else if fi, err := a.stat(cmd); err == nil && a.writableByOthers(fi) {
			st = model.AuditFail
			addEv(ch, i18n.T("ev.audit_writable", cmd, describe(fi)))
		} else {
			addEv(ch, i18n.T("ev.audit_keys_command"))
		}
		if worse(st, ch.Status) {
			ch.Status = st
		}
	}
	if ch.Status != model.AuditPass {
		ch.Recommendation = i18n.T("audit.ssh_authkeys_file.rec")
	}
}

func (a *auditor) sshHostKeys(c *sshConfig, ch *model.AuditCheck) {
	files, _ := filepath.Glob(a.host("/etc/ssh/ssh_host_*_key"))
	for _, d := range c.Directives {
		if d.Key == "hostkey" && d.Match == "" && len(d.Args) > 0 {
			if f := a.host(d.Args[0]); !slices.Contains(files, f) {
				files = append(files, f)
			}
		}
	}
	bad := 0
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 || !a.isRoot(fi) {
			bad++
			addEv(ch, i18n.T("ev.audit_bad_perms", a.rel(f), describe(fi)))
		}
	}
	if bad > 0 {
		ch.Status = model.AuditFail
		ch.Recommendation = i18n.T("audit.ssh_host_keys_perms.rec")
		ch.FixCommand = "chown root:root /etc/ssh/ssh_host_*_key && chmod 600 /etc/ssh/ssh_host_*_key"
	} else {
		addEv(ch, i18n.T("ev.audit_files_ok", len(files)))
	}
}

func (a *auditor) sshConfigPerms(c *sshConfig, ch *model.AuditCheck) {
	// Каталоги тоже: в доступный на запись sshd_config.d любой положит
	// свой 00-x.conf, и sshd прочитает его первым.
	dirs := []string{"/etc/ssh", "/etc/ssh/sshd_config.d"}
	for _, f := range c.Files {
		if d := path.Dir(f); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	for _, d := range dirs {
		if fi, err := a.lstat(d); err == nil && fi.IsDir() && a.writableByOthers(fi) {
			ch.Status = model.AuditFail
			addEv(ch, i18n.T("ev.audit_dir_writable", d, describe(fi)))
		}
	}
	for _, f := range c.Files {
		fi, err := a.stat(f)
		if err != nil {
			continue
		}
		if a.writableByOthers(fi) {
			ch.Status = model.AuditFail
			addEv(ch, i18n.T("ev.audit_writable", f, describe(fi)))
		}
	}
	if ch.Status == model.AuditFail {
		ch.Recommendation = i18n.T("audit.ssh_config_perms.rec")
		ch.FixCommand = "chown -R root:root /etc/ssh && chmod 644 /etc/ssh/sshd_config && chmod -R go-w /etc/ssh/sshd_config.d"
	} else {
		addEv(ch, i18n.T("ev.audit_files_ok", len(c.Files)))
	}
}

// sshFix — команда исправления: значение добавляется туда, где sshd
// прочитает его первым. Если Include каталога sshd_config.d стоит в
// начале основного файла — отдельный файл 00-…, иначе строка в начало
// sshd_config. Затем проверка синтаксиса (sshd -t) и перечитывание.
func sshFix(c *sshConfig, key, value string) string {
	line := key + " " + value
	write := fmt.Sprintf("sed -i '1i %s' %s", line, sshdConfig)
	if c.DropInFirst {
		write = fmt.Sprintf("echo '%s' > /etc/ssh/sshd_config.d/00-%s.conf", line, strings.ToLower(key))
	}
	return write + " && sshd -t && (systemctl reload ssh || systemctl reload sshd)"
}

// debianFamily — дистрибутив на основе Debian (по /etc/os-release).
func (a *auditor) debianFamily() bool {
	data, err := a.read("/etc/os-release", true)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (k != "ID" && k != "ID_LIKE") {
			continue
		}
		for id := range strings.FieldsSeq(strings.Trim(v, `"'`)) {
			if id == "debian" || id == "ubuntu" {
				return true
			}
		}
	}
	return false
}

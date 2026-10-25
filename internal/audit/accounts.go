package audit

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// passwdEntry — строка /etc/passwd.
type passwdEntry struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
	Line  int
}

// shadowInfo — то, что берётся из /etc/shadow. Сам хеш не хранится:
// только тип алгоритма и признаки «пусто» и «заблокировано».
type shadowInfo struct {
	Empty  bool
	Locked bool   // «!», «*» или «!хеш»
	Algo   string // 1 (MD5), des, 5, 6, y, 2b…; "" — нет хеша
	Line   int
}

// groupEntry — строка /etc/group.
type groupEntry struct {
	Name    string
	GID     int
	Members []string
	Line    int
}

// privGroups — группы, дающие root или доступ к секретам. docker, lxd и
// disk фактически равны root: через них монтируют корень хоста или
// читают блочное устройство.
var privGroups = []string{"sudo", "admin", "wheel", "docker", "lxd", "disk", "adm", "shadow"}

// rootEquivalent — группы, членство в которых равно root.
var rootEquivalent = map[string]bool{"sudo": true, "admin": true, "wheel": true, "docker": true, "lxd": true, "disk": true}

// noLoginShells — оболочки, не дающие входа.
var noLoginShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true, "/bin/sync": true,
	"/usr/bin/sync": true, "/sbin/shutdown": true, "/sbin/halt": true, "/usr/sbin/shutdown": true, "/usr/sbin/halt": true, "": true,
}

func parsePasswd(data string) []passwdEntry {
	var out []passwdEntry
	for i, line := range strings.Split(data, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, passwdEntry{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: strings.TrimSpace(f[6]), Line: i + 1})
	}
	return out
}

// parseShadow разбирает /etc/shadow, сразу отбрасывая хеши.
func parseShadow(data string) map[string]shadowInfo {
	out := map[string]shadowInfo{}
	for i, line := range strings.Split(data, "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) < 2 || f[0] == "" {
			continue
		}
		h := f[1]
		si := shadowInfo{Line: i + 1}
		switch {
		case h == "":
			si.Empty = true
		case strings.HasPrefix(h, "!") || strings.HasPrefix(h, "*"):
			si.Locked = true
			h = strings.TrimLeft(h, "!*")
		}
		switch {
		case h == "":
		case strings.HasPrefix(h, "$"):
			if algo, _, ok := strings.Cut(h[1:], "$"); ok {
				si.Algo = algo
			}
		case len(h) == 13:
			si.Algo = "des"
		}
		out[f[0]] = si
	}
	return out
}

func parseGroup(data string) []groupEntry {
	var out []groupEntry
	for i, line := range strings.Split(data, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		var members []string
		for m := range strings.SplitSeq(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		out = append(out, groupEntry{Name: f[0], GID: gid, Members: members, Line: i + 1})
	}
	return out
}

// uidMin — UID_MIN из /etc/login.defs (по умолчанию 1000).
func (a *auditor) uidMin() int {
	data, err := a.read("/etc/login.defs", true)
	if err != nil {
		return 1000
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "UID_MIN" {
			if n, err := strconv.Atoi(f[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1000
}

// accountChecks — проверки учётных записей (раздел 1.2 плана).
func (a *auditor) accountChecks() []model.AuditCheck {
	g := model.AuditGroupAccounts
	uid0 := newCheck("acct_uid0_extra", g, model.RiskCritical, "audit.acct_uid0_extra.title", "T1136.001")
	empty := newCheck("acct_empty_password", g, model.RiskCritical, "audit.acct_empty_password.title", "T1078")
	shell := newCheck("acct_service_shell", g, model.RiskMedium, "audit.acct_service_shell.title")
	weak := newCheck("acct_weak_hash", g, model.RiskMedium, "audit.acct_weak_hash.title")
	newUsers := newCheck("acct_new", g, model.RiskHigh, "audit.acct_new.title", "T1136.001")
	priv := newCheck("acct_priv_groups", g, model.RiskHigh, "audit.acct_priv_groups.title", "T1098")
	dup := newCheck("acct_duplicate_ids", g, model.RiskHigh, "audit.acct_duplicate_ids.title")
	perms := newCheck("acct_passwd_perms", g, model.RiskHigh, "audit.acct_passwd_perms.title")
	homes := newCheck("acct_home_perms", g, model.RiskMedium, "audit.acct_home_perms.title")
	path := newCheck("acct_root_path", g, model.RiskHigh, "audit.acct_root_path.title")
	all := []*model.AuditCheck{&uid0, &empty, &shell, &weak, &newUsers, &priv, &dup, &perms, &homes, &path}
	result := func() []model.AuditCheck {
		out := make([]model.AuditCheck, len(all))
		for i, c := range all {
			out[i] = *c
		}
		return out
	}

	pdata, err := a.read("/etc/passwd", true)
	if err != nil {
		st := model.AuditNA
		if isPerm(err) {
			st = model.AuditUnknown
		}
		for _, c := range all {
			c.Status = st
			addEv(c, i18n.T("ev.audit_no_access", "/etc/passwd"))
		}
		return result()
	}
	users := parsePasswd(string(pdata))
	a.usersRead = true
	var groups []groupEntry
	if data, err := a.read("/etc/group", true); err == nil {
		groups = parseGroup(string(data))
		a.groupsRead = true
	}
	var shadow map[string]shadowInfo
	sdata, serr := a.read("/etc/shadow", true)
	if serr == nil {
		shadow = parseShadow(string(sdata))
		clear(sdata) // хеши больше не нужны
	}
	minUID := a.uidMin()

	// UID 0 у кого-то кроме root.
	for _, u := range users {
		a.next.Users[u.Name] = u.UID
		if u.UID == 0 && u.Name != "root" {
			uid0.Status = model.AuditFail
			addEv(&uid0, at("/etc/passwd", u.Line, u.Name+":x:0"))
		}
	}
	if uid0.Status == model.AuditFail {
		uid0.Recommendation = i18n.T("audit.acct_uid0_extra.rec")
	} else {
		addEv(&uid0, i18n.T("ev.audit_only_root_uid0"))
	}

	// Пароли: пустые и слабые хеши. Без прав на shadow — unknown.
	if serr != nil {
		for _, c := range []*model.AuditCheck{&empty, &weak} {
			c.Status = model.AuditUnknown
			addEv(c, i18n.T("ev.audit_no_access", "/etc/shadow"))
		}
	} else {
		for _, name := range sortedKeys(shadow) {
			si := shadow[name]
			if si.Empty {
				empty.Status = model.AuditFail
				addEv(&empty, i18n.T("ev.audit_empty_pw", name, si.Line))
			}
			if !si.Locked && (si.Algo == "1" || si.Algo == "des") {
				weak.Status = model.AuditFail
				addEv(&weak, i18n.T("ev.audit_weak_hash", name, algoName(si.Algo)))
			}
		}
		if empty.Status == model.AuditFail {
			empty.Recommendation = i18n.T("audit.acct_empty_password.rec")
		} else {
			addEv(&empty, i18n.T("ev.audit_no_empty_pw"))
		}
		if weak.Status == model.AuditFail {
			weak.Recommendation = i18n.T("audit.acct_weak_hash.rec")
		} else {
			addEv(&weak, i18n.T("ev.audit_hash_ok"))
		}
	}

	// Служебные пользователи с рабочей оболочкой. С заблокированным
	// паролем (postgres в Debian) — только предупреждение: войти можно
	// лишь по ключу или через su от root. Пустой пароль — не блокировка:
	// войти может любой. Без прав на /etc/shadow блокировку не узнать.
	for _, u := range users {
		if u.UID == 0 || u.UID >= minUID || u.UID == 65534 || noLoginShells[u.Shell] {
			continue
		}
		si, known := shadow[u.Name]
		if serr != nil {
			if worse(model.AuditUnknown, shell.Status) {
				shell.Status = model.AuditUnknown
			}
			addEv(&shell, i18n.T("ev.audit_service_shell_nolock", u.Name, u.UID, u.Shell))
			continue
		}
		locked := known && si.Locked && !si.Empty
		if locked {
			if shell.Status == model.AuditPass {
				shell.Status = model.AuditWarn
			}
			addEv(&shell, i18n.T("ev.audit_service_shell_locked", u.Name, u.UID, u.Shell))
		} else {
			shell.Status = model.AuditFail
			addEv(&shell, i18n.T("ev.audit_service_shell", u.Name, u.UID, u.Shell))
		}
	}
	if shell.Status == model.AuditFail || shell.Status == model.AuditWarn {
		shell.Recommendation = i18n.T("audit.acct_service_shell.rec")
	}

	// Привилегированные группы: члены по /etc/group и по основной группе.
	byGID := map[int]string{}
	for _, gr := range groups {
		byGID[gr.GID] = gr.Name
	}
	members := map[string][]string{}
	for _, gr := range groups {
		if slices.Contains(privGroups, gr.Name) {
			members[gr.Name] = append(members[gr.Name], gr.Members...)
		}
	}
	for _, u := range users {
		if gname := byGID[u.GID]; slices.Contains(privGroups, gname) {
			members[gname] = append(members[gname], u.Name)
		}
	}
	priv.Status = model.AuditInfo
	for _, gname := range privGroups {
		m := members[gname]
		sort.Strings(m)
		m = slices.Compact(m)
		if len(m) == 0 {
			continue
		}
		a.next.Priv[gname] = m
		addEv(&priv, i18n.L(fmt.Sprintf("%s: %s", gname, strings.Join(m, ", "))))
	}
	priv.Recommendation = i18n.T("audit.acct_priv_groups.rec")

	// Изменения относительно прошлого запуска.
	a.accountChanges(users, members, &newUsers, &priv)

	// Повторы имён и идентификаторов.
	dupCheck := func(kind i18n.Msg, keys map[string][]int) {
		for _, k := range sortedKeys(keys) {
			if lines := keys[k]; len(lines) > 1 {
				dup.Status = model.AuditFail
				addEv(&dup, i18n.T("ev.audit_duplicate", kind, k, fmt.Sprint(lines)))
			}
		}
	}
	names, uids, gnames, gids := map[string][]int{}, map[string][]int{}, map[string][]int{}, map[string][]int{}
	for _, u := range users {
		names[u.Name] = append(names[u.Name], u.Line)
		uids[strconv.Itoa(u.UID)] = append(uids[strconv.Itoa(u.UID)], u.Line)
	}
	for _, gr := range groups {
		gnames[gr.Name] = append(gnames[gr.Name], gr.Line)
		gids[strconv.Itoa(gr.GID)] = append(gids[strconv.Itoa(gr.GID)], gr.Line)
	}
	dupCheck(i18n.T("ev.audit_dup_user"), names)
	dupCheck(i18n.L("/etc/passwd: UID"), uids)
	dupCheck(i18n.T("ev.audit_dup_group"), gnames)
	dupCheck(i18n.L("/etc/group: GID"), gids)
	if dup.Status == model.AuditFail {
		dup.Recommendation = i18n.T("audit.acct_duplicate_ids.rec")
	}

	a.accountFilePerms(&perms)
	a.homePerms(users, minUID, &homes)
	a.rootPath(&path)
	return result()
}

func algoName(a string) string {
	switch a {
	case "1":
		return "MD5 ($1$)"
	case "des":
		return "DES"
	}
	return a
}

// accountChanges — новые пользователи и новые члены привилегированных
// групп с прошлого запуска аудита.
//
// Изменение держит проверку в fail/warn ChangeWindow (см. applyRecent):
// следующий запуск сравнивает уже с новой базовой линией.
func (a *auditor) accountChanges(users []passwdEntry, members map[string][]string, newUsers, priv *model.AuditCheck) {
	newUsers.Change = true
	b := a.opt.Baseline
	if b == nil {
		newUsers.Status = model.AuditNA
		addEv(newUsers, i18n.T("ev.audit_no_baseline"))
		return
	}
	if b.Init {
		rootGroups := map[string]bool{}
		for g, m := range members {
			if rootEquivalent[g] {
				for _, u := range m {
					rootGroups[u] = true
				}
			}
		}
		for _, u := range users {
			if _, ok := b.Users[u.Name]; !ok {
				a.change(newUsers.ID, u.UID == 0 || rootGroups[u.Name], i18n.T("ev.audit_new_user", u.Name, u.UID, u.Shell))
			}
		}
		if a.groupsRead && b.Priv != nil {
			for _, g := range privGroups {
				for _, u := range members[g] {
					if !slices.Contains(b.Priv[g], u) {
						a.change(priv.ID, true, i18n.T("ev.audit_new_member", u, g))
					}
				}
			}
		}
	}
	switch {
	case a.applyRecent(newUsers):
		newUsers.Recommendation = i18n.T("audit.acct_new.rec")
	case !b.Init:
		addEv(newUsers, i18n.T("ev.audit_baseline_saved", len(users)))
	default:
		addEv(newUsers, i18n.T("ev.audit_no_new_users"))
	}
	a.applyRecent(priv)
}

// accountFilePerms — права /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow.
func (a *auditor) accountFilePerms(c *model.AuditCheck) {
	for _, f := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"} {
		fi, err := a.lstat(f)
		if err != nil {
			continue
		}
		secret := strings.Contains(f, "shadow")
		bad := a.writableByOthers(fi) || (secret && fi.Mode().Perm()&0o007 != 0)
		if bad {
			c.Status = model.AuditFail
			addEv(c, i18n.T("ev.audit_bad_perms", f, describe(fi)))
		}
	}
	if c.Status == model.AuditFail {
		c.Recommendation = i18n.T("audit.acct_passwd_perms.rec")
		c.FixCommand = "chown root:root /etc/passwd /etc/group && chmod 644 /etc/passwd /etc/group && chown root:shadow /etc/shadow /etc/gshadow && chmod 640 /etc/shadow /etc/gshadow"
	} else {
		addEv(c, i18n.T("ev.audit_account_files_ok"))
	}
}

// homePerms — домашние каталоги, доступные на запись всем. Туда можно
// подложить .bashrc или authorized_keys чужому пользователю.
func (a *auditor) homePerms(users []passwdEntry, minUID int, c *model.AuditCheck) {
	for _, u := range users {
		if !(u.UID == 0 || u.UID >= minUID) || u.UID == 65534 || noLoginShells[u.Shell] || u.Home == "" || u.Home == "/" {
			continue
		}
		fi, err := a.lstat(u.Home)
		if err != nil || !fi.IsDir() {
			continue
		}
		m := fi.Mode().Perm()
		switch {
		case m&0o002 != 0:
			c.Status = model.AuditFail
			addEv(c, i18n.T("ev.audit_home_writable", u.Name, u.Home, describe(fi)))
		case u.UID == 0 && m&0o077 != 0:
			if c.Status == model.AuditPass {
				c.Status = model.AuditWarn
			}
			addEv(c, i18n.T("ev.audit_root_home", u.Home, describe(fi)))
		}
	}
	if c.Status != model.AuditPass {
		c.Recommendation = i18n.T("audit.acct_home_perms.rec")
	}
}

// rootPath — каталоги в PATH root: «.», пустой элемент или каталог,
// доступный на запись не root, позволяют подменить команду, которую root
// вызовет по имени.
func (a *auditor) rootPath(c *model.AuditCheck) {
	type src struct {
		file   string
		follow bool
	}
	// Строка с PATH показывается один раз, даже если в ней несколько
	// плохих каталогов.
	shownLine := map[string]bool{}
	lineEv := func(file string, n int, line string) {
		if k := fmt.Sprintf("%s:%d", file, n); !shownLine[k] {
			shownLine[k] = true
			addEv(c, at(file, n, strings.TrimSpace(line)))
		}
	}
	for _, s := range []src{{"/etc/environment", true}, {"/etc/login.defs", true}, {"/root/.profile", false}, {"/root/.bashrc", false}} {
		data, err := a.read(s.file, s.follow)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			val, ok := pathAssignment(line)
			if !ok {
				continue
			}
			for _, dir := range strings.Split(val, ":") {
				if strings.Contains(dir, "$") {
					continue // $PATH и другие переменные
				}
				// Оболочка раскрывает «~» после «=» и «:» в домашний
				// каталог root; «~user» — чужой домашний каталог.
				if dir == "~" || strings.HasPrefix(dir, "~/") {
					dir = "/root" + strings.TrimPrefix(dir, "~")
				} else if strings.HasPrefix(dir, "~") {
					continue
				}
				switch {
				case dir == "" || dir == "." || !strings.HasPrefix(dir, "/"):
					c.Status = model.AuditFail
					lineEv(s.file, i+1, line)
					addEv(c, i18n.T("ev.audit_path_relative", dir))
				default:
					if fi, err := a.stat(dir); err == nil && fi.IsDir() && a.writableByOthers(fi) && fi.Mode()&os.ModeSticky == 0 {
						c.Status = model.AuditFail
						lineEv(s.file, i+1, line)
						addEv(c, i18n.T("ev.audit_writable", dir, describe(fi)))
					}
				}
			}
		}
	}
	if c.Status == model.AuditFail {
		c.Recommendation = i18n.T("audit.acct_root_path.rec")
	} else {
		addEv(c, i18n.T("ev.audit_path_ok"))
	}
}

// pathAssignment — значение PATH из строки «PATH=…», «export PATH=…» или
// «ENV_SUPATH PATH=…» (login.defs).
func pathAssignment(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "#") {
		return "", false
	}
	t = strings.TrimPrefix(t, "export ")
	t = strings.TrimPrefix(t, "ENV_SUPATH")
	t = strings.TrimSpace(t)
	v, ok := strings.CutPrefix(t, "PATH=")
	if !ok {
		return "", false
	}
	if i := strings.IndexAny(v, ";#"); i >= 0 {
		v = v[:i]
	}
	return strings.Trim(strings.TrimSpace(v), `"'`), true
}

package detect

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// ---------------------------------------------------------------------
// Справочники
// ---------------------------------------------------------------------

// tempDirs — каталоги, куда может писать любой пользователь. Запуск
// программ оттуда типичен для вредоносного ПО и почти не встречается у
// штатных служб.
var tempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/", "/run/user/", "/var/run/user/"}

// systemDirs — стандартные каталоги исполняемых файлов дистрибутива и
// пакетов.
var systemDirs = []string{
	"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/", "/usr/lib64/", "/lib64/",
	"/usr/libexec/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/local/lib/", "/snap/", "/usr/share/",
}

// distroDirs — каталоги, куда файлы попадают только из пакетов
// дистрибутива (в отличие от /usr/local и /opt, куда ставят вручную).
var distroDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/", "/usr/lib64/", "/lib64/", "/usr/libexec/"}

// shells — командные оболочки.
var shells = set("sh", "bash", "dash", "zsh", "ksh", "ash", "csh", "tcsh", "fish", "busybox", "mksh")

// interpreters — интерпретаторы и сетевые утилиты, которые часто
// используются для reverse shell.
var interpreters = set("python", "python2", "python3", "perl", "ruby", "php", "lua", "node", "nc", "ncat", "netcat", "socat", "telnet", "awk", "gawk", "openssl")

// networkTools — утилиты, запуск которых веб-сервером подозрителен.
var networkTools = set("nc", "ncat", "netcat", "socat", "curl", "wget", "telnet")

// webServers — процессы, обслуживающие запросы из сети. Запуск ими
// оболочки — классический признак эксплуатации уязвимости или web-shell.
var webServers = set("nginx", "apache2", "httpd", "lighttpd", "caddy", "php-fpm", "php-cgi", "uwsgi", "gunicorn",
	"mysqld", "mariadbd", "postgres", "redis-server", "mongod", "tomcat", "jetty", "unicorn", "puma")

// weakWebServers — среды, которые нередко штатно запускают shell
// (сборки, npm-скрипты, Jenkins), поэтому признак для них слабее.
var weakWebServers = set("java", "node", "python", "python3", "ruby")

// knownDaemons — имена системных служб, под которые любят маскироваться.
var knownDaemons = set("sshd", "systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "systemd-resolved",
	"systemd-networkd", "systemd-timesyncd", "init", "cron", "crond", "atd", "rsyslogd", "syslogd", "dbus-daemon",
	"polkitd", "agetty", "udevd", "snapd", "containerd", "dockerd", "kthreadd", "kworker", "ksoftirqd", "kswapd0",
	"migration", "watchdogd", "irqbalance", "multipathd", "auditd", "nginx", "apache2", "mysqld", "postgres")

// minerNames — имена известных программ-майнеров и связанных с ними
// вредоносов (kinsing, kdevtmpfsi).
var minerNames = set("xmrig", "xmr-stak", "xmrig-notls", "minerd", "cpuminer", "cgminer", "bfgminer", "ethminer",
	"t-rex", "lolminer", "nbminer", "phoenixminer", "kdevtmpfsi", "kinsing", "nanominer", "srbminer", "teamredminer")

// poolPorts — порты, типичные для пулов майнинга (4444 также порт
// Metasploit по умолчанию).
var poolPorts = map[int]bool{3333: true, 4444: true, 5555: true, 7777: true, 14433: true, 14444: true, 45560: true, 45700: true, 20535: true, 20580: true}

// devHiddenOK — скрытые каталоги, где программы штатно живут
// (инструменты разработчика, рантаймы).
var devHiddenOK = []string{"/.local/", "/.cache/", "/.vscode-server/", "/.cursor-server/", "/.nvm/", "/.cargo/", "/.rustup/",
	"/.npm/", "/.pyenv/", "/.rbenv/", "/.sdkman/", "/.bun/", "/.deno/", "/.config/", "/.docker/", "/.go/", "/.asdf/", "/.volta/"}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// ---------------------------------------------------------------------
// Вспомогательные функции
// ---------------------------------------------------------------------

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// baseName — имя исполняемого файла без пути и версии интерпретатора
// (python3.11 → python3).
func baseName(path string) string {
	b := filepath.Base(path)
	if strings.HasPrefix(b, "python") || strings.HasPrefix(b, "php") || strings.HasPrefix(b, "perl") || strings.HasPrefix(b, "ruby") {
		if i := strings.IndexByte(b, '.'); i > 0 {
			b = b[:i]
		}
	}
	return b
}

// progName — «главное» имя программы: comm, а если он обрезан —
// базовое имя exe.
func progName(p *model.Process) string {
	if p.Exe != "" {
		return baseName(p.Exe)
	}
	return p.Name
}

func isShell(p *model.Process) bool { return shells[p.Name] || shells[progName(p)] }
func isInterpreter(p *model.Process) bool {
	return interpreters[baseName(p.Name)] || interpreters[progName(p)]
}

func cmdText(p *model.Process) string { return strings.Join(p.Args, " ") }

// exeRef — как ссылаться на exe в доказательствах.
func exeRef(p *model.Process) i18n.Msg {
	return i18n.L(fmt.Sprintf("/proc/%d/exe → %s", p.PID, p.Exe))
}

func inTemp(path string) bool { return path != "" && hasAnyPrefix(path, tempDirs) }

func inSystem(path string) bool { return path != "" && hasAnyPrefix(path, systemDirs) }

// skipUserRules — правила про исполняемый файл и имя неприменимы к
// потокам ядра и зомби.
func skipUserRules(p *model.Process) bool { return p.Kernel || p.State == "Z" }

func one(f model.Finding) []model.Finding { return []model.Finding{f} }

// ---------------------------------------------------------------------
// Расположение
// ---------------------------------------------------------------------

func ruleExeLocation(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || !inTemp(p.Exe) {
		return nil
	}
	return one(model.Finding{
		ID: "exe_in_temp", Title: i18n.T("rule.exe_in_temp.title"), Category: model.CatLocation, Weight: 15,
		Evidence:       []i18n.Msg{exeRef(p), i18n.T("ev.dir_world_writable")},
		Recommendation: i18n.T("rule.exe_in_temp.rec", quote(filepath.Dir(p.Exe)), p.PID, quote(p.Exe)),
	})
}

func ruleHiddenPath(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || p.Exe == "" || !strings.Contains(p.Exe, "/.") {
		return nil
	}
	for _, ok := range devHiddenOK {
		if strings.Contains(p.Exe, ok) {
			return nil
		}
	}
	return one(model.Finding{
		ID: "exe_hidden_path", Title: i18n.T("rule.exe_hidden_path.title"), Category: model.CatLocation, Weight: 10,
		Evidence:       []i18n.Msg{exeRef(p), i18n.T("ev.hidden_component")},
		Recommendation: i18n.T("rule.exe_hidden_path.rec", quote(filepath.Dir(p.Exe))),
	})
}

func ruleCwdTemp(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || !inTemp(p.Cwd+"/") || inTemp(p.Exe) {
		return nil
	}
	return one(model.Finding{
		ID: "cwd_in_temp", Title: i18n.T("rule.cwd_in_temp.title"), Category: model.CatLocation, Weight: 4,
		Evidence:       []i18n.Msg{i18n.L(fmt.Sprintf("/proc/%d/cwd → %s", p.PID, p.Cwd))},
		Recommendation: i18n.T("rule.cwd_in_temp.rec", quote(p.Cwd)),
	})
}

// ---------------------------------------------------------------------
// Целостность исполняемого файла
// ---------------------------------------------------------------------

func ruleExeDeleted(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || !p.ExeDeleted || strings.HasPrefix(p.Exe, "/memfd:") {
		return nil
	}
	f := model.Finding{
		ID: "exe_deleted", Title: i18n.T("rule.exe_deleted.title"), Category: model.CatIntegrity, Weight: 20,
		Evidence:       []i18n.Msg{i18n.L(exeRef(p).Lit + " (deleted)")},
		Recommendation: i18n.T("rule.exe_deleted.rec", p.PID),
	}
	if inSystem(p.Exe) || strings.HasPrefix(p.Exe, "/opt/") {
		// После apt upgrade у долгоживущих служб старый бинарник числится
		// удалённым — это норма до перезапуска службы.
		f.Weight = 4
		f.Title = i18n.T("rule.exe_deleted.title_system")
		f.Evidence = append(f.Evidence, i18n.T("ev.system_path_after_upgrade"))
		f.Recommendation = i18n.T("rule.exe_deleted.rec_system")
	}
	return one(f)
}

func ruleMemfd(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || !strings.HasPrefix(p.Exe, "/memfd:") {
		return nil
	}
	f := model.Finding{
		ID: "exe_memfd", Title: i18n.T("rule.exe_memfd.title"), Category: model.CatIntegrity, Weight: 35, Strong: true,
		Evidence:       []i18n.Msg{exeRef(p), i18n.T("ev.memfd_no_file")},
		Recommendation: i18n.T("rule.exe_memfd.rec", p.PID),
	}
	if strings.Contains(p.Exe, "runc") || p.Name == "runc" || strings.HasPrefix(p.Name, "runc:") {
		// Старые версии runc штатно перезапускают себя через memfd.
		f.Weight, f.Strong = 8, false
		f.Evidence = append(f.Evidence, i18n.T("ev.memfd_runc"))
	}
	return one(f)
}

func ruleExePerms(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || p.ExeInfo == nil {
		return nil
	}
	var out []model.Finding
	fi := p.ExeInfo
	if fi.WorldWritable {
		out = append(out, model.Finding{
			ID: "exe_world_writable", Title: i18n.T("rule.exe_world_writable.title"), Category: model.CatIntegrity, Weight: 15,
			Evidence:       []i18n.Msg{exeRef(p), i18n.T("ev.mode", fi.Mode)},
			Recommendation: i18n.T("rule.exe_world_writable.rec", quote(p.Exe)),
		})
	}
	if (fi.SetUID || fi.SetGID) && !inSystem(p.Exe) {
		out = append(out, model.Finding{
			ID: "exe_setuid_nonstd", Title: i18n.T("rule.exe_setuid_nonstd.title"), Category: model.CatIntegrity, Weight: 15,
			Evidence:       []i18n.Msg{exeRef(p), i18n.T("ev.mode", fi.Mode)},
			Recommendation: i18n.T("rule.exe_setuid_nonstd.rec"),
		})
	}
	if inSystem(p.Exe) && fi.UID > 0 {
		out = append(out, model.Finding{
			ID: "exe_system_nonroot", Title: i18n.T("rule.exe_system_nonroot.title"), Category: model.CatIntegrity, Weight: 10,
			Evidence:       []i18n.Msg{exeRef(p), i18n.T("ev.owner_uid", fi.UID)},
			Recommendation: i18n.T("rule.exe_system_nonroot.rec", quote(p.Exe)),
		})
	}
	return out
}

// ---------------------------------------------------------------------
// Маскировка и имена
// ---------------------------------------------------------------------

var kthreadLike = regexp.MustCompile(`^\[[^\]]+\]$`)

func ruleKthreadMasquerade(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || len(p.Args) == 0 {
		return nil
	}
	if !kthreadLike.MatchString(strings.TrimSpace(p.Args[0])) {
		return nil
	}
	ev := []i18n.Msg{i18n.T("ev.argv0_kthread", quote(p.Args[0])), i18n.T("ev.no_pf_kthread")}
	if p.Exe != "" {
		ev = append(ev, exeRef(p))
	}
	return one(model.Finding{
		ID: "kthread_masquerade", Title: i18n.T("rule.kthread_masquerade.title"), Category: model.CatMasquerade, Weight: 30, Strong: true,
		Evidence:       ev,
		Recommendation: i18n.T("rule.kthread_masquerade.rec", p.PID),
	})
}

func ruleSystemNameMasquerade(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || p.Exe == "" {
		return nil
	}
	name := p.Name
	if !knownDaemons[name] {
		// kworker/0:1, ksoftirqd/0 и т. п.
		if i := strings.IndexByte(name, '/'); i > 0 && knownDaemons[name[:i]] {
			name = name[:i]
		} else {
			return nil
		}
	}
	if inSystem(p.Exe) || strings.HasPrefix(p.Exe, "/opt/") {
		return nil
	}
	return one(model.Finding{
		ID: "system_name_masquerade", Title: i18n.T("rule.system_name_masquerade.title"), Category: model.CatMasquerade, Weight: 25,
		Evidence:       []i18n.Msg{i18n.T("ev.name_is_daemon", quote(p.Name)), exeRef(p)},
		Recommendation: i18n.T("rule.system_name_masquerade.rec", name, p.PPID),
	})
}

// wrappers — программы, у которых comm и имя файла штатно различаются.
var wrappers = set("env", "busybox", "sudo", "su", "runuser", "timeout", "nohup", "nice", "ionice", "setsid", "stdbuf", "dumb-init", "tini", "s6-svscan", "flock")

func ruleNameMismatch(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || p.Exe == "" || p.Name == "" || strings.HasPrefix(p.Exe, "/memfd:") {
		return nil
	}
	// Программы из каталогов дистрибутива нередко штатно называются иначе
	// (systemd-udevd → udevadm, (sd-pam) → systemd-executor). Маскировку
	// под системные имена ловит отдельное правило system_name_masquerade.
	if hasAnyPrefix(p.Exe, distroDirs) {
		return nil
	}
	exeBase := filepath.Base(p.Exe)
	if wrappers[exeBase] || isInterpreter(p) || shells[exeBase] || strings.HasPrefix(exeBase, "python") || strings.HasPrefix(exeBase, "java") {
		return nil
	}
	// comm обрезается ядром до 15 символов.
	short := exeBase
	if len(short) > 15 {
		short = short[:15]
	}
	if p.Name == short || strings.HasPrefix(exeBase, p.Name) || strings.HasPrefix(p.Name, short) {
		return nil
	}
	// Многие программы штатно меняют comm (postgres, nginx: worker и др.)
	// на что-то, содержащее имя файла.
	if strings.Contains(p.Name, exeBase) || strings.Contains(exeBase, strings.SplitN(p.Name, ":", 2)[0]) {
		return nil
	}
	return one(model.Finding{
		ID: "name_mismatch", Title: i18n.T("rule.name_mismatch.title"), Category: model.CatMasquerade, Weight: 6,
		Evidence:       []i18n.Msg{i18n.L("comm = " + quote(p.Name)), exeRef(p)},
		Recommendation: i18n.T("rule.name_mismatch.rec"),
	})
}

func ruleUnusualName(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || p.Name == "" {
		return nil
	}
	var reason i18n.Msg
	switch {
	case strings.HasPrefix(p.Name, "."):
		reason = i18n.T("ev.name_dot")
	case strings.TrimSpace(p.Name) == "":
		reason = i18n.T("ev.name_spaces")
	case strings.HasSuffix(p.Name, " ") || strings.HasPrefix(p.Name, " "):
		reason = i18n.T("ev.name_edge_space")
	default:
		return nil
	}
	return one(model.Finding{
		ID: "unusual_name", Title: i18n.T("rule.unusual_name.title"), Category: model.CatMasquerade, Weight: 8,
		Evidence:       []i18n.Msg{i18n.T("ev.comm_reason", quote(p.Name), reason)},
		Recommendation: i18n.T("rule.unusual_name.rec"),
	})
}

func ruleEmptyCmdline(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || len(p.Args) > 0 || p.Exe == "" || slices.Contains(p.Access, "cmdline") {
		return nil
	}
	return one(model.Finding{
		ID: "empty_cmdline", Title: i18n.T("rule.empty_cmdline.title"), Category: model.CatMasquerade, Weight: 6,
		Evidence:       []i18n.Msg{i18n.T("ev.cmdline_empty", p.PID, p.Exe)},
		Recommendation: i18n.T("rule.empty_cmdline.rec"),
	})
}

// ruleUnicodeControl: в имени, пути или аргументах есть невидимые символы
// форматирования (model.InvisibleRune). Штатным программам они не нужны,
// а символ «справа налево» или нулевой ширины меняет вид строки в ps и в
// панели. Сами символы интерфейсы показывают как «�».
func ruleUnicodeControl(p *model.Process, _ *Context) []model.Finding {
	if p.Kernel {
		return nil
	}
	var ev []i18n.Msg
	check := func(field i18n.Msg, s string) {
		for _, r := range s {
			if model.InvisibleRune(r) {
				ev = append(ev, i18n.T("ev.unicode_char", field, fmt.Sprintf("U+%04X", r)))
				return
			}
		}
	}
	check(i18n.T("ev.field_name"), p.Name)
	check(i18n.T("ev.field_path"), p.Exe)
	for i, a := range p.Args {
		if len(ev) >= 5 {
			break
		}
		check(i18n.L(fmt.Sprintf("argv[%d]", i)), a)
	}
	if len(ev) == 0 {
		return nil
	}
	return one(model.Finding{
		ID: "unicode_control", Title: i18n.T("rule.unicode_control.title"), Category: model.CatMasquerade, Weight: 15,
		Evidence:       ev,
		Recommendation: i18n.T("rule.unicode_control.rec", p.PID),
	})
}

// ruleCmdlineTruncated: командная строка длиннее лимита сканера. Так
// бывает у Java с длинным classpath, но огромная строка — и способ
// спрятать команду за мусором или перегрузить мониторинг.
func ruleCmdlineTruncated(p *model.Process, _ *Context) []model.Finding {
	if !p.CmdlineTruncated {
		return nil
	}
	w := 8
	if progName(p) == "java" {
		w = 2 // длинный classpath — обычное дело
	}
	return one(model.Finding{
		ID: "cmdline_truncated", Title: i18n.T("rule.cmdline_truncated.title"), Category: model.CatMasquerade, Weight: w,
		Evidence:       []i18n.Msg{i18n.T("ev.cmdline_read_bytes", len(p.Cmdline))},
		Recommendation: i18n.T("rule.cmdline_truncated.rec", p.PID),
	})
}

// ---------------------------------------------------------------------
// Цепочки запуска
// ---------------------------------------------------------------------

func ruleWebShellChain(p *model.Process, c *Context) []model.Finding {
	if skipUserRules(p) {
		return nil
	}
	child := progName(p)
	if !(isShell(p) || networkTools[child] || networkTools[p.Name] || (isInterpreter(p) && !webServers[p.Name])) {
		return nil
	}
	par := c.parent(p)
	if par == nil {
		return nil
	}
	pname := par.Name
	if strings.HasPrefix(pname, "php-fpm") {
		pname = "php-fpm"
	}
	strong := webServers[pname] || webServers[progName(par)]
	weak := weakWebServers[pname] || weakWebServers[progName(par)]
	if !strong && !weak {
		return nil
	}
	// Среды выполнения (python, node, java) постоянно запускают сами себя
	// и другие интерпретаторы; для них учитываются только оболочки и
	// сетевые утилиты.
	if !strong && !(isShell(p) || networkTools[child] || networkTools[p.Name]) {
		return nil
	}
	f := model.Finding{
		ID: "web_spawns_shell", Title: i18n.T("rule.web_spawns_shell.title"), Category: model.CatChain, Weight: 30, Strong: true,
		Evidence: []i18n.Msg{i18n.T("ev.parent_child", par.PID, quote(par.Name), par.Exe, p.PID, quote(p.Name)),
			i18n.T("ev.child_cmdline", truncate(p.Cmdline, 200))},
		Recommendation: i18n.T("rule.web_spawns_shell.rec"),
	}
	if !strong {
		f.Weight, f.Strong = 12, false
		f.Evidence = append(f.Evidence, i18n.T("ev.parent_runtime"))
	}
	return one(f)
}

func ruleSchedulerChain(p *model.Process, c *Context) []model.Finding {
	if skipUserRules(p) {
		return nil
	}
	par := c.parent(p)
	if par == nil || !(par.Name == "cron" || par.Name == "crond" || par.Name == "atd") {
		return nil
	}
	text := cmdText(p)
	if !inTemp(p.Exe) && !downloadExec.MatchString(text) && !strings.Contains(text, "/dev/shm") && !strings.Contains(text, "/tmp/") {
		return nil
	}
	return one(model.Finding{
		ID: "scheduler_suspicious", Title: i18n.T("rule.scheduler_suspicious.title"), Category: model.CatPersistence, Weight: 15,
		Evidence:       []i18n.Msg{i18n.T("ev.parent", par.PID, quote(par.Name)), i18n.T("ev.cmdline", truncate(p.Cmdline, 200))},
		Recommendation: i18n.T("rule.scheduler_suspicious.rec"),
	})
}

// ---------------------------------------------------------------------
// Сеть
// ---------------------------------------------------------------------

func socketByFD(p *model.Process, fd int) (string, bool) {
	for _, f := range p.Files {
		if f.FD == fd && f.Kind == "socket" {
			return f.Target, true
		}
	}
	return "", false
}

func describeSocket(p *model.Process, target string) string {
	for _, s := range p.Sockets {
		if fmt.Sprintf("socket:[%d]", s.Inode) == target && s.Proto != "unix" {
			return fmt.Sprintf("%s %s:%d → %s:%d %s", s.Proto, s.LocalAddr, s.LocalPort, s.RemoteAddr, s.RemotePort, s.State)
		}
		if fmt.Sprintf("socket:[%d]", s.Inode) == target {
			return "unix " + s.Path
		}
	}
	return ""
}

func ruleStdioSocket(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || !(isShell(p) || isInterpreter(p)) {
		return nil
	}
	var ev []string
	inet := false
	for fd := 0; fd <= 2; fd++ {
		t, ok := socketByFD(p, fd)
		if !ok {
			continue
		}
		d := describeSocket(p, t)
		if d != "" && !strings.HasPrefix(d, "unix") {
			inet = true
		}
		ev = append(ev, fmt.Sprintf("/proc/%d/fd/%d → %s %s", p.PID, fd, t, d))
	}
	// Unix-сокеты на stdio штатно бывают у служб под systemd (журнал),
	// поэтому признак ставится только для сетевых сокетов или если мы
	// не смогли определить тип сокета.
	if len(ev) == 0 || (!inet && allUnix(p, ev)) {
		return nil
	}
	return one(model.Finding{
		ID: "stdio_socket", Title: i18n.T("rule.stdio_socket.title"), Category: model.CatNetwork, Weight: 40, Strong: true,
		Evidence:       append(i18n.Ls(ev), i18n.T("ev.reverse_shell_like")),
		Recommendation: i18n.T("rule.stdio_socket.rec", p.PID, p.PPID),
	})
}

func allUnix(p *model.Process, ev []string) bool {
	for _, s := range p.Sockets {
		if s.Proto != "unix" {
			for _, e := range ev {
				if strings.Contains(e, fmt.Sprintf("socket:[%d]", s.Inode)) {
					return false
				}
			}
		}
	}
	// Если сокет не найден ни в одной таблице, тип неизвестен — считаем
	// unix, чтобы не создавать ложных срабатываний.
	return true
}

func ruleShellOutbound(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) {
		return nil
	}
	name := progName(p)
	if !(isShell(p) || name == "nc" || name == "ncat" || name == "netcat" || name == "socat" || name == "telnet") {
		return nil
	}
	var ev []string
	for _, s := range p.Sockets {
		if strings.HasPrefix(s.Proto, "tcp") && s.State == "ESTABLISHED" && !model.IsLoopback(s.RemoteAddr) {
			ev = append(ev, fmt.Sprintf("%s %s:%d → %s:%d", s.Proto, s.LocalAddr, s.LocalPort, s.RemoteAddr, s.RemotePort))
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return one(model.Finding{
		ID: "shell_network", Title: i18n.T("rule.shell_network.title"), Category: model.CatNetwork, Weight: 15,
		Evidence:       i18n.Ls(ev),
		Recommendation: i18n.T("rule.shell_network.rec"),
	})
}

func rulePoolPort(p *model.Process, _ *Context) []model.Finding {
	var ev []string
	for _, s := range p.Sockets {
		if strings.HasPrefix(s.Proto, "tcp") && s.State == "ESTABLISHED" && poolPorts[s.RemotePort] && !model.IsLoopback(s.RemoteAddr) {
			ev = append(ev, fmt.Sprintf("%s → %s:%d", s.Proto, s.RemoteAddr, s.RemotePort))
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return one(model.Finding{
		ID: "pool_port", Title: i18n.T("rule.pool_port.title"), Category: model.CatNetwork, Weight: 12,
		Evidence:       append(i18n.Ls(ev), i18n.T("ev.pool_ports")),
		Recommendation: i18n.T("rule.pool_port.rec"),
	})
}

func ruleSuspiciousListen(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) {
		return nil
	}
	risky := inTemp(p.Exe) || p.ExeDeleted || isShell(p) || networkTools[progName(p)] || strings.HasPrefix(p.Exe, "/memfd:")
	if !risky {
		return nil
	}
	var ev []string
	for _, s := range p.Sockets {
		if s.State == "LISTEN" && s.Proto != "unix" && !model.IsLoopback(s.LocalAddr) {
			ev = append(ev, fmt.Sprintf("%s %s:%d LISTEN", s.Proto, s.LocalAddr, s.LocalPort))
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return one(model.Finding{
		ID: "suspicious_listen", Title: i18n.T("rule.suspicious_listen.title"), Category: model.CatNetwork, Weight: 15,
		Evidence:       append(i18n.Ls(ev), i18n.T("ev.risky_listener")),
		Recommendation: i18n.T("rule.suspicious_listen.rec"),
	})
}

// ---------------------------------------------------------------------
// Содержимое командной строки
// ---------------------------------------------------------------------

var (
	reverseShell = regexp.MustCompile(`/dev/(tcp|udp)/[^\s/]+/\d+|\b(nc|ncat|netcat)\b[^|;]*\s-(e|c)\s|\bsocat\b[^|;]*\bexec:|pty\.spawn|\b(ba)?sh -i\b|mkfifo\s[^;|]+;[^|]*\|\s*(nc|ncat|netcat)\b|socket\.socket\(.*connect|fsockopen\(|TCPSocket\.(new|open)`)
	downloadExec = regexp.MustCompile(`(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b|base64\s+(-d|--decode)[^|;]*\|\s*(ba|da)?sh\b|(curl|wget)\b[^;&]*(;|&&)\s*chmod\s+\+?[0-7x]+\s|python[0-9.]*\s+-c\s.*(urllib|requests).*exec|echo\s+[A-Za-z0-9+/=]{60,}\s*\|\s*base64`)
	minerPattern = regexp.MustCompile(`(?i)stratum\+(tcp|ssl|tls)://|--donate-level|\bcryptonight\b|\brandomx\b|--cpu-max-threads-hint|\bnicehash\b|\b(supportxmr|minexmr|nanopool|moneroocean|hashvault|c3pool|f2pool)\b|--algo[= ](rx/0|cn/|kawpow|ethash)`)
)

func ruleReverseShellPattern(p *model.Process, _ *Context) []model.Finding {
	text := cmdText(p)
	m := reverseShell.FindString(text)
	if m == "" {
		return nil
	}
	return one(model.Finding{
		ID: "revshell_pattern", Title: i18n.T("rule.revshell_pattern.title"), Category: model.CatContent, Weight: 35, Strong: true,
		Evidence:       []i18n.Msg{i18n.T("ev.match", quote(m)), i18n.T("ev.cmdline", truncate(p.Cmdline, 300))},
		Recommendation: i18n.T("rule.revshell_pattern.rec"),
	})
}

func ruleDownloadExec(p *model.Process, _ *Context) []model.Finding {
	text := cmdText(p)
	m := downloadExec.FindString(text)
	if m == "" {
		return nil
	}
	return one(model.Finding{
		ID: "download_exec", Title: i18n.T("rule.download_exec.title"), Category: model.CatContent, Weight: 25,
		Evidence:       []i18n.Msg{i18n.T("ev.match", quote(truncate(m, 200))), i18n.T("ev.cmdline", truncate(p.Cmdline, 300))},
		Recommendation: i18n.T("rule.download_exec.rec"),
	})
}

func ruleMinerPattern(p *model.Process, _ *Context) []model.Finding {
	text := cmdText(p)
	m := minerPattern.FindString(text)
	if m == "" {
		return nil
	}
	return one(model.Finding{
		ID: "miner_pattern", Title: i18n.T("rule.miner_pattern.title"), Category: model.CatContent, Weight: 30, Strong: true,
		Evidence:       []i18n.Msg{i18n.T("ev.match", quote(m)), i18n.T("ev.cmdline", truncate(p.Cmdline, 300))},
		Recommendation: i18n.T("rule.miner_pattern.rec"),
	})
}

func ruleMinerName(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) {
		return nil
	}
	name := strings.ToLower(p.Name)
	exe := strings.ToLower(baseName(p.Exe))
	if !minerNames[name] && !minerNames[exe] {
		return nil
	}
	return one(model.Finding{
		ID: "miner_name", Title: i18n.T("rule.miner_name.title"), Category: model.CatMasquerade, Weight: 15,
		Evidence:       []i18n.Msg{i18n.L(fmt.Sprintf("comm = %q, exe = %q", p.Name, p.Exe))},
		Recommendation: i18n.T("rule.miner_name.rec"),
	})
}

// ---------------------------------------------------------------------
// Поведение
// ---------------------------------------------------------------------

func ruleCPUSustained(p *model.Process, c *Context) []model.Finding {
	n := c.Counters(p.Key).HighCPUScans
	if p.Kernel || c.Cfg.CPUSustainScan <= 0 || n < c.Cfg.CPUSustainScan {
		return nil
	}
	dur := c.Cfg.ScanInterval * timeMul(n)
	return one(model.Finding{
		ID: "cpu_sustained", Title: i18n.T("rule.cpu_sustained.title"), Category: model.CatBehavior, Weight: 8,
		Evidence: []i18n.Msg{i18n.T("ev.cpu_sustained", fmt.Sprintf("%.0f", c.Cfg.CPUThreshold), n,
			dur.Round(time.Second).String(), fmt.Sprintf("%.1f", p.CPUPercent))},
		Recommendation: i18n.T("rule.cpu_sustained.rec"),
	})
}

func ruleMemSustained(p *model.Process, c *Context) []model.Finding {
	n := c.Counters(p.Key).HighMemScans
	if p.Kernel || c.Cfg.CPUSustainScan <= 0 || n < c.Cfg.CPUSustainScan {
		return nil
	}
	return one(model.Finding{
		ID: "mem_sustained", Title: i18n.T("rule.mem_sustained.title"), Category: model.CatBehavior, Weight: 4,
		Evidence: []i18n.Msg{i18n.T("ev.mem_sustained", fmt.Sprintf("%.0f", c.Cfg.MemThreshold), n,
			fmt.Sprintf("%.1f", p.MemPercent))},
		Recommendation: i18n.T("rule.mem_sustained.rec"),
	})
}

// timeMul переводит число сканирований в множитель для time.Duration.
func timeMul(n int) time.Duration { return time.Duration(n) }

// ---------------------------------------------------------------------
// Окружение и привилегии
// ---------------------------------------------------------------------

func ruleLDPreload(p *model.Process, _ *Context) []model.Finding {
	var vars []string
	for _, v := range p.EnvFlags {
		if v == "LD_PRELOAD" || v == "LD_AUDIT" {
			vars = append(vars, v)
		}
	}
	if len(vars) == 0 {
		return nil
	}
	return one(model.Finding{
		ID: "ld_preload", Title: i18n.T("rule.ld_preload.title"), Category: model.CatEnvironment, Weight: 20,
		Evidence:       []i18n.Msg{i18n.T("ev.environ_has", p.PID, strings.Join(vars, ", ")), i18n.T("ev.preload_rootkits")},
		Recommendation: i18n.T("rule.ld_preload.rec", p.PID),
	})
}

func ruleRootFromWritable(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || p.EUID != 0 || p.Exe == "" {
		return nil
	}
	if !(inTemp(p.Exe) || strings.HasPrefix(p.Exe, "/home/")) {
		return nil
	}
	return one(model.Finding{
		ID: "root_from_writable", Title: i18n.T("rule.root_from_writable.title"), Category: model.CatPrivilege, Weight: 10,
		Evidence:       []i18n.Msg{i18n.L("EUID = 0, " + exeRef(p).Lit)},
		Recommendation: i18n.T("rule.root_from_writable.rec"),
	})
}

// ---------------------------------------------------------------------
// Справочные признаки (не влияют на оценку)
// ---------------------------------------------------------------------

func ruleInfoContainer(p *model.Process, _ *Context) []model.Finding {
	if p.ContainerRuntime == "" {
		return nil
	}
	ev := []i18n.Msg{i18n.T("ev.container_runtime", p.ContainerRuntime)}
	if p.Container != "" {
		ev = append(ev, i18n.T("ev.container_id", p.Container))
	}
	if len(p.NSPID) > 1 {
		ev = append(ev, i18n.T("ev.container_pid", p.NSPID[len(p.NSPID)-1]))
	}
	return one(model.Finding{ID: "info_container", Title: i18n.T("rule.info_container.title"), Category: model.CatInfo, Evidence: ev,
		Recommendation: i18n.T("rule.info_container.rec")})
}

func ruleInfoListen(p *model.Process, _ *Context) []model.Finding {
	var ev []string
	for _, s := range p.Sockets {
		if s.State == "LISTEN" && s.Proto != "unix" {
			ev = append(ev, s.Proto+" "+s.LocalAddr+":"+strconv.Itoa(s.LocalPort))
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return one(model.Finding{ID: "info_listen", Title: i18n.T("rule.info_listen.title"), Category: model.CatInfo, Evidence: i18n.Ls(ev)})
}

func ruleInfoAccess(p *model.Process, _ *Context) []model.Finding {
	if len(p.Access) == 0 {
		return nil
	}
	return one(model.Finding{ID: "info_access", Title: i18n.T("rule.info_access.title"), Category: model.CatInfo,
		Evidence:       []i18n.Msg{i18n.T("ev.not_read", strings.Join(p.Access, ", "))},
		Recommendation: i18n.T("rule.info_access.rec")})
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// quote — строка в кавычках Go (%q): так в доказательствах и командах
// видны пробелы и управляющие символы в именах и путях.
func quote(s string) string { return strconv.Quote(s) }

package detect

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

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
func exeRef(p *model.Process) string {
	return fmt.Sprintf("/proc/%d/exe → %s", p.PID, p.Exe)
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
		ID: "exe_in_temp", Title: "Исполняемый файл во временном каталоге", Category: model.CatLocation, Weight: 15,
		Evidence:       []string{exeRef(p), "каталог доступен на запись всем пользователям"},
		Recommendation: fmt.Sprintf("Проверьте происхождение файла: ls -la %q; sha256sum /proc/%d/exe; dpkg -S %q (штатные пакеты туда не ставятся).", filepath.Dir(p.Exe), p.PID, p.Exe),
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
		ID: "exe_hidden_path", Title: "Исполняемый файл в скрытом каталоге или со скрытым именем", Category: model.CatLocation, Weight: 10,
		Evidence:       []string{exeRef(p), "компонент пути начинается с точки — такие файлы не видны в обычном ls"},
		Recommendation: fmt.Sprintf("Осмотрите каталог: ls -la %q; выясните, какой пакет или пользователь его создал.", filepath.Dir(p.Exe)),
	})
}

func ruleCwdTemp(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || !inTemp(p.Cwd+"/") || inTemp(p.Exe) {
		return nil
	}
	return one(model.Finding{
		ID: "cwd_in_temp", Title: "Рабочий каталог во временном каталоге", Category: model.CatLocation, Weight: 4,
		Evidence:       []string{fmt.Sprintf("/proc/%d/cwd → %s", p.PID, p.Cwd)},
		Recommendation: fmt.Sprintf("Посмотрите содержимое рабочего каталога: ls -la %q.", p.Cwd),
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
		ID: "exe_deleted", Title: "Исполняемый файл удалён после запуска", Category: model.CatIntegrity, Weight: 20,
		Evidence:       []string{exeRef(p) + " (deleted)"},
		Recommendation: fmt.Sprintf("Скопируйте бинарник, пока процесс жив: cp /proc/%d/exe /root/deleted-%d.bin; проверьте хеш.", p.PID, p.PID),
	}
	if inSystem(p.Exe) || strings.HasPrefix(p.Exe, "/opt/") {
		// После apt upgrade у долгоживущих служб старый бинарник числится
		// удалённым — это норма до перезапуска службы.
		f.Weight = 4
		f.Title = "Исполняемый файл в системном каталоге заменён или удалён"
		f.Evidence = append(f.Evidence, "путь системный: типично после обновления пакетов до перезапуска службы")
		f.Recommendation = "Сверьте с журналом обновлений (/var/log/apt/history.log, /var/log/dpkg.log) и перезапустите службу, если обновление было."
	}
	return one(f)
}

func ruleMemfd(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || !strings.HasPrefix(p.Exe, "/memfd:") {
		return nil
	}
	f := model.Finding{
		ID: "exe_memfd", Title: "Процесс запущен из памяти (memfd), без файла на диске", Category: model.CatIntegrity, Weight: 35, Strong: true,
		Evidence:       []string{exeRef(p), "memfd_create позволяет выполнять код, не оставляя файла в файловой системе"},
		Recommendation: fmt.Sprintf("Сохраните образ: cp /proc/%d/exe /root/memfd-%d.bin; проверьте родителя и сетевые соединения процесса.", p.PID, p.PID),
	}
	if strings.Contains(p.Exe, "runc") || p.Name == "runc" || strings.HasPrefix(p.Name, "runc:") {
		// Старые версии runc штатно перезапускают себя через memfd.
		f.Weight, f.Strong = 8, false
		f.Evidence = append(f.Evidence, "имя связано с runc — старые версии runc используют memfd штатно")
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
			ID: "exe_world_writable", Title: "Исполняемый файл доступен на запись всем", Category: model.CatIntegrity, Weight: 15,
			Evidence:       []string{exeRef(p), "права: " + fi.Mode},
			Recommendation: fmt.Sprintf("Любой пользователь может подменить файл. Проверьте целостность и права: stat %q.", p.Exe),
		})
	}
	if (fi.SetUID || fi.SetGID) && !inSystem(p.Exe) {
		out = append(out, model.Finding{
			ID: "exe_setuid_nonstd", Title: "SUID/SGID-файл вне системных каталогов", Category: model.CatIntegrity, Weight: 15,
			Evidence:       []string{exeRef(p), "права: " + fi.Mode},
			Recommendation: "Найдите все такие файлы: find / -xdev -perm /6000 -type f 2>/dev/null — и сравните со списком пакетов.",
		})
	}
	if inSystem(p.Exe) && fi.UID > 0 {
		out = append(out, model.Finding{
			ID: "exe_system_nonroot", Title: "Файл в системном каталоге принадлежит не root", Category: model.CatIntegrity, Weight: 10,
			Evidence:       []string{exeRef(p), fmt.Sprintf("владелец UID %d", fi.UID)},
			Recommendation: fmt.Sprintf("Проверьте пакет и контрольные суммы: dpkg -S %q && dpkg --verify $(dpkg -S %q | cut -d: -f1).", p.Exe, p.Exe),
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
	ev := []string{fmt.Sprintf("argv[0] = %q — так выглядят только потоки ядра в ps", p.Args[0]),
		"флаг PF_KTHREAD в /proc/PID/stat не установлен — это пользовательский процесс"}
	if p.Exe != "" {
		ev = append(ev, exeRef(p))
	}
	return one(model.Finding{
		ID: "kthread_masquerade", Title: "Пользовательский процесс маскируется под поток ядра", Category: model.CatMasquerade, Weight: 30, Strong: true,
		Evidence:       ev,
		Recommendation: fmt.Sprintf("У настоящих потоков ядра нет exe и cmdline. Изучите файл: ls -l /proc/%d/exe; sha256sum /proc/%d/exe.", p.PID, p.PID),
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
		ID: "system_name_masquerade", Title: "Имя системной службы, но файл вне системных каталогов", Category: model.CatMasquerade, Weight: 25,
		Evidence:       []string{fmt.Sprintf("имя процесса %q совпадает с системной службой", p.Name), exeRef(p)},
		Recommendation: fmt.Sprintf("Сравните с настоящим файлом службы (command -v %s) и проверьте, как процесс был запущен (родитель PID %d).", name, p.PPID),
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
		ID: "name_mismatch", Title: "Имя процесса не совпадает с именем исполняемого файла", Category: model.CatMasquerade, Weight: 6,
		Evidence:       []string{fmt.Sprintf("comm = %q", p.Name), exeRef(p)},
		Recommendation: "Некоторые программы штатно переименовывают процесс; если эта программа к ним не относится, выясните, зачем она скрывает настоящее имя.",
	})
}

func ruleUnusualName(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || p.Name == "" {
		return nil
	}
	var reason string
	switch {
	case strings.HasPrefix(p.Name, "."):
		reason = "имя начинается с точки"
	case strings.TrimSpace(p.Name) == "":
		reason = "имя состоит из пробелов"
	case strings.HasSuffix(p.Name, " ") || strings.HasPrefix(p.Name, " "):
		reason = "имя начинается или заканчивается пробелом"
	default:
		return nil
	}
	return one(model.Finding{
		ID: "unusual_name", Title: "Необычное имя процесса", Category: model.CatMasquerade, Weight: 8,
		Evidence:       []string{fmt.Sprintf("comm = %q: %s", p.Name, reason)},
		Recommendation: "Такие имена затрудняют поиск процесса в ps/top. Проверьте файл и родителя.",
	})
}

func ruleEmptyCmdline(p *model.Process, _ *Context) []model.Finding {
	if skipUserRules(p) || len(p.Args) > 0 || p.Exe == "" || slices.Contains(p.Access, "cmdline") {
		return nil
	}
	return one(model.Finding{
		ID: "empty_cmdline", Title: "Пустая командная строка у пользовательского процесса", Category: model.CatMasquerade, Weight: 6,
		Evidence:       []string{fmt.Sprintf("/proc/%d/cmdline пуст, но exe есть: %s", p.PID, p.Exe)},
		Recommendation: "Процесс мог затереть argv, чтобы скрыть параметры запуска. Сверьте с exe и родителем.",
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
		ID: "web_spawns_shell", Title: "Сетевой сервис запустил оболочку или сетевую утилиту", Category: model.CatChain, Weight: 30, Strong: true,
		Evidence: []string{fmt.Sprintf("родитель PID %d %q (%s) → потомок PID %d %q", par.PID, par.Name, par.Exe, p.PID, p.Name),
			"командная строка потомка: " + truncate(p.Cmdline, 200)},
		Recommendation: "Проверьте журналы веб-сервера (access/error log) около времени запуска, поищите недавно изменённые файлы в каталоге сайта (find /var/www -mmin -1440 -type f).",
	}
	if !strong {
		f.Weight, f.Strong = 12, false
		f.Evidence = append(f.Evidence, "родитель — среда выполнения, которая иногда штатно запускает shell (сборка, скрипты)")
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
		ID: "scheduler_suspicious", Title: "Планировщик запускает программу из временного каталога или загрузку из сети", Category: model.CatPersistence, Weight: 15,
		Evidence:       []string{fmt.Sprintf("родитель PID %d %q", par.PID, par.Name), "командная строка: " + truncate(p.Cmdline, 200)},
		Recommendation: "Проверьте задания: crontab -l -u <user>; ls -la /etc/cron* /var/spool/cron/crontabs; atq.",
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
		ID: "stdio_socket", Title: "Ввод/вывод оболочки или интерпретатора подключён к сетевому сокету", Category: model.CatNetwork, Weight: 40, Strong: true,
		Evidence:       append(ev, "так выглядит reverse/bind shell: команды приходят по сети прямо в оболочку"),
		Recommendation: fmt.Sprintf("Определите удалённую сторону: ss -tnp | grep 'pid=%d,'; проверьте, кто запустил процесс (родитель PID %d).", p.PID, p.PPID),
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
		ID: "shell_network", Title: "Оболочка или netcat/socat держит внешнее TCP-соединение", Category: model.CatNetwork, Weight: 15,
		Evidence:       ev,
		Recommendation: "Оболочки обычно не открывают сетевые соединения сами. Выясните назначение удалённого адреса (whois, журналы файрвола).",
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
		ID: "pool_port", Title: "Соединение на порт, типичный для пулов майнинга или Metasploit", Category: model.CatNetwork, Weight: 12,
		Evidence:       append(ev, "порты 3333/4444/5555/7777/14444 и др. часто используют пулы Monero; 4444 — порт Metasploit по умолчанию"),
		Recommendation: "Порт сам по себе ничего не доказывает. Проверьте, что за сервис на удалённой стороне и нужна ли процессу эта связь.",
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
		ID: "suspicious_listen", Title: "Подозрительный процесс принимает входящие соединения", Category: model.CatNetwork, Weight: 15,
		Evidence:       append(ev, "процесс запущен из временного каталога/удалён/является оболочкой или netcat"),
		Recommendation: "Так может выглядеть bind shell или бэкдор. Проверьте, кто подключался: ss -tnp state established.",
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
		ID: "revshell_pattern", Title: "Командная строка содержит конструкцию reverse shell", Category: model.CatContent, Weight: 35, Strong: true,
		Evidence:       []string{fmt.Sprintf("совпадение: %q", m), "командная строка: " + truncate(p.Cmdline, 300)},
		Recommendation: "Определите удалённый адрес из командной строки и соединений процесса, проверьте журналы входа и веб-сервера на момент запуска.",
	})
}

func ruleDownloadExec(p *model.Process, _ *Context) []model.Finding {
	text := cmdText(p)
	m := downloadExec.FindString(text)
	if m == "" {
		return nil
	}
	return one(model.Finding{
		ID: "download_exec", Title: "Загрузка из сети с немедленным выполнением", Category: model.CatContent, Weight: 25,
		Evidence:       []string{fmt.Sprintf("совпадение: %q", truncate(m, 200)), "командная строка: " + truncate(p.Cmdline, 300)},
		Recommendation: "Установщики иногда так работают, но это и типичный способ доставки вредоносов. Скачайте скрипт отдельно (без выполнения) и изучите.",
	})
}

func ruleMinerPattern(p *model.Process, _ *Context) []model.Finding {
	text := cmdText(p)
	m := minerPattern.FindString(text)
	if m == "" {
		return nil
	}
	return one(model.Finding{
		ID: "miner_pattern", Title: "Параметры командной строки характерны для майнера", Category: model.CatContent, Weight: 30, Strong: true,
		Evidence:       []string{fmt.Sprintf("совпадение: %q", m), "командная строка: " + truncate(p.Cmdline, 300)},
		Recommendation: "Проверьте загрузку CPU (top -p PID), соединения процесса и способ запуска (cron, systemd, родитель).",
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
		ID: "miner_name", Title: "Имя совпадает с известной программой-майнером", Category: model.CatMasquerade, Weight: 15,
		Evidence:       []string{fmt.Sprintf("comm = %q, exe = %q", p.Name, p.Exe)},
		Recommendation: "Само имя ничего не доказывает (майнинг может быть разрешён). Проверьте, согласован ли запуск.",
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
		ID: "cpu_sustained", Title: "Длительная высокая загрузка CPU", Category: model.CatBehavior, Weight: 8,
		Evidence:       []string{fmt.Sprintf("CPU ≥ %.0f%% в %d сканированиях подряд (≈ %s), сейчас %.1f%%", c.Cfg.CPUThreshold, n, dur.Round(time.Second), p.CPUPercent)},
		Recommendation: "Высокая нагрузка бывает у легитимных задач (сборки, БД). Подозрительна в сочетании с другими признаками: майнинг, неизвестный файл.",
	})
}

func ruleMemSustained(p *model.Process, c *Context) []model.Finding {
	n := c.Counters(p.Key).HighMemScans
	if p.Kernel || c.Cfg.CPUSustainScan <= 0 || n < c.Cfg.CPUSustainScan {
		return nil
	}
	return one(model.Finding{
		ID: "mem_sustained", Title: "Длительное высокое потребление памяти", Category: model.CatBehavior, Weight: 4,
		Evidence:       []string{fmt.Sprintf("RAM ≥ %.0f%% в %d сканированиях подряд, сейчас %.1f%%", c.Cfg.MemThreshold, n, p.MemPercent)},
		Recommendation: "Сверьте с ожидаемым поведением программы; проверьте утечки памяти или нецелевое использование.",
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
		ID: "ld_preload", Title: "Задана переменная подгрузки библиотек (LD_PRELOAD/LD_AUDIT)", Category: model.CatEnvironment, Weight: 20,
		Evidence:       []string{fmt.Sprintf("в /proc/%d/environ есть %s (значение не сохраняется)", p.PID, strings.Join(vars, ", ")), "через подгружаемую библиотеку руткиты перехватывают системные вызовы"},
		Recommendation: fmt.Sprintf("Посмотрите значение вручную: tr '\\0' '\\n' < /proc/%d/environ | grep -E '^LD_(PRELOAD|AUDIT)='; проверьте библиотеку (dpkg -S, sha256sum).", p.PID),
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
		ID: "root_from_writable", Title: "Процесс root запущен из каталога, доступного на запись пользователям", Category: model.CatPrivilege, Weight: 10,
		Evidence:       []string{fmt.Sprintf("EUID = 0, %s", exeRef(p))},
		Recommendation: "Подмена такого файла непривилегированным пользователем даёт ему права root. Проверьте, кто владеет файлом и каталогом.",
	})
}

// ---------------------------------------------------------------------
// Справочные признаки (не влияют на оценку)
// ---------------------------------------------------------------------

func ruleInfoContainer(p *model.Process, _ *Context) []model.Finding {
	if p.ContainerRuntime == "" {
		return nil
	}
	ev := []string{fmt.Sprintf("среда: %s", p.ContainerRuntime)}
	if p.Container != "" {
		ev = append(ev, "контейнер: "+p.Container)
	}
	if len(p.NSPID) > 1 {
		ev = append(ev, fmt.Sprintf("PID внутри контейнера: %d", p.NSPID[len(p.NSPID)-1]))
	}
	return one(model.Finding{ID: "info_container", Title: "Процесс работает в контейнере", Category: model.CatInfo, Evidence: ev,
		Recommendation: "Пути exe/cwd указаны внутри файловой системы контейнера."})
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
	return one(model.Finding{ID: "info_listen", Title: "Процесс слушает сетевые порты", Category: model.CatInfo, Evidence: ev})
}

func ruleInfoAccess(p *model.Process, _ *Context) []model.Finding {
	if len(p.Access) == 0 {
		return nil
	}
	return one(model.Finding{ID: "info_access", Title: "Часть данных недоступна из-за прав", Category: model.CatInfo,
		Evidence:       []string{"не прочитано: " + strings.Join(p.Access, ", ")},
		Recommendation: "Запустите сканер от root, чтобы правила, зависящие от этих данных, могли сработать."})
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

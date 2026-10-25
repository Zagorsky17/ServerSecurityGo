package fail2ban

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// now — момент «сейчас» во всех тестах; журнал пишется в UTC.
var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func stamp(ago time.Duration) string {
	return now.Add(-ago).Format("2006-01-02 15:04:05") + ",123"
}

// logLine — строка журнала в формате fail2ban 1.x.
func logLine(ago time.Duration, module, level, msg string) string {
	return stamp(ago) + " fail2ban." + module + strings.Repeat(" ", 10) + "[812]: " + level + "    " + msg + "\n"
}

func write(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// installed — дерево хоста с установленным fail2ban и jail sshd.
func installed(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "usr/bin/fail2ban-server", "#!/usr/bin/python3\n")
	write(t, root, "etc/fail2ban/jail.conf", "[DEFAULT]\nbantime = 10m\nfindtime = 10m\nmaxretry = 5\nenabled = false\n"+
		"filter = %(__name__)s[mode=%(mode)s]\nmode = normal\n\n[sshd]\nport = ssh\nlogpath = %(sshd_log)s\n\n[nginx-http-auth]\nport = http,https\n")
	write(t, root, "etc/fail2ban/jail.d/defaults-debian.conf", "[sshd]\nenabled = true\n")
	return root
}

var server = &model.Process{PID: 812, Name: "fail2ban-server", Args: []string{"/usr/bin/python3", "/usr/bin/fail2ban-server", "-xf", "start"}, Key: "812-1"}

func build(t *testing.T, c *Collector, root string, procs ...*model.Process) (*model.Fail2banReport, []model.SystemFinding) {
	t.Helper()
	return c.Build(Input{HostRoot: root, Procs: procs, Now: now, Days: 14, Loc: time.UTC})
}

func findingIDs(fs []model.SystemFinding) map[string]model.SystemFinding {
	m := map[string]model.SystemFinding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func TestNotInstalled(t *testing.T) {
	rep, fs := build(t, NewCollector(), t.TempDir())
	if rep.Installed || len(fs) != 0 {
		t.Fatalf("fail2ban нет, а отчёт %+v, находки %v", rep, fs)
	}
	// Каталог /etc/fail2ban без программы (остался после удаления пакета) —
	// тоже «не установлен».
	root := t.TempDir()
	write(t, root, "etc/fail2ban/jail.local", "[sshd]\nenabled = true\n")
	if rep, _ := build(t, NewCollector(), root); rep.Installed {
		t.Fatal("остатки конфигурации без fail2ban-server приняты за установку")
	}
	// Процесс без файлов (fail2ban в контейнере с сетью хоста) — установлен.
	if rep, _ := build(t, NewCollector(), root, server); !rep.Installed || !rep.Running {
		t.Fatalf("процесс fail2ban-server не учтён: %+v", rep)
	}
}

func TestNotRunning(t *testing.T) {
	root := installed(t)
	write(t, root, "var/log/fail2ban.log", logLine(3*time.Hour, "server", "INFO", "Exiting Fail2ban"))
	rep, fs := build(t, NewCollector(), root)
	if !rep.Installed || rep.Running {
		t.Fatalf("installed/running: %+v", rep)
	}
	f, ok := findingIDs(fs)["fail2ban_not_running"]
	if !ok || f.Risk != model.RiskMedium {
		t.Fatalf("нет fail2ban_not_running MEDIUM: %+v", fs)
	}
	ev := ""
	for _, m := range f.Evidence {
		ev += m.String() + "\n"
	}
	if !strings.Contains(ev, "/usr/bin/fail2ban-server") || !strings.Contains(ev, now.Add(-3*time.Hour).Format("2006-01-02 15:04")) {
		t.Errorf("в фактах нет способа обнаружения или времени остановки:\n%s", ev)
	}
	// Запущен — находки нет.
	if _, fs := build(t, NewCollector(), root, server); findingIDs(fs)["fail2ban_not_running"].ID != "" {
		t.Error("fail2ban_not_running при запущенном fail2ban")
	}
}

func TestJailConfig(t *testing.T) {
	root := installed(t)
	write(t, root, "etc/fail2ban/jail.local", "[DEFAULT]\nbantime = 1h ; комментарий\nignoreip = 127.0.0.1/8 ::1\n    192.0.2.0/24, 198.51.100.7\n\n"+
		"[sshd]\nmaxretry = 3\nbantime.increment = true\n")
	// .local в jail.d читается после jail.local и включает nginx.
	write(t, root, "etc/fail2ban/jail.d/zz-nginx.local", "[nginx-http-auth]\nenabled = yes\nbantime = -1\n")
	// jail.d/*.conf читается раньше jail.local: его значение переопределено.
	write(t, root, "etc/fail2ban/jail.d/00-early.conf", "[sshd]\nmaxretry = 9\n")
	jc := readJails(root)
	if len(jc.Jails) != 2 {
		t.Fatalf("ожидалось 2 включённых jail, получено %+v", jc.Jails)
	}
	n, s := jc.Jails[0], jc.Jails[1]
	if n.Name != "nginx-http-auth" || s.Name != "sshd" {
		t.Fatalf("порядок/имена: %+v", jc.Jails)
	}
	if s.MaxRetry != 3 || s.BanTime != 3600 || s.FindTime != 600 || !s.Increment || s.Filter != "sshd" || !s.SSH() || s.Port != "ssh" {
		t.Errorf("sshd: %+v", s)
	}
	if s.Source != "/etc/fail2ban/jail.d/defaults-debian.conf" {
		t.Errorf("источник enabled: %q", s.Source)
	}
	if strings.Join(s.IgnoreIP, " ") != "127.0.0.1/8 ::1 192.0.2.0/24 198.51.100.7" {
		t.Errorf("ignoreip (многострочный, через запятую): %q", s.IgnoreIP)
	}
	if n.BanTime != -1 || n.SSH() || n.Filter != "nginx-http-auth" || n.Port != "http,https" {
		t.Errorf("nginx: %+v", n)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]int64{"600": 600, "10m": 600, "1h": 3600, "1h 30m": 5400, "1h30m": 5400, "2d": 172800, "1w": 604800,
		"-1": -1, "1 hour": 3600, "3 minutes": 180, "1.5h": 5400, "0": 0} {
		got, ok := parseDuration(in)
		if !ok || got != want {
			t.Errorf("parseDuration(%q) = %d, %v; нужно %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "abc", "10x", "h", "1h 2zz", "%(bantime)s"} {
		if _, ok := parseDuration(in); ok {
			t.Errorf("parseDuration(%q) принял ошибочное значение", in)
		}
	}
}

func TestInterpolation(t *testing.T) {
	c := newINI()
	c.parse("[DEFAULT]\na = %(b)s-x\nb = %(a)s\nname = %(__name__)s\npct = 100%%\n[j]\nc = %(name)s/%(missing)s\n", "t")
	if v, _ := c.get("j", "c"); v != "j/%(missing)s" {
		t.Errorf("__name__ и неизвестная ссылка: %q", v)
	}
	if v, _ := c.get("j", "pct"); v != "100%" {
		t.Errorf("%%%%: %q", v)
	}
	// Взаимные ссылки не зацикливают разбор.
	if v, _ := c.get("j", "a"); !strings.Contains(v, "-x") {
		t.Errorf("циклическая ссылка: %q", v)
	}
}

// demoLog — журнал за трое суток: перебор с двух адресов одной /24,
// баны, разбан, перезапуск fail2ban с восстановлением бана.
func demoLog() string {
	var b strings.Builder
	h := time.Hour
	for i := 0; i < 5; i++ {
		b.WriteString(logLine(50*h+time.Duration(i)*time.Second, "filter", "INFO", "[sshd] Found 203.0.113.5 - 2026-10-23 10:00:00"))
	}
	b.WriteString(logLine(50*h-time.Minute, "actions", "NOTICE", "[sshd] Ban 203.0.113.5"))
	b.WriteString(logLine(49*h, "actions", "NOTICE", "[sshd] Unban 203.0.113.5"))
	// Перезапуск: старые баны сняты, действующий восстановлен.
	b.WriteString(logLine(5*h, "actions", "NOTICE", "[sshd] Ban 198.51.100.9"))
	b.WriteString(logLine(4*h, "server", "INFO", "Exiting Fail2ban"))
	b.WriteString(logLine(4*h-time.Minute, "server", "INFO", "Starting Fail2ban v1.0.2"))
	b.WriteString(logLine(4*h-time.Minute, "actions", "NOTICE", "[sshd] Restore Ban 203.0.113.77"))
	for i := 0; i < 7; i++ {
		b.WriteString(logLine(2*h-time.Duration(i)*time.Second, "filter", "INFO", "[sshd] Found 203.0.113.5 - 2026-10-25 10:00:00"))
	}
	b.WriteString(logLine(30*time.Minute, "filter", "INFO", "[sshd] Found 203.0.113.6 - 2026-10-25 11:30:00"))
	b.WriteString(logLine(30*time.Minute, "actions", "NOTICE", "[sshd] Ban 203.0.113.5"))
	b.WriteString(logLine(29*time.Minute, "observer", "NOTICE", "[sshd] Increase Ban 203.0.113.5 (2 # 2:00:00 -> "+now.Add(90*time.Minute).Format("2006-01-02 15:04:05")+")"))
	b.WriteString(logLine(20*time.Minute, "filter", "INFO", "[sshd] Ignore 192.0.2.1 by ip"))
	b.WriteString(logLine(10*time.Minute, "actions", "WARNING", "[sshd] 203.0.113.5 already banned"))
	// Старый формат 0.8 (без PID) и мусор.
	b.WriteString(stamp(5*time.Minute) + " fail2ban.actions: WARNING [ssh-old] Ban 2001:db8::1\n")
	b.WriteString("garbage line\n\n2026-13-45 99:99:99,000 fail2ban.x [1]: INFO [sshd] Ban 1.2.3.4\n")
	b.WriteString(logLine(time.Minute, "filter", "INFO", "[sshd] Found not-an-ip - x"))
	return b.String()
}

func TestLogReport(t *testing.T) {
	root := installed(t)
	write(t, root, "var/log/fail2ban.log", demoLog())
	rep, fs := build(t, NewCollector(), root, server)
	if !rep.LogAvailable || rep.Version != "1.0.2" || len(rep.LogFiles) != 1 || rep.LogFiles[0] != "/var/log/fail2ban.log" {
		t.Fatalf("журнал: available=%v version=%q files=%v", rep.LogAvailable, rep.Version, rep.LogFiles)
	}
	if len(fs) != 0 {
		t.Errorf("лишние находки: %+v", fs)
	}
	if rep.Found != 13 || rep.BanCount != 4 || rep.Found24h != 8 || rep.Bans24h != 3 {
		t.Errorf("итоги: found=%d bans=%d found24h=%d bans24h=%d", rep.Found, rep.BanCount, rep.Found24h, rep.Bans24h)
	}
	if rep.Peak.Found != 7 {
		t.Errorf("пик: %+v", rep.Peak)
	}
	if n := len(rep.Hourly); n != 14*24+1 {
		t.Errorf("часов в окне: %d", n)
	}
	if len(rep.Daily) < 14 || len(rep.Daily) > 16 {
		t.Errorf("дней: %d", len(rep.Daily))
	}
	// Текущие баны: 203.0.113.5 (продлён) и 2001:db8::1 (старый формат).
	// 198.51.100.9 снят перезапуском, восстановленный 203.0.113.77 истёк
	// (bantime 10m).
	bans := map[string]model.Fail2banBan{}
	for _, b := range rep.Bans {
		bans[b.IP] = b
	}
	if len(bans) != 2 {
		t.Fatalf("текущие баны: %+v", rep.Bans)
	}
	b5 := bans["203.0.113.5"]
	if b5.Count != 2 || !b5.Until.Equal(now.Add(90*time.Minute)) || b5.UnbanCommand != "fail2ban-client set sshd unbanip 203.0.113.5" {
		t.Errorf("бан 203.0.113.5: %+v", b5)
	}
	if _, ok := bans["2001:db8::1"]; !ok {
		t.Error("бан из журнала старого формата не учтён")
	}
	// Топ: 203.0.113.5 первым; подсеть /24 из двух адресов.
	if len(rep.Top) == 0 || rep.Top[0].Addr != "203.0.113.5" || rep.Top[0].Found != 12 || rep.Top[0].Bans != 2 {
		t.Errorf("топ: %+v", rep.Top)
	}
	if len(rep.TopNets) != 1 || rep.TopNets[0].Addr != "203.0.113.0/24" || rep.TopNets[0].IPs != 2 {
		t.Errorf("подсети: %+v", rep.TopNets)
	}
	jails := map[string]model.Fail2banJail{}
	for _, j := range rep.Jails {
		jails[j.Name] = j
	}
	if j := jails["sshd"]; j.Found != 13 || j.Bans != 3 || j.Banned != 1 || j.Source == "" || !j.SSH {
		t.Errorf("jail sshd: %+v", j)
	}
	if j := jails["ssh-old"]; j.Source != "" || j.Banned != 1 {
		t.Errorf("jail из журнала без конфигурации: %+v", j)
	}
	if len(rep.Recent) == 0 || rep.Recent[0].Action != "ban" || rep.Recent[0].IP != "2001:db8::1" {
		t.Errorf("последние события (новые первыми): %+v", rep.Recent)
	}
}

// TestRestoredBanExpiry: восстановленный бан с bantime = 1h ещё действует.
func TestRestoredBanExpiry(t *testing.T) {
	root := installed(t)
	write(t, root, "etc/fail2ban/jail.local", "[sshd]\nbantime = 1h\n")
	write(t, root, "var/log/fail2ban.log", logLine(30*time.Minute, "server", "INFO", "Starting Fail2ban v1.1.0")+
		logLine(30*time.Minute, "actions", "NOTICE", "[sshd] Restore Ban 203.0.113.77")+
		logLine(2*time.Hour, "actions", "NOTICE", "[sshd] Ban 203.0.113.78")) // истёк: строки не по порядку, сортируются
	rep, _ := build(t, NewCollector(), root, server)
	if len(rep.Bans) != 1 || rep.Bans[0].IP != "203.0.113.77" || !rep.Bans[0].Restored || !rep.Bans[0].Until.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("баны: %+v", rep.Bans)
	}
	// Остановленный fail2ban снял правила: текущих банов нет.
	if rep, _ := build(t, NewCollector(), root); len(rep.Bans) != 0 {
		t.Errorf("баны при остановленном fail2ban: %+v", rep.Bans)
	}
}

func TestPermanentAndJailStop(t *testing.T) {
	root := installed(t)
	write(t, root, "etc/fail2ban/jail.d/x.local", "[recidive]\nenabled = true\nbantime = -1\n")
	write(t, root, "var/log/fail2ban.log", logLine(10*24*time.Hour, "actions", "NOTICE", "[recidive] Ban 203.0.113.1")+
		logLine(time.Hour, "actions", "NOTICE", "[sshd] Ban 203.0.113.2")+
		logLine(30*time.Minute, "jail", "INFO", "Jail 'sshd' stopped"))
	rep, _ := build(t, NewCollector(), root, server)
	if len(rep.Bans) != 1 || rep.Bans[0].IP != "203.0.113.1" || !rep.Bans[0].Permanent || !rep.Bans[0].Until.IsZero() {
		t.Fatalf("бессрочный бан и остановка jail: %+v", rep.Bans)
	}
}

func gz(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

// TestRotation: ротированные и сжатые файлы учитываются, после
// переименования текущего файла ничего не считается дважды, дописанное
// дочитывается.
func TestRotation(t *testing.T) {
	root := installed(t)
	found := func(ago time.Duration, ip string) string {
		return logLine(ago, "filter", "INFO", "[sshd] Found "+ip+" - x")
	}
	write(t, root, "var/log/fail2ban.log.2.gz", gz(t, found(3*24*time.Hour, "203.0.113.1")+found(3*24*time.Hour, "203.0.113.1")))
	// Файл старше окна не читается.
	old := write(t, root, "var/log/fail2ban.log.3.gz", gz(t, found(30*24*time.Hour, "203.0.113.9")))
	_ = os.Chtimes(old, now.Add(-30*24*time.Hour), now.Add(-30*24*time.Hour))
	write(t, root, "var/log/fail2ban.log.1", found(2*24*time.Hour, "203.0.113.2"))
	cur := write(t, root, "var/log/fail2ban.log", found(time.Hour, "203.0.113.3"))
	// Посторонние файлы рядом не читаются.
	write(t, root, "var/log/fail2ban.log.bak", found(time.Hour, "203.0.113.4"))

	c := NewCollector()
	rep, _ := build(t, c, root, server)
	if rep.Found != 4 || len(rep.LogFiles) != 3 {
		t.Fatalf("found=%d files=%v", rep.Found, rep.LogFiles)
	}
	// Дописали строку, причём последняя — без перевода строки: её fail2ban
	// мог ещё не дописать, она учитывается позже.
	f, _ := os.OpenFile(cur, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(found(30*time.Minute, "203.0.113.3"))
	f.WriteString(strings.TrimSuffix(found(20*time.Minute, "203.0.113.3"), "\n"))
	f.Close()
	if rep, _ = build(t, c, root, server); rep.Found != 5 {
		t.Fatalf("после дописывания found=%d, нужно 5", rep.Found)
	}
	// logrotate: .1 → .2.gz (старый .2.gz удалён), текущий → .1, новый пустой.
	os.Remove(filepath.Join(root, "var/log/fail2ban.log.2.gz"))
	os.Rename(filepath.Join(root, "var/log/fail2ban.log.1"), filepath.Join(root, "var/log/fail2ban.log.2.gz.tmp"))
	write(t, root, "var/log/fail2ban.log.2.gz", gz(t, found(2*24*time.Hour, "203.0.113.2")))
	os.Remove(filepath.Join(root, "var/log/fail2ban.log.2.gz.tmp"))
	os.Rename(cur, filepath.Join(root, "var/log/fail2ban.log.1"))
	write(t, root, "var/log/fail2ban.log", "")
	if rep, _ = build(t, c, root, server); rep.Found != 4 {
		// 203.0.113.1 (×2) ушёл вместе с удалённым .2.gz; осталось .2 (1) +
		// .1 (3, включая строку без перевода — файл больше не растёт).
		t.Fatalf("после ротации found=%d, нужно 4", rep.Found)
	}
	if len(c.files) != 3 {
		t.Errorf("кеш не забыл удалённые файлы: %d", len(c.files))
	}
	// Усечение (copytruncate): файл стал короче — разбирается заново.
	write(t, root, "var/log/fail2ban.log.1", found(time.Hour, "203.0.113.3"))
	if rep, _ = build(t, c, root, server); rep.Found != 2 {
		t.Fatalf("после усечения found=%d, нужно 2", rep.Found)
	}
}

func TestSSHWithoutJail(t *testing.T) {
	root := installed(t)
	write(t, root, "etc/fail2ban/jail.d/defaults-debian.conf", "[sshd]\nenabled = false\n[nginx-http-auth]\nenabled = true\n")
	write(t, root, "var/log/fail2ban.log", "")
	sshd := &model.Process{PID: 650, Key: "650-1", Name: "sshd", Exe: "/usr/sbin/sshd"}
	exp := &model.ExposureReport{Entries: []model.Exposure{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Scope: model.ScopePublic, ProcName: "sshd", ProcKey: "650-1", PID: 650}}}
	in := Input{HostRoot: root, Procs: []*model.Process{server, sshd}, Exposure: exp, Now: now, Loc: time.UTC}
	_, fs := NewCollector().Build(in)
	f, ok := findingIDs(fs)["fail2ban_sshd_disabled"]
	if !ok || f.Risk != model.RiskLow || f.Suppressed {
		t.Fatalf("нет fail2ban_sshd_disabled: %+v", fs)
	}
	if !strings.Contains(f.Evidence[0].String(), "0.0.0.0:22") || !strings.Contains(f.Evidence[1].String(), "nginx-http-auth") {
		t.Errorf("факты: %v", f.Evidence)
	}
	// allowlist по процессу sshd подавляет находку.
	in.Allowed = func(p *model.Process, id string) bool { return p.Name == "sshd" && id == "fail2ban_sshd_disabled" }
	_, fs = NewCollector().Build(in)
	if f := findingIDs(fs)["fail2ban_sshd_disabled"]; !f.Suppressed || f.Risk != model.RiskInfo {
		t.Errorf("allowlist не подавил: %+v", f)
	}
	// SSH только в частной сети — находки нет.
	exp.Entries[0].Scope = model.ScopePrivate
	in.Allowed = nil
	if _, fs := NewCollector().Build(in); findingIDs(fs)["fail2ban_sshd_disabled"].ID != "" {
		t.Error("находка при SSH только в частной сети")
	}
}

func TestLogUnavailable(t *testing.T) {
	root := installed(t)
	// Журнала нет.
	_, fs := build(t, NewCollector(), root, server)
	f, ok := findingIDs(fs)["fail2ban_log_unavailable"]
	if !ok || f.Risk != model.RiskInfo || !strings.Contains(f.Evidence[0].String(), "/var/log/fail2ban.log") {
		t.Fatalf("нет журнала: %+v", fs)
	}
	// Симлинк вместо журнала не открывается.
	target := write(t, root, "etc/shadow", "secret\n")
	os.MkdirAll(filepath.Join(root, "var/log"), 0o755)
	os.Symlink(target, filepath.Join(root, "var/log/fail2ban.log"))
	rep, fs := build(t, NewCollector(), root, server)
	if rep.LogAvailable || !strings.Contains(findingIDs(fs)["fail2ban_log_unavailable"].Evidence[0].String(), "symlink") &&
		!strings.Contains(findingIDs(fs)["fail2ban_log_unavailable"].Evidence[0].String(), "симлинк") {
		t.Errorf("симлинк: %+v", fs)
	}
	// Журнал в journald.
	write(t, root, "etc/fail2ban/fail2ban.local", "[Definition]\nlogtarget = SYSTEMD-JOURNAL\nloglevel = NOTICE\n")
	rep, fs = build(t, NewCollector(), root, server)
	if rep.LogTarget != "SYSTEMD-JOURNAL" || !strings.Contains(findingIDs(fs)["fail2ban_log_unavailable"].Evidence[0].String(), "SYSTEMD-JOURNAL") {
		t.Errorf("journald: %+v %+v", rep, fs)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0].String(), "NOTICE") {
		t.Errorf("предупреждение об уровне журнала: %v", rep.Warnings)
	}
}

// TestLineLimits: длинные строки и огромное число адресов не ломают разбор
// и не раздувают память.
func TestLineLimits(t *testing.T) {
	fd := newFileData()
	long := stamp(time.Hour) + " fail2ban.filter [1]: INFO [sshd] Found 203.0.113.1 " + strings.Repeat("x", 200<<10) + "\n"
	in := long + logLine(time.Hour, "filter", "INFO", "[sshd] Found 203.0.113.2 - x")
	n, _ := fd.consume(strings.NewReader(in), 1<<30, false, time.UTC)
	if n != int64(len(in)) || len(fd.byIP) != 1 {
		t.Fatalf("длинная строка: n=%d из %d, адресов %d", n, len(in), len(fd.byIP))
	}
	var b strings.Builder
	for i := 0; i < maxTotalIPs+50; i++ {
		b.WriteString(stamp(time.Hour) + " fail2ban.filter [1]: INFO [sshd] Found 10." + strconv.Itoa(i>>16) + "." + strconv.Itoa(i>>8&255) + "." + strconv.Itoa(i&255) + " - x\n")
	}
	fd = newFileData()
	fd.consume(strings.NewReader(b.String()), 1<<30, true, time.UTC)
	if len(fd.byIP) != maxTotalIPs || fd.overflow != 50 {
		t.Errorf("предел адресов: %d, сверх %d", len(fd.byIP), fd.overflow)
	}
}

func TestUnbanCommand(t *testing.T) {
	if c := unbanCommand("sshd", "203.0.113.1"); c != "fail2ban-client set sshd unbanip 203.0.113.1" {
		t.Error(c)
	}
	if c := unbanCommand("sshd", `fe80::1%";id;"`); c != "" {
		t.Errorf("адрес с зоной попал в команду: %q", c)
	}
	for _, j := range []string{"ssh;rm -rf /", "a b", "$(id)", strings.Repeat("a", 65), ""} {
		if c := unbanCommand(j, "203.0.113.1"); c != "" {
			t.Errorf("опасное имя jail %q попало в команду: %q", j, c)
		}
	}
}

// TestMemoryBudget: предел адресов и событий общий на все файлы журнала,
// а не на каждый: иначе десятки ротированных файлов умножали бы его.
func TestMemoryBudget(t *testing.T) {
	oldIPs, oldEv := maxTotalIPs, maxTotalEvts
	maxTotalIPs, maxTotalEvts = 10, 6
	t.Cleanup(func() { maxTotalIPs, maxTotalEvts = oldIPs, oldEv })
	root := installed(t)
	var a, b strings.Builder
	for i := 0; i < 8; i++ {
		ip := "203.0.113." + strconv.Itoa(i)
		a.WriteString(logLine(48*time.Hour, "filter", "INFO", "[sshd] Found "+ip+" - x"))
		a.WriteString(logLine(48*time.Hour, "actions", "NOTICE", "[sshd] Ban "+ip))
		ip = "198.51.100." + strconv.Itoa(i)
		b.WriteString(logLine(time.Hour, "filter", "INFO", "[sshd] Found "+ip+" - x"))
		b.WriteString(logLine(time.Hour, "actions", "NOTICE", "[sshd] Ban "+ip))
	}
	write(t, root, "var/log/fail2ban.log.1", a.String())
	write(t, root, "var/log/fail2ban.log", b.String())
	c := NewCollector()
	rep, _ := build(t, c, root, server)
	ips, evs := 0, 0
	for _, fd := range c.files {
		ips += len(fd.byIP) + len(fd.ignored)
		evs += len(fd.events)
	}
	if ips > 10 || evs > 6 {
		t.Errorf("общий бюджет превышен: адресов %d, событий %d", ips, evs)
	}
	if rep.Found != 16 {
		t.Errorf("почасовые счётчики не зависят от бюджета: found=%d", rep.Found)
	}
	found := false
	for _, w := range rep.Warnings {
		found = found || strings.Contains(w.String(), "отброшена") || strings.Contains(w.String(), "dropped")
	}
	if !found {
		t.Errorf("нет предупреждения о пределе: %v", rep.Warnings)
	}
}

// TestReadBudget: общий бюджет чтения кончился посреди файла — файл
// дочитывается при следующих построениях, а не считается обрезанным
// навсегда (и предупреждения о размере файла нет).
func TestReadBudget(t *testing.T) {
	old := maxTotalBytes
	t.Cleanup(func() { maxTotalBytes = old })
	root := installed(t)
	line := logLine(time.Hour, "filter", "INFO", "[sshd] Found 203.0.113.1 - x")
	maxTotalBytes = int64(len(line))*3 + 10
	write(t, root, "var/log/fail2ban.log.2.gz", gz(t, strings.Repeat(line, 5)))
	write(t, root, "var/log/fail2ban.log.1", strings.Repeat(line, 5))
	write(t, root, "var/log/fail2ban.log", strings.Repeat(line, 5))
	c := NewCollector()
	var rep *model.Fail2banReport
	for i := 0; i < 8; i++ {
		rep, _ = build(t, c, root, server)
	}
	if rep.Found != 15 {
		t.Errorf("после нескольких построений found=%d, нужно 15", rep.Found)
	}
	for _, w := range rep.Warnings {
		if strings.Contains(w.String(), "МБ") || strings.Contains(w.String(), "MB") {
			t.Errorf("ложное предупреждение о размере: %v", w)
		}
	}
}

// TestCopytruncateRegrow: после copytruncate файл успел вырасти больше
// прежнего размера — он разбирается заново, а не с середины.
func TestCopytruncateRegrow(t *testing.T) {
	root := installed(t)
	cur := write(t, root, "var/log/fail2ban.log", logLine(3*time.Hour, "filter", "INFO", "[sshd] Found 203.0.113.1 - x"))
	c := NewCollector()
	if rep, _ := build(t, c, root, server); rep.Found != 1 {
		t.Fatalf("found=%d", rep.Found)
	}
	// Тот же inode (WriteFile усекает файл), новое содержимое длиннее.
	var b strings.Builder
	for i := 0; i < 4; i++ {
		b.WriteString(logLine(time.Hour, "filter", "INFO", "[sshd] Found 198.51.100.7 - x"))
	}
	if err := os.WriteFile(cur, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ := build(t, c, root, server)
	if rep.Found != 4 || rep.Top[0].Addr != "198.51.100.7" {
		t.Errorf("после copytruncate found=%d top=%+v", rep.Found, rep.Top)
	}
}

// TestRestoreBeforeJailStarted: строка Restore Ban в ту же секунду перед
// «Jail started» не теряется; выключенный jail берёт bantime из DEFAULT.
func TestRestoreBeforeJailStarted(t *testing.T) {
	root := installed(t)
	write(t, root, "etc/fail2ban/jail.local", "[DEFAULT]\nbantime = 1d\n")
	write(t, root, "var/log/fail2ban.log", logLine(2*time.Hour, "server", "INFO", "Starting Fail2ban v1.0.2")+
		logLine(2*time.Hour, "actions", "NOTICE", "[sshd] Restore Ban 203.0.113.9")+
		logLine(2*time.Hour, "jail", "INFO", "Jail 'sshd' started")+
		logLine(time.Hour, "actions", "NOTICE", "[old-jail] Ban 203.0.113.10"))
	rep, _ := build(t, NewCollector(), root, server)
	got := map[string]bool{}
	for _, b := range rep.Bans {
		got[b.IP] = true
	}
	if !got["203.0.113.9"] || !got["203.0.113.10"] {
		t.Errorf("баны: %+v", rep.Bans)
	}
}

// TestWindowAndMemo: счётчики старше окна забываются и не попадают в топ
// (в том числе ignoreip), а без изменений отчёт не пересчитывается.
func TestWindowAndMemo(t *testing.T) {
	root := installed(t)
	write(t, root, "var/log/fail2ban.log", logLine(20*24*time.Hour, "filter", "INFO", "[sshd] Found 203.0.113.50 - x")+
		logLine(20*24*time.Hour, "filter", "INFO", "[sshd] Ignore 192.0.2.50 by ip")+
		logLine(time.Hour, "filter", "INFO", "[sshd] Found 203.0.113.1 - x"))
	c := NewCollector()
	rep, _ := build(t, c, root, server)
	if len(rep.Top) != 1 || rep.Top[0].Addr != "203.0.113.1" {
		t.Errorf("топ за окном: %+v", rep.Top)
	}
	for _, fd := range c.files {
		if len(fd.byIP) != 1 || len(fd.ignored) != 0 {
			t.Errorf("старые счётчики не забыты: %v %v", fd.byIP, fd.ignored)
		}
	}
	if rep2, _ := build(t, c, root, server); rep2 != rep {
		t.Error("отчёт пересчитан без изменений")
	}
	f, _ := os.OpenFile(filepath.Join(root, "var/log/fail2ban.log"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(logLine(time.Minute, "filter", "INFO", "[sshd] Found 203.0.113.1 - x"))
	f.Close()
	if rep3, _ := build(t, c, root, server); rep3 == rep || rep3.Found != 2 {
		t.Errorf("после дописывания отчёт не обновился: found=%d", rep3.Found)
	}
}

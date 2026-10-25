package scanner

import (
	"encoding/json"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// newDemoScanner создаёт сканер над демонстрационным деревом.
func newDemoScanner(t *testing.T) (*Scanner, *fakeproc.Tree, string) {
	t.Helper()
	tree := fakeproc.Demo(time.Now())
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hist, _ := history.Open(history.Options{CPUThreshold: 80, MemThreshold: 50})
	cfg := detect.DefaultConfig()
	cfg.CPUSustainScan = 2
	sc := New(Options{FS: fakeproc.NewFS(procRoot, hostRoot), Detect: cfg, History: hist, Interval: time.Second,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Hostname: "test"})
	return sc, tree, procRoot
}

func byPID(snap *model.Snapshot, pid int) *model.Process {
	for _, p := range snap.Processes {
		if p.PID == pid {
			return p
		}
	}
	return nil
}

// TestDemoPipeline прогоняет полный конвейер на демо-данных и проверяет
// оценки для каждого сценария.
func TestDemoPipeline(t *testing.T) {
	sc, _, _ := newDemoScanner(t)
	snap, err := sc.ScanOnce()
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]model.Risk{
		1: model.RiskInfo, 2: model.RiskInfo, 15: model.RiskInfo, 650: model.RiskInfo, 720: model.RiskInfo, 721: model.RiskInfo,
		800: model.RiskInfo, 1200: model.RiskInfo,
		860:  model.RiskLow,  // Redis на 0.0.0.0, закрыт ufw: признак доступности, не взлома
		1190: model.RiskInfo, // docker-proxy
		1300: model.RiskLow,  // обновлённый пакетом бинарник
		3101: model.RiskCritical, 3201: model.RiskCritical, 3202: model.RiskCritical, 3301: model.RiskCritical,
		3401: model.RiskMedium, // memfd: сильный признак одной категории
		3501: model.RiskHigh,
	}
	for pid, r := range want {
		p := byPID(snap, pid)
		if p == nil {
			t.Errorf("PID %d не найден", pid)
			continue
		}
		if p.Risk != r {
			var ids []string
			for _, f := range p.Findings {
				ids = append(ids, f.ID)
			}
			t.Errorf("PID %d %s: риск %s (%d), ожидался %s; признаки %v", pid, p.Name, p.Risk, p.Score, r, ids)
		}
	}

	// Сокеты связаны с процессами, включая контейнерное пространство имён.
	if p := byPID(snap, 3101); len(p.Sockets) != 1 || p.Sockets[0].RemotePort != 3333 {
		t.Errorf("сокеты майнера: %+v", p.Sockets)
	}
	if p := byPID(snap, 1200); len(p.Sockets) != 1 || p.Sockets[0].LocalPort != 3000 || p.Container == "" {
		t.Errorf("контейнер: %+v %q", p.Sockets, p.Container)
	}
	// Секреты замаскированы.
	if p := byPID(snap, 950); strings.Contains(p.Cmdline, "hunter2") || strings.Contains(p.Cmdline, "S3cretPassw0rd") {
		t.Errorf("секрет в cmdline: %s", p.Cmdline)
	}
	// Дерево.
	if p := byPID(snap, 721); len(p.Children) != 1 || p.Children[0] != 3201 {
		t.Errorf("потомки nginx worker: %v", p.Children)
	}
	// Системные проверки.
	var sys []string
	for _, f := range snap.System {
		sys = append(sys, f.ID+":"+f.Path)
	}
	joined := strings.Join(sys, " ")
	if !strings.Contains(joined, "ld_so_preload:/etc/ld.so.preload") || !strings.Contains(joined, "autostart_suspicious:/etc/cron.d/sysupdate") {
		t.Errorf("системные находки: %v", sys)
	}
	if strings.Contains(joined, "logrotate") && strings.Contains(joined, "autostart_suspicious:/etc/cron.d/logrotate") {
		t.Error("ложное срабатывание на logrotate")
	}
	if snap.Stats.Total != len(snap.Processes) || snap.Stats.ByRisk["CRITICAL"] != 4 {
		t.Errorf("статистика: %+v", snap.Stats)
	}
}

// TestHistoryAcrossScans: короткоживущий процесс даёт started/exited,
// длительная нагрузка майнера — признак cpu_sustained.
func TestHistoryAcrossScans(t *testing.T) {
	sc, tree, procRoot := newDemoScanner(t)
	anim := fakeproc.NewAnimator(tree, procRoot)
	sc.opt.BeforeScan = anim.Step
	for range 4 {
		if _, err := sc.ScanOnce(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond)
	}
	evs := sc.History().Events(0)
	seen := map[string]bool{}
	for _, e := range evs {
		seen[e.Type] = true
	}
	for _, want := range []string{model.EvBaseline, model.EvStarted, model.EvExited} {
		if !seen[want] {
			t.Errorf("нет события %s", want)
		}
	}
	snap := sc.Snapshot()
	miner := byPID(snap, 3101)
	found := false
	for _, f := range miner.Findings {
		if f.ID == "cpu_sustained" {
			found = true
		}
	}
	if !found || miner.CPUPercent < 100 {
		t.Errorf("майнер: CPU %.0f%%, cpu_sustained=%v", miner.CPUPercent, found)
	}
}

// TestScanBudget: тысячи процессов с длинными командными строками не
// раздувают снимок — после общего бюджета строки читаются по минимуму и
// получают признак cmdline_truncated.
func TestScanBudget(t *testing.T) {
	old := scanCmdlineBudget
	scanCmdlineBudget = 256 << 10 // 40 процессов по 30 КБ его заведомо превышают
	defer func() { scanCmdlineBudget = old }()
	tree := fakeproc.Demo(time.Now())
	const n = 40
	for i := range n {
		tree.Procs = append(tree.Procs, &fakeproc.Proc{PID: 10000 + i, PPID: 1, Comm: "sleep", UID: 1000, State: "S", StartTicks: 100,
			Args: []string{"sleep", strings.Repeat("9", 30<<10)}, Exe: "/usr/bin/sleep", Cwd: "/"})
	}
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hist, _ := history.Open(history.Options{})
	sc := New(Options{FS: fakeproc.NewFS(procRoot, hostRoot), Detect: detect.DefaultConfig(), History: hist, Interval: time.Second,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	snap, err := sc.ScanOnce()
	if err != nil {
		t.Fatal(err)
	}
	total, truncated, flagged := 0, 0, 0
	for _, p := range snap.Processes {
		total += len(p.Cmdline)
		if p.CmdlineTruncated {
			truncated++
		}
		for _, f := range p.Findings {
			if f.ID == "cmdline_truncated" {
				flagged++
			}
		}
	}
	if limit := scanCmdlineBudget + n*minCmdline + 64<<10; total > limit {
		t.Errorf("командные строки в снимке: %d байт, лимит %d", total, limit)
	}
	if truncated < n/4 || flagged != truncated {
		t.Errorf("обрезано %d, признаков %d", truncated, flagged)
	}
}

// TestEnglishTexts: все тексты снимка и истории (признаки, доказательства,
// объяснения, рекомендации, события, предупреждения) на английском не
// содержат русских слов — так ловятся строки, не прошедшие через каталог.
func TestEnglishTexts(t *testing.T) {
	sc, _, _ := newDemoScanner(t)
	var snap *model.Snapshot
	for range 3 { // несколько сканирований: длительная нагрузка и события
		var err error
		if snap, err = sc.ScanOnce(); err != nil {
			t.Fatal(err)
		}
	}
	v, err := i18n.RenderJSON(map[string]any{"snap": snap, "events": sc.History().Events(0)}, i18n.EN)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	if i := strings.IndexFunc(string(b), func(r rune) bool { return r >= 0x400 && r <= 0x4FF }); i >= 0 {
		t.Errorf("русский текст в английском выводе: …%s…", string(b)[max(0, i-200):min(len(b), i+200)])
	}
	if !strings.Contains(string(b), "Executable in a temporary directory") {
		t.Error("в выводе нет переведённых признаков")
	}
}

// TestDemoExposure: поверхность атаки на демо-данных — Redis за ufw,
// MongoDB-контейнер в обход ufw, порт приложения через docker-proxy.
func TestDemoExposure(t *testing.T) {
	sc, _, _ := newDemoScanner(t)
	snap, err := sc.ScanOnce()
	if err != nil {
		t.Fatal(err)
	}
	rep := snap.Exposure
	if rep == nil || rep.Firewall.UFW != "active" || len(rep.Bindings) != 2 {
		t.Fatalf("отчёт: %+v", rep)
	}
	find := func(port int, scope string) *model.Exposure {
		for i := range rep.Entries {
			if e := &rep.Entries[i]; e.Port == port && e.Scope == scope {
				return e
			}
		}
		return nil
	}
	if e := find(27017, model.ScopePublic); e == nil || e.Risk != model.RiskCritical || e.Firewall != model.FwBypassed || e.Container != "db" {
		t.Errorf("mongo: %+v", e)
	}
	if e := find(6379, model.ScopePublic); e == nil || e.Risk != model.RiskLow || e.Firewall != model.FwFiltered || e.PID != 860 {
		t.Errorf("redis: %+v", e)
	}
	if e := find(3000, model.ScopePublic); e == nil || e.PID != 1190 || e.Docker == nil || e.Docker.ContainerName != "webapp" || e.Risk != model.RiskHigh || e.FindingID != "" {
		t.Errorf("docker-proxy: %+v", e)
	}
	if e := find(3000, model.ScopeNetNS); e == nil || e.PID != 1200 {
		t.Errorf("приложение в контейнере: %+v", e)
	}
	if e := find(6380, model.ScopePublic); e != nil {
		t.Errorf("порт остановленного контейнера: %+v", e)
	}
	// Опасные: MongoDB (CRITICAL), порт 3000 в обход ufw (HIGH), Redis за ufw (LOW).
	if snap.Stats.PublicPorts != 7 || snap.Stats.DangerousPorts != 3 {
		t.Errorf("статистика: %+v", snap.Stats)
	}
	sys := map[string]model.Risk{}
	for _, f := range snap.System {
		sys[f.ID+"|"+f.Path] = f.Risk
	}
	for k, want := range map[string]model.Risk{"exposed_database|27017/tcp": model.RiskCritical, "fw_docker_bypass|27017/tcp": model.RiskHigh,
		"fw_docker_bypass|3000/tcp": model.RiskHigh, "exposed_database|6379/tcp": model.RiskLow} {
		if sys[k] != want {
			t.Errorf("%s: %s, ожидалось %s", k, sys[k], want)
		}
	}
	// Секреты из окружения контейнера (config.v2.json) никуда не попадают.
	b, _ := json.Marshal(snap)
	if strings.Contains(string(b), "SECRET=demo") {
		t.Error("окружение контейнера попало в снимок")
	}
	// События истории: системные находки записаны один раз.
	n := 0
	for _, e := range sc.History().Events(1000) {
		if e.Type == model.EvSystem && strings.Contains(e.Details.String(), "27017/tcp") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("событий о 27017/tcp: %d", n)
	}
}

// TestScanNoLeaks: сканирования не оставляют горутин и не накапливают
// память — служба работает месяцами.
func TestScanNoLeaks(t *testing.T) {
	sc, _, _ := newDemoScanner(t)
	for range 5 { // прогрев: кеши, первые события истории
		if _, err := sc.ScanOnce(); err != nil {
			t.Fatal(err)
		}
	}
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	g0, h0 := runtime.NumGoroutine(), heap()
	for range 100 {
		if _, err := sc.ScanOnce(); err != nil {
			t.Fatal(err)
		}
	}
	// Горутины могут завершаться с задержкой — даём им время.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > g0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > g0 {
		t.Errorf("горутин было %d, стало %d", g0, g)
	}
	// Снимок демо-системы — сотни килобайт; рост на мегабайты означал бы
	// утечку (например, накопление ключей истории).
	if h := heap(); h > h0+4<<20 {
		t.Errorf("куча выросла с %d до %d байт", h0, h)
	}
}

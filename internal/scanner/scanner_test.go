package scanner

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
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
		1300: model.RiskLow, // обновлённый пакетом бинарник
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

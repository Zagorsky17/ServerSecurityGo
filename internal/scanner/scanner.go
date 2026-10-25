// Пакет scanner связывает сбор данных (procfs), анализ (detect) и
// историю (history): периодически делает снимок процессов и хранит
// последний результат для веб-интерфейса.
//
// Сканер только читает: он не завершает процессы, не удаляет файлы и не
// блокирует соединения.
package scanner

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/exposure"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fail2ban"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/redact"
)

// Options — параметры сканера.
type Options struct {
	FS       *procfs.FS
	Detect   detect.Config
	History  *history.Store
	Interval time.Duration
	Logger   *slog.Logger
	// BeforeScan вызывается перед каждым сканированием (демо-режим
	// использует его, чтобы «оживлять» поддельные процессы).
	BeforeScan func()
	// Hostname переопределяет имя хоста (для демо).
	Hostname string
	// Demo — данные поддельные: предупреждения о правах неактуальны.
	Demo bool
	// LogDays — за сколько дней разбирать журнал fail2ban
	// (SSG_AUTH_LOG_DAYS); 0 — fail2ban.DefaultDays.
	LogDays int
}

// Scanner — периодический сканер процессов.
type Scanner struct {
	opt    Options
	mu     sync.RWMutex
	snap   *model.Snapshot
	seq    atomic.Uint64
	rescan chan struct{}
	scanMu sync.Mutex // сканирования не должны пересекаться
	f2b    *fail2ban.Collector
}

// New создаёт сканер.
func New(opt Options) *Scanner {
	if opt.Interval <= 0 {
		opt.Interval = 30 * time.Second
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	opt.Detect.ScanInterval = opt.Interval
	return &Scanner{opt: opt, rescan: make(chan struct{}, 1), f2b: fail2ban.NewCollector()}
}

// Snapshot возвращает последний снимок (nil до первого сканирования).
func (s *Scanner) Snapshot() *model.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// History возвращает хранилище истории.
func (s *Scanner) History() *history.Store { return s.opt.History }

// Interval возвращает период сканирования.
func (s *Scanner) Interval() time.Duration { return s.opt.Interval }

// Rescan просит выполнить внеочередное сканирование (не блокирует).
func (s *Scanner) Rescan() {
	select {
	case s.rescan <- struct{}{}:
	default:
	}
}

// Run выполняет сканирование сразу и затем по таймеру до отмены ctx.
func (s *Scanner) Run(ctx context.Context) {
	t := time.NewTicker(s.opt.Interval)
	defer t.Stop()
	for {
		if _, err := s.ScanOnce(); err != nil {
			s.opt.Logger.Error(i18n.S("log.scan_error"), "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.rescan:
		}
	}
}

// ScanOnce выполняет одно полное сканирование.
func (s *Scanner) ScanOnce() (*model.Snapshot, error) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.opt.BeforeScan != nil {
		s.opt.BeforeScan()
	}
	start := time.Now()
	snap, err := s.collect(start)
	if err != nil {
		return nil, err
	}

	hist := s.opt.History
	hist.Observe(start, snap.Processes)
	// Поверхность атаки оценивается до анализа процессов: правило
	// exposure берёт из неё опасные публичные порты.
	snap.Exposure = exposure.Build(exposure.Input{Procs: snap.Processes, Sockets: snap.Sockets, Addrs: s.opt.FS.LocalAddrs(),
		HostRoot: s.opt.FS.HostRoot, Allowed: s.opt.Detect.Allowed})
	snap.Warnings = append(snap.Warnings, snap.Exposure.Warnings...)
	ctx := &detect.Context{Cfg: s.opt.Detect, ByPID: pidMap(snap.Processes), Counters: hist.Counters, Now: start, Exposed: exposedByInode(snap.Exposure)}
	detect.Analyze(snap.Processes, ctx)
	snap.System = append(detect.SystemChecks(s.opt.FS.HostRoot, start, s.opt.Detect), exposure.SystemFindings(snap.Exposure)...)
	// fail2ban: журнал разбирается заново только в новой части, поэтому
	// каждое сканирование обходится в несколько stat.
	var f2bFindings []model.SystemFinding
	snap.Fail2ban, f2bFindings = s.f2b.Build(fail2ban.Input{HostRoot: s.opt.FS.HostRoot, Procs: snap.Processes, Exposure: snap.Exposure,
		Now: start, Days: s.opt.LogDays, Allowed: s.opt.Detect.Allowed})
	snap.System = append(snap.System, f2bFindings...)
	events := hist.Record(start, snap.Processes, snap.System)

	snap.Stats = stats(snap)
	snap.Duration = time.Since(start)
	snap.Seq = s.seq.Add(1)

	for _, e := range events {
		// В журнал пишем только факт и уровень, без командной строки.
		if (e.Type == model.EvStarted || e.Type == model.EvRiskUp || e.Type == model.EvSystem) && e.Risk >= model.RiskHigh {
			s.opt.Logger.Warn(i18n.S("log.high_risk"), "type", e.Type, "pid", e.PID, "name", e.Name, "risk", e.Risk.String(), "key", e.Key)
		}
	}
	s.opt.Logger.Debug(i18n.S("log.scan_done"), "processes", len(snap.Processes), "duration", snap.Duration.Round(time.Millisecond).String(), "events", len(events))

	s.mu.Lock()
	s.snap = snap
	s.mu.Unlock()
	return snap, nil
}

// exposedByInode — опасные публичные порты по inode сокета (для правила
// exposure). Указатели ссылаются на элементы rep.Entries, которые после
// построения отчёта не меняются.
func exposedByInode(rep *model.ExposureReport) map[uint64]*model.Exposure {
	m := map[uint64]*model.Exposure{}
	for i := range rep.Entries {
		if e := &rep.Entries[i]; e.Inode != 0 && e.FindingID != "" {
			m[e.Inode] = e
		}
	}
	return m
}

func pidMap(procs []*model.Process) map[int]*model.Process {
	m := make(map[int]*model.Process, len(procs))
	for _, p := range procs {
		m[p.PID] = p
	}
	return m
}

// Бюджет одного сканирования на данные, которые задают сами процессы.
// Лимиты одного процесса (procfs.Limits) не спасают от тысяч процессов:
// когда общий бюджет исчерпан, остальные читаются с минимальными
// лимитами. Обрезка командной строки видна как признак cmdline_truncated.
// Переменные, а не константы — чтобы тест мог уменьшить бюджет.
var (
	// Обычному серверу хватает десятков КБ; 2 МБ — запас для Java и
	// контейнеров. Правила и маскирование секретов проходят по строке
	// регулярными выражениями, и бюджет ограничивает ещё и время
	// сканирования (≈1 с на 2 МБ).
	scanCmdlineBudget = 2 << 20 // байт командных строк на сканирование
	minCmdline        = 512     // столько читается и после исчерпания бюджета
	scanFilesBudget   = 50_000  // записей Process.Files на сканирование
)

// collect читает все процессы и сокеты.
func (s *Scanner) collect(now time.Time) (*model.Snapshot, error) {
	fs := s.opt.FS
	pids, err := fs.PIDs()
	if err != nil {
		return nil, i18n.Errorf("err.read_path", fs.Root, err)
	}
	boot, err := fs.BootTime()
	if err != nil {
		s.opt.Logger.Warn(i18n.S("log.boot_time"), "err", err)
	}
	users := fs.Users()
	memTotal := fs.MemTotal()

	snap := &model.Snapshot{Time: now, ByKey: map[string]*model.Process{}}
	snap.Host = s.hostInfo(boot, memTotal)

	raws := make([]*procfs.Raw, 0, len(pids))
	readErrors := 0
	cmdBudget, filesBudget := scanCmdlineBudget, scanFilesBudget
	for _, pid := range pids {
		lim := procfs.Limits{Cmdline: min(fs.MaxCmdline, max(cmdBudget, minCmdline)), Files: min(fs.MaxFiles, filesBudget)}
		if fs.MaxCmdline <= 0 {
			lim.Cmdline = min(procfs.DefaultMaxCmdline, max(cmdBudget, minCmdline))
		}
		raw, err := fs.ReadProcessLimits(pid, boot, lim)
		if err != nil {
			if !errors.Is(err, procfs.ErrGone) {
				readErrors++
			}
			continue
		}
		p := raw.Proc
		for _, a := range raw.RawArgs {
			cmdBudget -= len(a) + 1
		}
		filesBudget -= len(p.Files)
		if name, ok := users[p.UID]; ok {
			p.User = name
		} else {
			p.User = strconv.Itoa(p.UID)
		}
		// Маскируем секреты сразу и отбрасываем исходные аргументы. Затереть
		// их байты в памяти Go не позволяет (строки неизменяемы, сборщик
		// мусора их не обнуляет): маскирование защищает интерфейс, историю
		// и журналы, но не память процесса. Поэтому в юните LimitCORE=0 —
		// при падении службы дамп памяти с секретами не создаётся.
		p.Args = redact.Args(raw.RawArgs)
		p.Cmdline = redact.Join(p.Args)
		clear(raw.RawArgs)
		raw.RawArgs = nil
		if p.Args == nil {
			p.Args = []string{}
		}
		if memTotal > 0 {
			p.MemPercent = float64(p.RSSBytes) / float64(memTotal) * 100
		}
		// Старые ядра без PF_KTHREAD в выводе: потомки kthreadd (PID 2)
		// без exe и cmdline — потоки ядра.
		if !p.Kernel && p.PPID == 2 && p.Exe == "" && len(p.Args) == 0 {
			p.Kernel = true
		}
		raws = append(raws, raw)
	}

	procs := make([]*model.Process, len(raws))
	byPID := make(map[int]*model.Process, len(raws))
	for i, r := range raws {
		procs[i] = r.Proc
		byPID[r.Proc.PID] = r.Proc
	}

	// Дерево: список потомков.
	for _, p := range procs {
		p.Children = []int{}
	}
	for _, p := range procs {
		if par := byPID[p.PPID]; par != nil && p.PPID != p.PID {
			par.Children = append(par.Children, p.PID)
		}
	}

	// Пространства имён: сравниваем с PID 1 (init хоста или контейнера,
	// в котором работает сканер).
	if init := byPID[1]; init != nil {
		for _, p := range procs {
			for _, n := range []string{"pid", "net", "mnt", "user"} {
				if a, b := p.Namespaces[n], init.Namespaces[n]; a != "" && b != "" && a != b {
					p.ForeignNS = append(p.ForeignNS, n)
				}
			}
		}
	}

	snap.Sockets = s.attachSockets(raws, byPID)
	snap.Processes = procs
	for _, p := range procs {
		snap.ByKey[p.Key] = p
	}
	snap.Warnings = s.warnings(snap, readErrors)
	return snap, nil
}

// attachSockets читает таблицы сокетов каждого сетевого пространства
// имён и связывает сокеты с процессами по inode из /proc/PID/fd.
func (s *Scanner) attachSockets(raws []*procfs.Raw, byPID map[int]*model.Process) []model.Socket {
	fs := s.opt.FS
	nsPID := map[string]int{}
	for _, r := range raws {
		ns := r.Proc.Namespaces["net"]
		if _, ok := nsPID[ns]; !ok && ns != "" {
			nsPID[ns] = r.Proc.PID
		}
	}
	// Inode сокетов уникальны в пределах системы, поэтому одна карта на
	// все пространства имён.
	byInode := map[uint64]model.Socket{}
	var unowned []model.Socket
	readTables := func(pid int, ns string) {
		for _, sk := range fs.ReadNetTables(pid, ns) {
			if sk.Inode == 0 {
				// TIME_WAIT и т. п.: у сокета больше нет владельца.
				if sk.Proto != "unix" {
					unowned = append(unowned, sk)
				}
				continue
			}
			if _, dup := byInode[sk.Inode]; !dup {
				byInode[sk.Inode] = sk
			}
		}
	}
	if len(nsPID) == 0 {
		readTables(0, "")
	}
	nsList := make([]string, 0, len(nsPID))
	for ns := range nsPID {
		nsList = append(nsList, ns)
	}
	sort.Strings(nsList)
	for _, ns := range nsList {
		readTables(nsPID[ns], ns)
	}

	owned := map[uint64]bool{}
	var all []model.Socket
	for _, r := range raws {
		p := r.Proc
		inodes := make([]uint64, 0, len(r.SocketInodes))
		for ino := range r.SocketInodes {
			inodes = append(inodes, ino)
		}
		sort.Slice(inodes, func(i, j int) bool { return inodes[i] < inodes[j] })
		for _, ino := range inodes {
			sk, ok := byInode[ino]
			if !ok {
				continue
			}
			sk.PID, sk.ProcKey, sk.ProcName, sk.User = p.PID, p.Key, p.Name, p.User
			p.Sockets = append(p.Sockets, sk)
			if sk.Proto != "unix" && !owned[ino] {
				owned[ino] = true
				all = append(all, sk)
			}
		}
	}
	// Сокеты без найденного владельца (нет прав на fd или сокет ядра).
	for ino, sk := range byInode {
		if !owned[ino] && sk.Proto != "unix" {
			all = append(all, sk)
		}
	}
	all = append(all, unowned...)
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].State != all[j].State {
			return all[i].State == "LISTEN"
		}
		if all[i].LocalPort != all[j].LocalPort {
			return all[i].LocalPort < all[j].LocalPort
		}
		return all[i].PID < all[j].PID
	})
	return all
}

func (s *Scanner) hostInfo(boot time.Time, memTotal uint64) model.HostInfo {
	fs := s.opt.FS
	h := model.HostInfo{BootTime: boot, IsRoot: os.Geteuid() == 0, MemTotal: memTotal, Kernel: fs.KernelRelease()}
	h.Hostname = s.opt.Hostname
	if h.Hostname == "" {
		h.Hostname, _ = os.Hostname()
	}
	if data, err := os.ReadFile(fs.HostPath("etc/os-release")); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				h.OS = strings.Trim(v, `"`)
			}
		}
	}
	if _, err := os.Stat(fs.HostPath(".dockerenv")); err == nil {
		h.InContainer = true
	}
	if data, err := os.ReadFile(fs.Root + "/1/cgroup"); err == nil {
		if rt, _ := procfs.DetectContainer(string(data)); rt != "" {
			h.InContainer = true
		}
	}
	return h
}

func (s *Scanner) warnings(snap *model.Snapshot, readErrors int) []i18n.Msg {
	var w []i18n.Msg
	if !snap.Host.IsRoot && !s.opt.Demo {
		w = append(w, i18n.T("warn.not_root"))
	}
	if snap.Host.InContainer {
		w = append(w, i18n.T("warn.in_container"))
	}
	restricted := 0
	for _, p := range snap.Processes {
		if len(p.Access) > 0 {
			restricted++
		}
	}
	if restricted > 0 {
		w = append(w, i18n.T("warn.restricted", restricted))
	}
	if readErrors > 0 {
		w = append(w, i18n.T("warn.read_errors", readErrors))
	}
	return w
}

func stats(snap *model.Snapshot) model.Stats {
	st := model.Stats{Total: len(snap.Processes), ByRisk: map[string]int{}, Sockets: len(snap.Sockets)}
	for _, r := range []model.Risk{model.RiskInfo, model.RiskLow, model.RiskMedium, model.RiskHigh, model.RiskCritical} {
		st.ByRisk[r.String()] = 0
	}
	st.PublicPorts, st.DangerousPorts = exposure.Stats(snap.Exposure)
	for _, p := range snap.Processes {
		if p.Kernel {
			st.Kernel++
		}
		if len(p.Access) > 0 {
			st.Restricted++
		}
		st.ByRisk[p.Risk.String()]++
	}
	return st
}

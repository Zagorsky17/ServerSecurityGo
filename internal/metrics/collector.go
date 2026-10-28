package metrics

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// Значения по умолчанию (SSG_METRICS_*, SSG_STEAL_THRESHOLD,
// SSG_DISK_FULL_THRESHOLD).
const (
	DefaultInterval  = 5 * time.Second
	DefaultRetention = 30 * 24 * time.Hour
	DefaultSteal     = 10.0
	DefaultDiskFull  = 90.0
)

// stateFileName — агрегаты между перезапусками службы. Сырые
// пятисекундные точки не сохраняются: они нужны только «прямо сейчас».
const stateFileName = "metrics.json"

// maxStateFile — предел размера metrics.json при чтении.
const maxStateFile = 64 << 20

// saveEvery — как часто агрегаты пишутся на диск.
const saveEvery = 5 * time.Minute

// Сколько условие должно держаться, чтобы появился признак: один
// всплеск — не повод для тревоги.
const (
	holdSteal  = 10 * time.Minute
	holdLoad   = 15 * time.Minute
	holdMemory = time.Minute
	// oomWindow — сколько признак oom_recent виден после последнего
	// убитого процесса.
	oomWindow = time.Hour
	// swapGrowth — рост занятого swap за swapWindow, с которого он
	// считается признаком нехватки памяти.
	swapGrowth = 64.0 // МБ
	swapWindow = 10 * time.Minute
	// psiMemory — порог давления памяти (some avg60), %.
	psiMemory = 10.0
)

// Options — параметры сборщика.
type Options struct {
	// ProcRoot, HostRoot — корни /proc и хоста (SSG_PROC_ROOT,
	// SSG_HOST_ROOT); пути разделов измеряются относительно HostRoot.
	ProcRoot string
	HostRoot string
	// Interval — период замера (SSG_METRICS_INTERVAL).
	Interval time.Duration
	// Retention — сколько хранить 15-минутные агрегаты
	// (SSG_METRICS_RETENTION).
	Retention time.Duration
	// StateDir — каталог для metrics.json; "" — только в памяти (демо,
	// терминальный интерфейс без службы).
	StateDir string
	// StealThreshold, DiskFullThreshold — пороги признаков steal_high и
	// disk_almost_full, %.
	StealThreshold    float64
	DiskFullThreshold float64
	// DiskUsage подменяет statfs (демо и тесты): nil — настоящий statfs.
	DiskUsage func(path string) (Usage, error)
	// BeforeCollect вызывается перед каждым замером: демо этим
	// «оживляет» поддельные счётчики /proc.
	BeforeCollect func()
	// FastHolds — признаки появляются через два замера вместо 10–15
	// минут (только демо: иначе их не увидеть за время показа).
	FastHolds bool
	Logger    *slog.Logger
}

// Collector снимает метрики и хранит ряды в памяти.
type Collector struct {
	opt      Options
	capMonth int

	mu       sync.RWMutex
	last     *Sample
	prev     raw
	series   map[string]*metricSeries
	findings []model.SystemFinding
	holds    map[string]time.Time
	oomSeen  uint64
	oomAt    time.Time
	saved    time.Time
	dirty    bool
}

// New создаёт сборщик и загружает сохранённые агрегаты.
func New(opt Options) *Collector {
	if opt.ProcRoot == "" {
		opt.ProcRoot = "/proc"
	}
	if opt.HostRoot == "" {
		opt.HostRoot = "/"
	}
	if opt.Interval <= 0 {
		opt.Interval = DefaultInterval
	}
	if opt.Retention <= 0 {
		opt.Retention = DefaultRetention
	}
	if opt.StealThreshold <= 0 {
		opt.StealThreshold = DefaultSteal
	}
	if opt.DiskFullThreshold <= 0 {
		opt.DiskFullThreshold = DefaultDiskFull
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	c := &Collector{opt: opt, series: map[string]*metricSeries{}, holds: map[string]time.Time{}}
	c.capMonth = max(int(opt.Retention/stepMin15), 1)
	c.load()
	return c
}

// Interval — период замера.
func (c *Collector) Interval() time.Duration { return c.opt.Interval }

// Run снимает метрики сразу и затем по интервалу до отмены ctx; при
// остановке агрегаты сохраняются.
func (c *Collector) Run(ctx context.Context) {
	if _, err := c.Collect(time.Now()); err != nil {
		c.opt.Logger.Warn(i18n.S("log.metrics_error"), "err", err)
	}
	t := time.NewTicker(c.opt.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Save()
			return
		case now := <-t.C:
			if _, err := c.Collect(now); err != nil {
				c.opt.Logger.Debug(i18n.S("log.metrics_error"), "err", err)
			}
			if now.Sub(c.savedAt()) >= saveEvery {
				c.Save()
			}
		}
	}
}

// Collect делает один замер и обновляет ряды и признаки.
func (c *Collector) Collect(now time.Time) (*Sample, error) {
	if c.opt.BeforeCollect != nil {
		c.opt.BeforeCollect()
	}
	r, err := c.readRaw(now)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sample(r)
	c.last = s
	c.prev = r
	for k, v := range s.values() {
		ms := c.series[k]
		if ms == nil {
			ms = newMetricSeries(c.capMonth)
			c.series[k] = ms
		}
		ms.add(now, v)
	}
	c.dirty = true
	c.findings = c.check(s)
	return s, nil
}

// sample считает проценты и скорости по разнице с прошлым замером.
// Первый замер сравнивать не с чем: тогда проценты считаются за всё
// время с загрузки (Average), а скорости — по uptime.
func (c *Collector) sample(r raw) *Sample {
	prev, dt := c.prev, 0.0
	s := &Sample{Time: r.time, NumCPU: len(r.cores), UptimeSec: r.uptime}
	if prev.time.IsZero() {
		s.Average = true
		dt = r.uptime
		s.CPU = r.cpu.percent()
		for _, core := range r.cores {
			s.Cores = append(s.Cores, core.percent())
		}
	} else {
		dt = r.time.Sub(prev.time).Seconds()
		s.CPU = r.cpu.sub(prev.cpu).percent()
		for i, core := range r.cores {
			if i < len(prev.cores) {
				s.Cores = append(s.Cores, core.sub(prev.cores[i]).percent())
			} else {
				s.Cores = append(s.Cores, core.percent())
			}
		}
	}
	// Диски и интерфейсы сопоставляются по имени: устройство могло
	// появиться или исчезнуть между замерами.
	prevDisks := map[string]DiskCounters{}
	for _, d := range prev.disks {
		prevDisks[d.Name] = d
	}
	for _, d := range r.disks {
		p := prevDisks[d.Name]
		// Сектор в diskstats всегда 512 байт, независимо от размера
		// блока файловой системы.
		rd := DiskRate{Name: d.Name,
			ReadMBs:  rate(d.ReadSectors, p.ReadSectors, dt) * 512 / (1 << 20),
			WriteMBs: rate(d.WriteSectors, p.WriteSectors, dt) * 512 / (1 << 20),
			BusyPct:  min(rate(d.IOTicks, p.IOTicks, dt)/10, 100), // io_ticks в мс: мс/с ÷ 10 = %
		}
		s.Disks = append(s.Disks, rd)
	}
	prevNets := map[string]NetCounters{}
	for _, n := range prev.nets {
		prevNets[n.Name] = n
	}
	for _, n := range r.nets {
		p := prevNets[n.Name]
		s.Nets = append(s.Nets, NetRate{Name: n.Name,
			RxMBs: rate(n.RxBytes, p.RxBytes, dt) / (1 << 20), TxMBs: rate(n.TxBytes, p.TxBytes, dt) / (1 << 20),
			RxPPS: rate(n.RxPackets, p.RxPackets, dt), TxPPS: rate(n.TxPackets, p.TxPackets, dt),
			RxDrops: rate(n.RxDrop, p.RxDrop, dt), RxErrors: rate(n.RxErrs, p.RxErrs, dt)})
	}
	if data, err := readProc(c.procPath("meminfo")); err == nil {
		m := ParseMeminfo(data)
		s.Mem = MemUsage{Total: m.Total * 1024, Available: m.Available * 1024, Cached: m.Cached * 1024,
			SwapTotal: m.SwapTotal * 1024}
		if m.Total >= m.Available {
			s.Mem.Used = (m.Total - m.Available) * 1024
		}
		s.Mem.Percent = pct(s.Mem.Used, s.Mem.Total)
		if m.SwapTotal >= m.SwapFree {
			s.Mem.SwapUsed = (m.SwapTotal - m.SwapFree) * 1024
		}
		s.Mem.SwapPct = pct(s.Mem.SwapUsed, s.Mem.SwapTotal)
	}
	if data, err := readProc(c.procPath("loadavg")); err == nil {
		s.Load, _ = ParseLoadAvg(data)
	}
	if data, err := readProc(c.procPath("vmstat")); err == nil {
		s.OOMKills, _ = ParseKeyValue(data, "oom_kill")
	}
	s.PSI = c.readPSI()
	s.Parts = c.partitions()
	s.VM = c.isVM(r.cpu)
	s.Container = c.inContainer()
	return s
}

// need — сколько условие должно держаться. В демо — два замера.
func (c *Collector) need(d time.Duration) time.Duration {
	if c.opt.FastHolds {
		return 2 * c.opt.Interval
	}
	return d
}

// hold — условие держится не меньше need. Как только условие пропадает,
// отсчёт начинается заново.
func (c *Collector) hold(id string, active bool, now time.Time, need time.Duration) bool {
	if !active {
		delete(c.holds, id)
		return false
	}
	since, ok := c.holds[id]
	if !ok {
		since = now
		c.holds[id] = since
	}
	return now.Sub(since) >= need
}

// check пересчитывает системные признаки по метрикам (раздел 15.5
// плана). Вызывается под c.mu.
func (c *Collector) check(s *Sample) []model.SystemFinding {
	now := s.Time
	var out []model.SystemFinding
	add := func(id string, risk model.Risk, path string, title, rec i18n.Msg, ev ...i18n.Msg) {
		out = append(out, model.SystemFinding{Finding: model.Finding{ID: id, Title: title, Category: model.CatInfo,
			Recommendation: rec, Evidence: ev}, Path: path, Risk: risk})
	}
	// steal считается только на виртуальной машине: на железе он всегда 0.
	steal := s.VM && s.CPU.Steal > c.opt.StealThreshold && !s.Average
	if c.hold("steal_high", steal, now, c.need(holdSteal)) {
		add("steal_high", model.RiskLow, "cpu.steal",
			i18n.T("rule.steal_high.title", round1(s.CPU.Steal)), i18n.T("rule.steal_high.rec"),
			i18n.T("ev.metrics_steal", round1(s.CPU.Steal), round1(c.opt.StealThreshold), int(holdSteal.Minutes())),
			i18n.T("ev.metrics_cpu_busy", round1(s.CPU.Busy)))
	}
	for _, p := range s.Parts {
		full, inodes := p.Percent > c.opt.DiskFullThreshold, p.InodePct > c.opt.DiskFullThreshold
		if !full && !inodes {
			continue
		}
		ev := []i18n.Msg{i18n.T("ev.metrics_disk", p.Point, round1(p.Percent), humanBytes(p.Free), p.Device)}
		if inodes {
			ev = append(ev, i18n.T("ev.metrics_inodes", round1(p.InodePct)))
		}
		add("disk_almost_full", model.RiskMedium, p.Point,
			i18n.T("rule.disk_almost_full.title", p.Point, round1(p.Percent)), i18n.T("rule.disk_almost_full.rec", p.Point), ev...)
	}
	loadHigh := s.NumCPU > 0 && s.Load.One > 2*float64(s.NumCPU)
	if c.hold("load_high", loadHigh, now, c.need(holdLoad)) {
		add("load_high", model.RiskInfo, "cpu.load",
			i18n.T("rule.load_high.title", round2(s.Load.One), s.NumCPU), i18n.T("rule.load_high.rec"),
			i18n.T("ev.metrics_load", round2(s.Load.One), round2(s.Load.Five), round2(s.Load.Fifteen), s.NumCPU),
			i18n.T("ev.metrics_cpu_busy", round1(s.CPU.Busy)))
	}
	swapGrew, grew := false, 0.0
	if ms := c.series[KeySwapUsed]; ms != nil && s.Mem.SwapUsed > 0 {
		if p, ok := ms.back(now, swapWindow); ok {
			grew = float64(s.Mem.SwapUsed)/(1<<20) - p.Avg
			swapGrew = grew >= swapGrowth
		}
	}
	psiMem := 0.0
	if s.PSI != nil {
		psiMem = s.PSI.Mem
	}
	if c.hold("memory_pressure", psiMem > psiMemory || swapGrew, now, c.need(holdMemory)) {
		ev := []i18n.Msg{i18n.T("ev.metrics_mem", round1(s.Mem.Percent), humanBytes(s.Mem.Available))}
		if psiMem > psiMemory {
			ev = append(ev, i18n.T("ev.metrics_psi", round1(psiMem)))
		}
		if swapGrew {
			ev = append(ev, i18n.T("ev.metrics_swap_growth", round1(grew), int(swapWindow.Minutes()), round1(s.Mem.SwapPct)))
		}
		add("memory_pressure", model.RiskInfo, "memory",
			i18n.T("rule.memory_pressure.title"), i18n.T("rule.memory_pressure.rec"), ev...)
	}
	// Счётчик oom_kill только растёт; первое чтение — отсчёт, а не
	// событие: процессы могли убиваться до запуска службы.
	if c.oomSeen == 0 && c.oomAt.IsZero() {
		c.oomSeen = s.OOMKills
	} else if s.OOMKills > c.oomSeen {
		c.oomSeen, c.oomAt = s.OOMKills, now
	}
	if !c.oomAt.IsZero() && now.Sub(c.oomAt) < oomWindow {
		add("oom_recent", model.RiskLow, "memory.oom",
			i18n.T("rule.oom_recent.title"), i18n.T("rule.oom_recent.rec"),
			i18n.T("ev.metrics_oom", c.oomSeen, c.oomAt.Local().Format("15:04:05")),
			i18n.T("ev.metrics_mem", round1(s.Mem.Percent), humanBytes(s.Mem.Available)))
	}
	return out
}

// Findings — системные признаки последнего замера.
func (c *Collector) Findings() []model.SystemFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]model.SystemFinding(nil), c.findings...)
}

// Sample возвращает последний замер (nil — ещё не было).
func (c *Collector) Sample() *Sample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.last
}

// View — ответ /api/metrics: текущие значения и ряды окна.
type View struct {
	Enabled     bool               `json:"enabled"`
	Ready       bool               `json:"ready"`
	Range       string             `json:"range"`
	StepSec     float64            `json:"stepSec"`
	IntervalSec float64            `json:"intervalSec"`
	RetentionH  float64            `json:"retentionH"`
	Now         *Sample            `json:"now,omitempty"`
	Series      map[string][]Point `json:"series"`
	VM          bool               `json:"vm"`
	Container   bool               `json:"container"`
	PSI         bool               `json:"psi"`
	// Alerts — ID сработавших признаков из метрик (для плашки в шапке).
	Alerts []string `json:"alerts"`
}

// View собирает представление для API и терминала.
func (c *Collector) View(rng string) View {
	rng = ValidRange(rng)
	c.mu.RLock()
	defer c.mu.RUnlock()
	v := View{Enabled: true, Range: rng, StepSec: StepSeconds(rng, c.opt.Interval), IntervalSec: c.opt.Interval.Seconds(),
		RetentionH: c.opt.Retention.Hours(), Now: c.last, Series: map[string][]Point{}, Alerts: []string{}}
	for k, ms := range c.series {
		v.Series[k] = ms.points(rng)
	}
	for _, f := range c.findings {
		v.Alerts = append(v.Alerts, f.ID)
	}
	sort.Strings(v.Alerts)
	if c.last != nil {
		v.Ready, v.VM, v.Container, v.PSI = true, c.last.VM, c.last.Container, c.last.PSI != nil
	}
	return v
}

// Brief — метрики для шапки и «Обзора»: текущие значения без рядов.
type Brief struct {
	Ready     bool      `json:"ready"`
	Time      time.Time `json:"time"`
	CPU       float64   `json:"cpu"`
	Steal     float64   `json:"steal"`
	Load1     float64   `json:"load1"`
	NumCPU    int       `json:"numCPU"`
	Mem       float64   `json:"mem"`
	Swap      float64   `json:"swap"`
	DiskPct   float64   `json:"diskPct"`
	DiskPoint string    `json:"diskPoint,omitempty"`
	// StealOver, DiskOver — значение выше порога (SSG_STEAL_THRESHOLD,
	// SSG_DISK_FULL_THRESHOLD). Пороги знает только сборщик, поэтому
	// интерфейсы не повторяют их у себя.
	StealOver bool    `json:"stealOver,omitempty"`
	DiskOver  bool    `json:"diskOver,omitempty"`
	DiskRead  float64 `json:"diskRead"`
	DiskWrite float64 `json:"diskWrite"`
	NetRx     float64 `json:"netRx"`
	NetTx     float64 `json:"netTx"`
	UptimeSec float64 `json:"uptimeSec"`
	VM        bool    `json:"vm"`
	Container bool    `json:"container"`
	Alerts    int     `json:"alerts"`
}

// Brief возвращает сводку (nil — замеров ещё нет).
func (c *Collector) Brief() *Brief {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.last
	if s == nil {
		return &Brief{}
	}
	b := &Brief{Ready: true, Time: s.Time, CPU: s.CPU.Busy, Steal: s.CPU.Steal, Load1: s.Load.One, NumCPU: s.NumCPU,
		Mem: s.Mem.Percent, Swap: s.Mem.SwapPct, UptimeSec: s.UptimeSec, VM: s.VM, Container: s.Container,
		Alerts: len(c.findings)}
	for _, d := range s.Disks {
		b.DiskRead += d.ReadMBs
		b.DiskWrite += d.WriteMBs
	}
	for _, n := range s.Nets {
		b.NetRx += n.RxMBs
		b.NetTx += n.TxMBs
	}
	for _, p := range s.Parts {
		if p.Percent > b.DiskPct {
			b.DiskPct, b.DiskPoint = p.Percent, p.Point
		}
	}
	b.StealOver = s.VM && !s.Average && s.CPU.Steal > c.opt.StealThreshold
	b.DiskOver = b.DiskPct > c.opt.DiskFullThreshold
	return b
}

// ---------------------------------------------------------------------
// Сохранение агрегатов между перезапусками
// ---------------------------------------------------------------------

type savedSeries struct {
	Min1  []Point `json:"min1"`
	Min15 []Point `json:"min15"`
}

type stateFile struct {
	Version int                    `json:"version"`
	Saved   time.Time              `json:"saved"`
	Series  map[string]savedSeries `json:"series"`
}

func (c *Collector) statePath() string { return filepath.Join(c.opt.StateDir, stateFileName) }

func (c *Collector) savedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.saved
}

// Save атомарно записывает агрегаты (1 мин и 15 мин). Сырые точки не
// сохраняются: после перезапуска они всё равно бесполезны.
func (c *Collector) Save() {
	if c.opt.StateDir == "" {
		return
	}
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	st := stateFile{Version: 1, Saved: time.Now(), Series: make(map[string]savedSeries, len(c.series))}
	for k, ms := range c.series {
		st.Series[k] = savedSeries{Min1: ms.min1.all(), Min15: ms.min15.all()}
	}
	c.saved, c.dirty = st.Saved, false
	c.mu.Unlock()

	data, err := json.Marshal(st)
	if err == nil {
		err = writeFileAtomic(c.statePath(), data)
	}
	if err != nil {
		c.opt.Logger.Warn(i18n.S("log.metrics_save"), "err", err)
	}
}

// writeFileAtomic пишет файл через временный и rename: прерванная
// запись не оставит обрезанный metrics.json.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metrics-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// load читает сохранённые агрегаты. Повреждённый файл не мешает
// запуску: он отодвигается в сторону, ряды начинаются заново.
func (c *Collector) load() {
	if c.opt.StateDir == "" {
		return
	}
	fi, err := os.Stat(c.statePath())
	if err != nil {
		return
	}
	if fi.Size() > maxStateFile {
		c.opt.Logger.Warn(i18n.S("log.metrics_state_bad"), "size", fi.Size())
		return
	}
	data, err := os.ReadFile(c.statePath())
	if err != nil {
		return
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil || st.Version != 1 {
		c.opt.Logger.Warn(i18n.S("log.metrics_state_bad"), "err", err)
		_ = os.Rename(c.statePath(), c.statePath()+".corrupt")
		return
	}
	cut := time.Now().Add(-c.opt.Retention)
	for k, ss := range st.Series {
		ms := newMetricSeries(c.capMonth)
		ms.min1.load(fresh(ss.Min1, cut))
		ms.min15.load(fresh(ss.Min15, cut))
		c.series[k] = ms
	}
	c.saved = st.Saved
}

// fresh отбрасывает точки старше cut (и точки из будущего: часы могли
// переставить).
func fresh(pts []Point, cut time.Time) []Point {
	out := make([]Point, 0, len(pts))
	limit := time.Now().Add(time.Hour)
	for _, p := range pts {
		if p.T.After(cut) && p.T.Before(limit) {
			out = append(out, p)
		}
	}
	return out
}

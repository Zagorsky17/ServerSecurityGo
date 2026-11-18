package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/investigate"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// baselineFile — базовая линия аудита в каталоге данных службы. В ней
// только имена пользователей, их UID, члены групп и SHA-256 файлов
// sudoers — без паролей и содержимого файлов.
const baselineFile = "audit-baseline.json"

// maxBaselineFile — предел размера файла базовой линии.
const maxBaselineFile = 16 << 20

// RunnerOptions — параметры фонового аудита службы.
type RunnerOptions struct {
	// Inventory возвращает неизменяемый отчёт; Updates уведомляет после публикации.
	Inventory        func() *model.FileInventory
	InventoryUpdates <-chan struct{}
	Events           func(int) []model.Event
	Snapshot         func() *model.Snapshot
	HostRoot         string
	// ProcRoot — корень /proc для параметров ядра (audit.Options.ProcRoot).
	ProcRoot string
	RootUID  int
	// Interval — период повторной проверки (SSG_AUDIT_INTERVAL).
	Interval time.Duration
	// StateDir — каталог для audit-baseline.json; "" — базовая линия только в
	// памяти (демо, терминальный интерфейс без службы).
	StateDir string
	// Record записывает изменения результатов в историю
	// (history.Store.RecordAudit) и возвращает события. nil — без истории.
	Record func(now time.Time, checks []model.AuditCheck) []model.Event
	Logger *slog.Logger
}

// Runner выполняет аудит при запуске, затем по интервалу и по запросу
// («Проверить сейчас»), а файловые проверки — по обновлению инвентаря. Проверки не
// выполняются параллельно.
type Runner struct {
	opt       RunnerOptions
	mu        sync.RWMutex
	report    *model.AuditReport
	runMu     sync.Mutex // один запуск в каждый момент
	base      Baseline   // под runMu
	running   atomic.Bool
	trigger   chan struct{}
	inventory *model.FileInventory // использованный неизменяемый отчёт, под runMu
}

// NewRunner создаёт исполнителя и загружает базовую линию из StateDir.
func NewRunner(opt RunnerOptions) *Runner {
	if opt.Interval <= 0 {
		opt.Interval = time.Hour
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	r := &Runner{opt: opt, trigger: make(chan struct{}, 1)}
	if opt.StateDir != "" {
		data, _, err := safefile.ReadRegular(filepath.Join(opt.StateDir, baselineFile), maxBaselineFile, false)
		if err == nil {
			var b Baseline
			if json.Unmarshal(data, &b) == nil {
				r.base = b
			} else {
				opt.Logger.Warn(i18n.S("log.audit_baseline_bad"))
			}
		}
	}
	return r
}

// Interval — период повторной проверки.
func (r *Runner) Interval() time.Duration { return r.opt.Interval }

// Report — результат последнего аудита (nil до первого).
func (r *Runner) Report() *model.AuditReport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.report
}

// Running — аудит выполняется прямо сейчас.
func (r *Runner) Running() bool { return r.running.Load() }

// RunNow просит выполнить аудит вне очереди. false — проверка уже идёт
// (новая не запускается) или запрос уже ждёт выполнения.
func (r *Runner) RunNow() bool {
	if r.running.Load() {
		return false
	}
	select {
	case r.trigger <- struct{}{}:
		return true
	default:
		return false
	}
}

// Run выполняет полный аудит по таймеру/запросу, файловые проверки — по новому инвентарю.
func (r *Runner) Run(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if r.Report() == nil {
		r.RunOnce()
	}
	t := time.NewTicker(r.opt.Interval)
	defer t.Stop()
	updates := r.opt.InventoryUpdates
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ctx.Err() != nil {
				return
			}
			r.RunOnce()
		case <-r.trigger:
			if ctx.Err() != nil {
				return
			}
			r.RunOnce()
			t.Reset(r.opt.Interval)
		case _, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			if ctx.Err() != nil {
				return
			}
			r.refreshInventory()
		}
	}
}

// RunOnce выполняет аудит синхронно и публикует результат.
func (r *Runner) RunOnce() *model.AuditReport {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	r.running.Store(true)
	defer r.running.Store(false)

	start := time.Now()
	base := r.base
	opt := Options{HostRoot: r.opt.HostRoot, ProcRoot: r.opt.ProcRoot, RootUID: r.opt.RootUID, Baseline: &base}
	if r.opt.Snapshot != nil {
		if snap := r.opt.Snapshot(); snap != nil {
			opt.Inventory = snap.Inventory
			opt.Exposure = snap.Exposure
		}
	}
	if r.opt.Inventory != nil {
		opt.Inventory = r.opt.Inventory()
	}
	r.inventory = opt.Inventory
	checks, next := Run(opt)
	r.base = next
	r.saveBaseline()
	rep := &model.AuditReport{Time: start, Duration: time.Since(start), Checks: checks, InventorySource: inventorySource(opt.Inventory)}
	r.publish(rep, start)
	return rep
}

func (r *Runner) publish(rep *model.AuditReport, now time.Time) {
	rep.UpdatedAt = now
	checks := rep.Checks
	if r.opt.Record != nil {
		for _, e := range r.opt.Record(now, checks) {
			if e.Risk >= model.RiskHigh {
				r.opt.Logger.Warn(i18n.S("log.audit_failed"), "check", e.Name, "risk", e.Risk.String())
			}
		}
	}
	var events []model.Event
	if r.opt.Events != nil {
		events = r.opt.Events(2000)
	}
	investigate.AttachAudit(checks, events)
	pass, total := Summary(checks)
	r.opt.Logger.Debug(i18n.S("log.audit_done"), "pass", pass, "total", total, "duration", rep.Duration.Round(time.Millisecond).String())
	r.mu.Lock()
	r.report = rep
	r.mu.Unlock()
}

func inventorySource(inventory *model.FileInventory) *model.AuditInventorySource {
	source := &model.AuditInventorySource{Incomplete: true}
	if inventory != nil {
		source.Ready, source.Time, source.Incomplete = true, inventory.Time, inventory.Incomplete
	}
	return source
}

func (r *Runner) refreshInventory() {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	if r.opt.Inventory == nil {
		return
	}
	inventory := r.opt.Inventory()
	previous := r.Report()
	if inventory == nil || inventory == r.inventory || previous == nil {
		return
	}
	r.running.Store(true)
	defer r.running.Store(false)
	a := auditor{opt: Options{Inventory: inventory}}
	changed := a.inventoryChecks()
	rep := *previous
	rep.Checks = append([]model.AuditCheck(nil), previous.Checks...)
	for i, c := range rep.Checks {
		for _, replacement := range changed {
			if c.ID == replacement.ID {
				rep.Checks[i] = replacement
				break
			}
		}
	}
	rep.InventorySource = inventorySource(inventory)
	r.inventory = inventory
	// Истории нужен полный набор: отсутствующие проверки она считает удалёнными.
	r.publish(&rep, time.Now())
}

// saveBaseline атомарно записывает audit-baseline.json (права 0600).
func (r *Runner) saveBaseline() {
	if r.opt.StateDir == "" {
		return
	}
	data, err := json.Marshal(r.base)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(r.opt.StateDir, ".audit-*.json")
	if err != nil {
		r.opt.Logger.Warn(i18n.S("log.audit_save"), "err", err)
		return
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Chmod(0o600)
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, filepath.Join(r.opt.StateDir, baselineFile))
	}
	if werr != nil {
		_ = os.Remove(name)
		r.opt.Logger.Warn(i18n.S("log.audit_save"), "err", werr)
	}
}

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
	HostRoot string
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
// («Проверить сейчас»). Работает в одной горутине (Run); проверки не
// выполняются параллельно.
type Runner struct {
	opt     RunnerOptions
	mu      sync.RWMutex
	report  *model.AuditReport
	runMu   sync.Mutex // один запуск в каждый момент
	base    Baseline   // под runMu
	running atomic.Bool
	trigger chan struct{}
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

// Run выполняет аудит сразу, затем по таймеру и по RunNow до отмены ctx.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(r.opt.Interval)
	defer t.Stop()
	for {
		r.RunOnce()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.trigger:
			t.Reset(r.opt.Interval)
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
	checks, next := Run(Options{HostRoot: r.opt.HostRoot, RootUID: r.opt.RootUID, Baseline: &base})
	r.base = next
	r.saveBaseline()
	rep := &model.AuditReport{Time: start, Duration: time.Since(start), Checks: checks}
	if r.opt.Record != nil {
		for _, e := range r.opt.Record(start, checks) {
			if e.Risk >= model.RiskHigh {
				r.opt.Logger.Warn(i18n.S("log.audit_failed"), "check", e.Name, "risk", e.Risk.String())
			}
		}
	}
	pass, total := Summary(checks)
	r.opt.Logger.Debug(i18n.S("log.audit_done"), "pass", pass, "total", total, "duration", rep.Duration.Round(time.Millisecond).String())
	r.mu.Lock()
	r.report = rep
	r.mu.Unlock()
	return rep
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

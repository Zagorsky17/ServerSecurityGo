// Package rootkit сопоставляет независимые представления /proc и sysfs.
package rootkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type Options struct {
	ProcRoot, HostRoot, StateDir string
	ReadOnly                     bool
	Interval                     time.Duration
}
type moduleBaseline struct {
	Boot    string
	Modules map[string]bool
}
type Checker struct {
	opt                      Options
	checkMu, sweepMu         sync.Mutex
	mu                       sync.RWMutex
	base                     moduleBaseline
	baseErr                  error
	sweep                    []model.SystemFinding
	checked, total           int
	started, finished        time.Time
	running                  bool
	complete                 bool
	list                     func(string) (map[int]bool, error)
	confirmDelay, batchPause time.Duration
}

func New(opt Options) *Checker {
	if opt.Interval <= 0 {
		opt.Interval = 10 * time.Minute
	}
	c := &Checker{opt: opt, list: pidList, confirmDelay: 50 * time.Millisecond, batchPause: 100 * time.Millisecond}
	if opt.StateDir != "" {
		data, _, err := safefile.ReadRegular(filepath.Join(opt.StateDir, "rootkit-modules.json"), 1<<20, false)
		if err == nil {
			err = json.Unmarshal(data, &c.base)
			if err == nil && (c.base.Boot == "" || c.base.Modules == nil) {
				err = os.ErrInvalid
			}
		}
		if !errors.Is(err, os.ErrNotExist) {
			c.baseErr = err
		}
	}
	return c
}

func finding(id, path string, risk model.Risk, title, rec i18n.Msg, ev ...i18n.Msg) model.SystemFinding {
	return model.SystemFinding{Finding: model.Finding{ID: id, Title: title, Category: model.CatRootkit, Strong: risk == model.RiskCritical, Evidence: ev, Recommendation: rec}, Path: path, Risk: risk}
}
func unavailable(path string, err error) model.SystemFinding {
	return finding("rootkit_unavailable", path, model.RiskInfo, i18n.T("rule.rootkit_unavailable.title", path), i18n.T("rule.rootkit_unavailable.rec"), i18n.T("ev.verification_error", err))
}

func (c *Checker) Check(ctx context.Context) []model.SystemFinding {
	c.checkMu.Lock()
	defer c.checkMu.Unlock()
	var out []model.SystemFinding
	visible, err := c.list(c.opt.ProcRoot)
	if err == nil {
		var ids []int
		ids, err = candidates(c.opt.ProcRoot, visible)
		if err == nil {
			var f []model.SystemFinding
			f, err = confirmHidden(ctx, c.opt.ProcRoot, visible, ids, c.confirmDelay, c.list)
			out = append(out, f...)
		}
	}
	if err != nil {
		out = append(out, unavailable(c.opt.ProcRoot, err))
	}
	bootData, _, berr := safefile.ReadRegular(filepath.Join(c.opt.ProcRoot, "sys/kernel/random/boot_id"), 4096, false)
	boot := strings.TrimSpace(string(bootData))
	if berr == nil && !bootIDPattern.MatchString(boot) {
		berr = os.ErrInvalid
	}
	baseline := c.base.Modules
	if boot != c.base.Boot {
		baseline = nil
	}
	f, live, merr := moduleChecks(ctx, c.opt.ProcRoot, c.opt.HostRoot, baseline, c.confirmDelay)
	out = append(out, f...)
	if merr != nil {
		out = append(out, unavailable("/proc/modules, /sys/module", merr))
	}
	if c.baseErr != nil {
		out = append(out, unavailable("rootkit-modules.json", c.baseErr))
	} else if berr != nil {
		out = append(out, unavailable("/proc/sys/kernel/random/boot_id", berr))
	} else if merr == nil && baseline == nil {
		next := moduleBaseline{Boot: boot, Modules: live}
		var err error
		if c.opt.StateDir != "" && !c.opt.ReadOnly {
			err = safefile.WriteJSON(filepath.Join(c.opt.StateDir, "rootkit-modules.json"), next, 1<<20)
		}
		if err != nil {
			out = append(out, unavailable("rootkit-modules.json", err))
		} else {
			c.base = next
		}
	}
	c.mu.RLock()
	out = append(out, c.sweep...)
	out = append(out, c.sweepFinding(time.Now()))
	c.mu.RUnlock()
	return out
}

// sweepFinding вызывается под c.mu; таймер остановленной проверки заморожен.
func (c *Checker) sweepFinding(now time.Time) model.SystemFinding {
	title := i18n.T("rule.rootkit_sweep_pending.title")
	id := "rootkit_sweep_pending"
	if !c.started.IsZero() {
		end := now
		if !c.running {
			end = c.finished
		}
		elapsed := max(end.Sub(c.started), 0)
		percent := min(100, c.checked*100/max(c.total-1, 1))
		switch {
		case c.complete:
			id = "rootkit_sweep_complete"
			title = i18n.T("rule.rootkit_sweep_complete.title", sweepDuration(elapsed))
		case !c.running:
			title = i18n.T("rule.rootkit_sweep_stopped.title", sweepDuration(elapsed), percent)
		default:
			percent = min(percent, 99)
			title = i18n.T("rule.rootkit_sweep_estimate.title", sweepDuration(elapsed), percent)
			if c.checked > 0 && elapsed >= time.Second && c.checked < c.total-1 {
				remaining := math.Ceil(elapsed.Seconds() * float64(c.total-1-c.checked) / float64(c.checked))
				if remaining < float64((1<<63-1)/int64(time.Second)) {
					title = i18n.T("rule.rootkit_sweep_running.title", sweepDuration(elapsed), sweepDuration(time.Duration(remaining)*time.Second), percent)
				}
			}
		}
	}
	rec := i18n.T("rule.rootkit_sweep_pending.rec")
	evidence := i18n.T("ev.rootkit_sweep", c.checked, c.total)
	if c.complete {
		rec = i18n.T("rule.rootkit_sweep_complete.rec")
		evidence = i18n.T("ev.rootkit_completed", c.checked, c.finished.UTC().Format(time.RFC3339))
	}
	return finding(id, "/proc", model.RiskInfo, title, rec, evidence)
}

func sweepDuration(d time.Duration) string {
	seconds := int64(d / time.Second)
	return fmt.Sprintf("%02d:%02d:%02d", seconds/3600, seconds/60%60, seconds%60)
}

// Sweep проходит всё пространство PID порциями, не блокируя основной сканер.
func (c *Checker) Sweep(ctx context.Context) (result error) {
	c.sweepMu.Lock()
	defer c.sweepMu.Unlock()
	c.mu.Lock()
	c.started, c.finished = time.Now(), time.Time{}
	c.running, c.complete = true, false
	c.checked, c.total = 0, 0
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.running, c.finished = false, time.Now()
		if result != nil {
			c.complete = false
			c.sweep = []model.SystemFinding{unavailable(c.opt.ProcRoot, result)}
		}
	}()
	data, _, err := safefile.ReadRegular(filepath.Join(c.opt.ProcRoot, "sys/kernel/pid_max"), 4096, false)
	maxPID, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if err == nil {
		err = parseErr
	}
	if err == nil && (maxPID < 1 || maxPID > 4_194_304) {
		err = os.ErrInvalid
	}
	c.mu.Lock()
	c.complete = false
	c.checked = 0
	c.total = maxPID
	c.mu.Unlock()
	if err != nil {
		c.mu.Lock()
		c.sweep = []model.SystemFinding{unavailable("/proc/sys/kernel/pid_max", err)}
		c.mu.Unlock()
		return err
	}
	var findings []model.SystemFinding
	var readErr error
	for start := 1; start < maxPID; start += 1024 {
		if err := ctx.Err(); err != nil {
			return err
		}
		visible, err := c.list(c.opt.ProcRoot)
		if err != nil {
			return err
		}
		end := min(start+1024, maxPID)
		ids := make([]int, 0, end-start)
		for pid := start; pid < end; pid++ {
			if !visible[pid] {
				ids = append(ids, pid)
			}
		}
		f, err := confirmHidden(ctx, c.opt.ProcRoot, visible, ids, c.confirmDelay, c.list)
		if err != nil {
			readErr = err
		}
		findings = append(findings, f...)
		c.mu.Lock()
		c.checked = end - 1
		c.mu.Unlock()
		if end < maxPID {
			if err := pause(ctx, c.batchPause); err != nil {
				return err
			}
		}
	}
	if readErr != nil {
		findings = append(findings, unavailable(c.opt.ProcRoot, readErr))
	}
	c.mu.Lock()
	c.sweep = slices.Clone(findings)
	c.complete = readErr == nil
	c.finished = time.Now()
	c.mu.Unlock()
	return readErr
}
func (c *Checker) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		_ = c.Sweep(ctx)
		if pause(ctx, c.opt.Interval) != nil {
			return
		}
	}
}

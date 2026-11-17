package fsinspect

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type Runner struct {
	opt     Options
	mu      sync.RWMutex
	runMu   sync.Mutex
	report  *model.FileInventory
	base    *model.FileInventory
	baseErr error
}

func New(opt Options) *Runner {
	r := &Runner{opt: defaults(opt)}
	if r.opt.StateDir != "" {
		b, _, e := safefile.ReadRegular(statePath(r.opt), 16<<20, false)
		if e == nil {
			var base model.FileInventory
			e = json.Unmarshal(b, &base)
			if e == nil && (base.Incomplete || base.Scope == "" || base.Time.IsZero() || len(base.Files) > 10000) {
				e = os.ErrInvalid
			}
			if e == nil {
				r.base = &base
			}
		}
		if !os.IsNotExist(e) {
			r.baseErr = e
		}
	}
	return r
}
func (r *Runner) Report() *model.FileInventory { r.mu.RLock(); defer r.mu.RUnlock(); return r.report }
func (r *Runner) Findings() []model.SystemFinding {
	rep := r.Report()
	if rep == nil {
		return []model.SystemFinding{{Risk: model.RiskInfo, Finding: model.Finding{ID: "fs_inventory_pending", Title: i18n.T("warn.fs_pending"), Category: model.CatInfo}}}
	}
	out := append([]model.SystemFinding(nil), rep.Findings...)
	if rep.Incomplete {
		out = append(out, model.SystemFinding{Risk: model.RiskInfo, Finding: model.Finding{ID: "fs_inventory_unavailable", Title: i18n.T("warn.fs_incomplete", ""), Evidence: rep.Warnings, Category: model.CatInfo}})
	}
	return out
}
func (r *Runner) RunOnce(ctx context.Context) *model.FileInventory {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	rep := Scan(ctx, r.opt)
	if r.baseErr != nil {
		rep.Incomplete = true
		rep.Warnings = append(rep.Warnings, i18n.T("warn.fs_baseline", r.baseErr.Error()))
	}
	if r.base != nil && r.base.Scope == rep.Scope {
		old := map[string]model.FilePrivilege{}
		for _, f := range r.base.Files {
			old[f.Path] = f
		}
		for _, f := range rep.Files {
			prev, exists := old[f.Path]
			if (f.SUID && (!exists || !prev.SUID)) || (f.SGID && (!exists || !prev.SGID)) || (f.Permitted&^prev.Permitted) != 0 || (f.Inheritable&^prev.Inheritable) != 0 || (f.Effective && !prev.Effective && f.Permitted != 0) {
				add(rep, "fs_privilege_new", f.Path, model.RiskHigh, "")
				if n := len(rep.Findings); n > 0 && rep.Findings[n-1].ID == "fs_privilege_new" {
					rep.Findings[n-1].Evidence = []i18n.Msg{i18n.T("ev.fs_new")}
				}
			}
		}
	} else if r.base != nil {
		rep.Incomplete = true
		rep.Warnings = append(rep.Warnings, i18n.T("warn.fs_baseline", "scope changed"))
	}
	if r.base == nil && r.baseErr == nil && !rep.Incomplete && !r.opt.ReadOnly && r.opt.StateDir != "" {
		if e := safefile.WriteJSON(statePath(r.opt), rep, 16<<20); e != nil {
			rep.Incomplete = true
			rep.Warnings = append(rep.Warnings, i18n.T("warn.fs_baseline", e.Error()))
		} else {
			r.base = rep
		}
	}
	r.mu.Lock()
	r.report = rep
	r.mu.Unlock()
	return rep
}
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(r.opt.Interval)
	defer t.Stop()
	for {
		r.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

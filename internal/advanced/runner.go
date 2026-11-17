// Пакет advanced проверяет ELF и веб-файлы отдельно от цикла процессов, с ограничением объёма.
package advanced

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type Options struct {
	HostRoot, ProcRoot string
	Webshell           bool
	Days               int
}
type Runner struct {
	opt         Options
	mu          sync.RWMutex
	runMu       sync.Mutex
	executables map[string]*model.ExecutableInspection
	findings    []model.SystemFinding
	done        bool
	incomplete  bool
}

func New(o Options) *Runner {
	if o.Days <= 0 {
		o.Days = 7
	}
	return &Runner{opt: o}
}
func (r *Runner) Run(ctx context.Context, snapshot func() *model.Snapshot) {
	for {
		snap := snapshot()
		delay := time.Second
		if snap != nil {
			r.Scan(ctx, snap)
			delay = time.Hour
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (r *Runner) Apply(procs []*model.Process) int {
	missing := 0
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range procs {
		if x := r.executables[p.Key]; x != nil && x.Path == p.Exe && time.Since(x.Time) < 2*time.Hour && p.ExeInfo != nil && x.Identity != "" && x.Identity == p.ExeInfo.Identity && x.Size == p.ExeInfo.Size && x.ModTime.Equal(p.ExeInfo.ModTime) {
			p.Executable = x
		} else if !p.Kernel && p.Exe != "" {
			missing++
		}
	}
	return missing
}
func (r *Runner) Findings() []model.SystemFinding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := append([]model.SystemFinding(nil), r.findings...)
	if !r.done {
		out = append(out, model.SystemFinding{Risk: model.RiskInfo, Finding: model.Finding{ID: "advanced_pending", Category: model.CatInfo, Title: i18n.T("warn.advanced_pending")}})
	} else if r.incomplete {
		out = append(out, model.SystemFinding{Risk: model.RiskInfo, Finding: model.Finding{ID: "advanced_unavailable", Category: model.CatInfo, Title: i18n.T("warn.advanced_incomplete")}})
	}
	return out
}
func (r *Runner) Scan(ctx context.Context, snap *model.Snapshot) {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	if snap == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	result := map[string]*model.ExecutableInspection{}
	incomplete := false
	root, e := os.OpenRoot(r.opt.HostRoot)
	if e != nil {
		incomplete = true
	} else {
		defer root.Close()
	}
	budget := int64(64 << 20)
	type cached struct {
		info       os.FileInfo
		inspection model.ExecutableInspection
	}
	var cache []cached
	live := filepath.Clean(r.opt.HostRoot) == "/" && filepath.Clean(r.opt.ProcRoot) == "/proc"
	for _, p := range snap.Processes {
		if p.Kernel || p.Exe == "" {
			continue
		}
		if ctx.Err() != nil || len(result) >= 5000 {
			incomplete = true
			break
		}
		var file *os.File
		var fi os.FileInfo
		var err error
		if live {
			data, _, e := safefile.ReadRegular(filepath.Join(r.opt.ProcRoot, strconv.Itoa(p.PID), "stat"), 8192, false)
			st, pe := procfs.ParseStat(string(data))
			if e != nil || pe != nil || st.StartTicks != p.StartTicks {
				continue
			}
			file, fi, err = safefile.Open(filepath.Join(r.opt.ProcRoot, strconv.Itoa(p.PID), "exe"), true)
		} else if root != nil {
			n, e := safefile.ResolveRooted(root, strings.TrimPrefix(p.Exe, "/"))
			err = e
			if err == nil {
				file, fi, err = safefile.OpenRooted(root, n)
			}
		} else {
			continue
		}
		if err != nil {
			incomplete = true
			continue
		}
		var x model.ExecutableInspection
		hit := false
		for _, c := range cache {
			if os.SameFile(fi, c.info) && procfs.FileIdentity(fi) == procfs.FileIdentity(c.info) && fi.Size() == c.info.Size() && fi.ModTime().Equal(c.info.ModTime()) {
				x = c.inspection
				hit = true
				break
			}
		}
		if !hit {
			if fi.Size() > 32<<20 || fi.Size() > budget || len(cache) >= 256 {
				file.Close()
				incomplete = true
				continue
			}
			data, err := io.ReadAll(io.LimitReader(file, min(32<<20, budget)+1))
			if int64(len(data)) > min(32<<20, budget) {
				err = safefile.ErrTooLarge
			}
			budget -= int64(len(data))
			if err == nil {
				x, err = InspectELF(data)
			}
			clear(data)
			if err != nil {
				x.Incomplete = true
				incomplete = true
			}
			after, e := file.Stat()
			if e != nil || !os.SameFile(fi, after) || procfs.FileIdentity(fi) != procfs.FileIdentity(after) || fi.Size() != after.Size() || !fi.ModTime().Equal(after.ModTime()) {
				x.Incomplete = true
				incomplete = true
			}
			cache = append(cache, cached{fi, x})
		}
		if live {
			data, _, e := safefile.ReadRegular(filepath.Join(r.opt.ProcRoot, strconv.Itoa(p.PID), "stat"), 8192, false)
			st, pe := procfs.ParseStat(string(data))
			target, te := os.Readlink(filepath.Join(r.opt.ProcRoot, strconv.Itoa(p.PID), "exe"))
			if e != nil || pe != nil || st.StartTicks != p.StartTicks || te != nil || strings.TrimSuffix(target, " (deleted)") != p.Exe || strings.HasSuffix(target, " (deleted)") != p.ExeDeleted {
				file.Close()
				incomplete = true
				continue
			}
		}
		file.Close()
		x.Identity = procfs.FileIdentity(fi)
		x.Time = time.Now()
		x.Path = p.Exe
		x.Size = fi.Size()
		x.ModTime = fi.ModTime()
		result[p.Key] = &x
	}
	var findings []model.SystemFinding
	if r.opt.Webshell {
		var complete bool
		findings, complete = webshells(ctx, r.opt.HostRoot, snap.Processes, r.opt.Days)
		incomplete = incomplete || !complete
	}
	r.mu.Lock()
	r.executables = result
	r.findings = findings
	r.incomplete = incomplete || ctx.Err() != nil
	r.done = true
	r.mu.Unlock()
}

// Package integrity сверяет системные файлы с локальной базой dpkg и сохранённым SHA-256.
package integrity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type Options struct {
	HostRoot, StateDir string
	ReadOnly           bool
	Interval           time.Duration
	Allowed            func(path string) bool
}
type baselineEntry struct{ Package, MD5, SHA256 string }
type baseline struct {
	Version int
	Files   map[string]baselineEntry
}
type Runner struct {
	opt      Options
	runMu    sync.Mutex
	mu       sync.RWMutex
	findings []model.SystemFinding
	base     baseline
	baseErr  error
	rate     int64
	// Только тесты подменяют источник между хешированием и второй сверкой базы.
	afterHash func()
}

func New(opt Options) *Runner {
	if opt.Interval <= 0 {
		opt.Interval = 24 * time.Hour
	}
	r := &Runner{opt: opt, base: baseline{Version: 1, Files: map[string]baselineEntry{}}, rate: 16 << 20}
	if opt.StateDir != "" {
		data, _, err := safefile.ReadRegular(filepath.Join(opt.StateDir, "integrity.json"), 32<<20, false)
		if err == nil {
			err = json.Unmarshal(data, &r.base)
			if err == nil {
				err = validateBaseline(r.base)
			}
		}
		if !errors.Is(err, os.ErrNotExist) {
			r.baseErr = err
		}
	}
	r.findings = []model.SystemFinding{finding("integrity_pending", "/var/lib/dpkg", model.RiskInfo, i18n.T("rule.integrity_pending.title"), i18n.T("rule.integrity_pending.rec"))}
	return r
}
func validateBaseline(b baseline) error {
	if b.Version != 1 || b.Files == nil || len(b.Files) > 200_000 {
		return os.ErrInvalid
	}
	for p, v := range b.Files {
		sha, e := hex.DecodeString(v.SHA256)
		if !validPath(p) || !selected(p) || e != nil || len(sha) != 32 {
			return os.ErrInvalid
		}
		if v.Package != "" {
			md, e := hex.DecodeString(v.MD5)
			if e != nil || len(md) != 16 {
				return os.ErrInvalid
			}
		}
	}
	return nil
}
func finding(id, path string, risk model.Risk, title, rec i18n.Msg, ev ...i18n.Msg) model.SystemFinding {
	return model.SystemFinding{Finding: model.Finding{ID: id, Category: model.CatIntegrity, Strong: risk == model.RiskCritical, Title: title, Recommendation: rec, Evidence: ev}, Path: path, Risk: risk}
}
func (r *Runner) Findings() []model.SystemFinding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.findings)
}
func (r *Runner) fail(err error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = slices.DeleteFunc(r.findings, func(f model.SystemFinding) bool {
		return f.ID == "integrity_unavailable" || f.ID == "integrity_complete" || f.ID == "integrity_pending"
	})
	r.findings = append(r.findings, finding("integrity_unavailable", "/var/lib/dpkg", model.RiskInfo, i18n.T("rule.integrity_unavailable.title"), i18n.T("rule.integrity_unavailable.rec"), i18n.T("ev.verification_error", err)))
	return err
}
func (r *Runner) idle(root *os.Root) error {
	if err := packageLocks(root); err != nil {
		return err
	}
	entries, err := safefile.ReadDir(filepath.Join(r.opt.HostRoot, "var/lib/dpkg/updates"), 1000)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errDatabase
	}
	return nil
}
func (r *Runner) Check(ctx context.Context) error {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	if r.baseErr != nil {
		return r.fail(r.baseErr)
	}
	root, err := os.OpenRoot(r.opt.HostRoot)
	if err != nil {
		return r.fail(err)
	}
	defer root.Close()
	if err := r.idle(root); err != nil {
		return r.fail(err)
	}
	db, err := loadDatabase(ctx, root)
	if err != nil {
		return r.fail(err)
	}
	names := make([]string, 0, len(db.files))
	for p := range db.files {
		names = append(names, p)
	}
	slices.Sort(names)
	var out []model.SystemFinding
	next := baseline{Version: 1, Files: map[string]baselineEntry{}}
	budget := readerBudget{start: time.Now(), rate: r.rate}
	var problems []error
	for _, p := range names {
		exp := db.files[p]
		sum, err := budget.hash(ctx, root, p)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		old, exists := r.base.Files[p]
		metadataChanged := exists && old.Package == exp.Package && old.MD5 != exp.MD5
		changed := sum.MD5 != exp.MD5 || (exists && old.Package == exp.Package && old.SHA256 != sum.SHA256)
		if changed || metadataChanged {
			// Повторяем чтение того же файла: текущую запись/замену не выдаём за устойчивое расхождение.
			if err := wait(ctx, 20*time.Millisecond); err != nil {
				return r.fail(err)
			}
			again, err := budget.hash(ctx, root, p)
			if err != nil || again != sum {
				problems = append(problems, errChanged)
				continue
			}
			risk := model.RiskHigh
			if critical(p) {
				risk = model.RiskCritical
			}
			out = append(out, finding("bin_modified", "/"+p, risk, i18n.T("rule.bin_modified.title", "/"+p), i18n.T("rule.bin_modified.rec"), i18n.T("ev.bin_digest", exp.Package, exp.MD5, sum.MD5), i18n.T("ev.bin_sha", old.SHA256, sum.SHA256)))
			if metadataChanged {
				out[len(out)-1].Evidence = append(out[len(out)-1].Evidence, i18n.T("ev.bin_metadata_changed"))
			}
			if exists {
				next.Files[p] = old
			}
		} else {
			next.Files[p] = baselineEntry{exp.Package, exp.MD5, sum.SHA256}
		}
	}
	checked := len(names)
	unverified := 0
	for p := range db.owned {
		if _, ok := db.files[p]; ok || db.excluded[p] {
			continue
		}
		fi, err := root.Lstat(p)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		if fi.Mode().IsRegular() {
			unverified++
		}
	}
	if unverified > 0 {
		out = append(out, finding("integrity_unverified", "/var/lib/dpkg", model.RiskInfo, i18n.T("rule.integrity_unverified.title", unverified), i18n.T("rule.integrity_unverified.rec")))
	}
	dirs := map[string]bool{}
	for _, d := range []string{"bin", "sbin", "usr/bin", "usr/sbin"} {
		dirs[db.canonical(d)] = true
	}
	for dir := range dirs {
		entries, err := safefile.ReadDir(filepath.Join(r.opt.HostRoot, dir), 100_000)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			problems = append(problems, err)
			continue
		}
		for _, entry := range entries {
			p := dir + "/" + entry.Name()
			if db.owned[p] || db.excluded[p] {
				continue
			}
			fi, err := root.Lstat(p)
			if err != nil {
				problems = append(problems, err)
				continue
			}
			_, wasAccepted := r.base.Files[p]
			if !fi.Mode().IsRegular() || (fi.Mode().Perm()&0111 == 0 && !wasAccepted) {
				continue
			}
			sum, err := budget.hash(ctx, root, p)
			if err != nil {
				problems = append(problems, err)
				continue
			}
			accepted := r.opt.Allowed != nil && r.opt.Allowed("/"+p)
			old, exists := r.base.Files[p]
			if exists && old.SHA256 != sum.SHA256 {
				again, err := budget.hash(ctx, root, p)
				if err != nil || again != sum {
					problems = append(problems, errChanged)
					continue
				}
				risk := model.RiskHigh
				if critical(p) {
					risk = model.RiskCritical
				}
				out = append(out, finding("bin_modified", "/"+p, risk, i18n.T("rule.bin_modified.title", "/"+p), i18n.T("rule.bin_modified.rec"), i18n.T("ev.bin_sha", old.SHA256, sum.SHA256)))
				next.Files[p] = old
			} else {
				f := finding("bin_unpackaged", "/"+p, model.RiskInfo, i18n.T("rule.bin_unpackaged.title", "/"+p), i18n.T("rule.bin_unpackaged.rec"), i18n.T("ev.bin_sha", "", sum.SHA256))
				f.Suppressed = accepted
				out = append(out, f)
				if accepted {
					next.Files[p] = baselineEntry{SHA256: sum.SHA256}
				} else if exists && old.Package != "" {
					next.Files[p] = old
				}
			}
		}
	}
	for p, old := range r.base.Files {
		if old.Package != "" || db.owned[p] {
			continue
		}
		if _, ok := next.Files[p]; ok {
			continue
		}
		// Пропавший или заменённый ссылкой принятый файл не должен молча исчезнуть из эталона.
		fi, err := root.Lstat(p)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		if !fi.Mode().IsRegular() {
			problems = append(problems, errChanged)
		}
	}
	if r.afterHash != nil {
		r.afterHash()
	}
	if err := r.idle(root); err != nil {
		return r.fail(err)
	}
	after, err := loadDatabase(ctx, root)
	if err != nil {
		return r.fail(err)
	}
	if after.digest != db.digest {
		return r.fail(errDatabase)
	}
	if err := r.idle(root); err != nil {
		return r.fail(err)
	}
	if err := ctx.Err(); err != nil {
		return r.fail(err)
	}
	// При частичном чтении сохраняем прежний эталон целиком; проверенные расхождения всё равно показываем.
	if len(problems) == 0 {
		if r.opt.StateDir != "" && !r.opt.ReadOnly {
			if err := safefile.WriteJSON(filepath.Join(r.opt.StateDir, "integrity.json"), next, 32<<20); err != nil {
				problems = append(problems, err)
			}
		}
		if len(problems) == 0 {
			r.base = next
		}
	}
	if len(problems) == 0 {
		out = append(out, finding("integrity_complete", "/var/lib/dpkg", model.RiskInfo, i18n.T("rule.integrity_complete.title"), i18n.T("rule.integrity_complete.rec"), i18n.T("ev.integrity_completed", checked, time.Now().UTC().Format(time.RFC3339))))
	} else {
		out = append(out, finding("integrity_unavailable", "/var/lib/dpkg", model.RiskInfo, i18n.T("rule.integrity_unavailable.title"), i18n.T("rule.integrity_unavailable.rec"), i18n.T("ev.integrity_errors", len(problems)), i18n.T("ev.verification_error", problems[0])))
	}
	slices.SortFunc(out, func(a, b model.SystemFinding) int { return strings.Compare(a.ID+a.Path, b.ID+b.Path) })
	r.mu.Lock()
	r.findings = out
	r.mu.Unlock()
	return errors.Join(problems...)
}
func (r *Runner) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		_ = r.Check(ctx)
		if wait(ctx, r.opt.Interval) != nil {
			return
		}
	}
}

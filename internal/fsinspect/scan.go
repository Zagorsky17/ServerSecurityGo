// Пакет fsinspect инвентаризирует привилегированные файлы без выполнения программ.
package fsinspect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/integrity"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type Options struct {
	HostRoot, ProcRoot, StateDir string
	Interval                     time.Duration
	Rate                         int
	Exclude, Mounts              []string
	ReadOnly                     bool
	MaxEntries                   int
	capRead                      func(*os.File) (Capability, error)
}

func defaults(o Options) Options {
	if o.HostRoot == "" {
		o.HostRoot = "/"
	}
	if o.Interval <= 0 {
		o.Interval = 6 * time.Hour
	}
	if o.Rate <= 0 {
		o.Rate = 2000
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 2_000_000
	}
	if o.capRead == nil {
		o.capRead = capabilities
	}
	return o
}
func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
func systemPath(p string) bool {
	for _, d := range []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/opt"} {
		if under(p, d) {
			return true
		}
	}
	return false
}
func add(r *model.FileInventory, id, p string, risk model.Risk, ev string) {
	if len(r.Findings) >= 10000 {
		r.Incomplete = true
		return
	}
	r.Findings = append(r.Findings, model.SystemFinding{Path: p, Risk: risk, Finding: model.Finding{ID: id, Category: model.CatPrivilege, Title: i18n.T("rule.fs_observation.title", id, p), Evidence: []i18n.Msg{i18n.L(ev)}, Recommendation: i18n.T("rec.fs_review"), Strong: risk >= model.RiskHigh}})
}
func Scan(ctx context.Context, opt Options) *model.FileInventory {
	o := defaults(opt)
	r := &model.FileInventory{Time: time.Now(), Files: []model.FilePrivilege{}}
	roots := append([]string{"/", "/dev/shm"}, o.Mounts...)
	slices.Sort(roots)
	roots = slices.Compact(roots)
	excludes := append([]string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containers"}, o.Exclude...)
	slices.Sort(excludes)
	scopeText := strings.Join(roots, "\x00") + "\n" + strings.Join(excludes, "\x00")
	sum := sha256.Sum256([]byte(scopeText))
	r.Scope = hex.EncodeToString(sum[:])
	root, err := os.OpenRoot(o.HostRoot)
	if err != nil {
		r.Incomplete = true
		r.Warnings = append(r.Warnings, i18n.T("warn.fs_incomplete", err.Error()))
		return r
	}
	defer root.Close()
	var network []string
	mountData, _, mountErr := safefile.ReadRegular(filepath.Join(o.ProcRoot, "self/mountinfo"), 4<<20, true)
	if mountErr == nil {
		mounts, e := ParseMountInfo(string(mountData))
		mountErr = e
		for _, m := range mounts {
			scopeText += "\n" + m.Point + " " + m.Type
			if NetworkFS(m.Type) {
				network = append(network, m.Point)
			}
		}
	}
	sum = sha256.Sum256([]byte(scopeText))
	r.Scope = hex.EncodeToString(sum[:])
	if mountErr != nil {
		r.Incomplete = true
		r.Warnings = append(r.Warnings, i18n.T("warn.fs_mounts"))
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	users, userOK := ids(root, "etc/passwd", 2)
	groups, groupOK := ids(root, "etc/group", 2)
	if !userOK || !groupOK {
		r.Incomplete = true
	}
	capsOK := true
	start := time.Now()
	seen := map[string]bool{}
	excluded := func(p string) bool {
		for _, d := range excludes {
			if under(p, d) {
				return true
			}
		}
		return false
	}
	var walk func(string, uint64, int, bool)
	walk = func(p string, dev uint64, depth int, explicit bool) {
		if ctx.Err() != nil || r.Scanned >= o.MaxEntries || depth > 128 {
			r.Incomplete = true
			return
		}
		for _, n := range network {
			if n == "/" || under(p, n) {
				if explicit {
					r.Incomplete = true
				}
				return
			}
		}
		if seen[p] || (!explicit && excluded(p)) {
			return
		}
		seen[p] = true
		rel := strings.TrimPrefix(p, "/")
		if rel == "" {
			rel = "."
		}
		fi, e := root.Lstat(rel)
		if os.IsNotExist(e) {
			return
		}
		if e != nil {
			r.Incomplete = true
			return
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return
		}
		current, uid, gid := metadata(fi)
		if !explicit && current != dev {
			return
		}
		if explicit {
			dev = current
		}
		r.Scanned++
		if r.Scanned%100 == 0 {
			pause := time.Duration(r.Scanned)*time.Second/time.Duration(o.Rate) - time.Since(start)
			if pause > 0 {
				timer := time.NewTimer(pause)
				select {
				case <-ctx.Done():
					timer.Stop()
					r.Incomplete = true
					return
				case <-timer.C:
				}
			}
		}
		if systemPath(p) {
			if fi.Mode().Perm()&2 != 0 && !(fi.IsDir() && fi.Mode()&os.ModeSticky != 0) {
				add(r, "fs_world_writable_system", p, model.RiskHigh, fi.Mode().String())
			}
			if userOK && groupOK && (!users[uid] || !groups[gid]) {
				add(r, "fs_unowned", p, model.RiskMedium, fmt.Sprintf("uid=%d gid=%d", uid, gid))
			}
		}
		if fi.IsDir() {
			entries, e := safefile.ReadDirRooted(root, rel, 100000)
			if e != nil {
				r.Incomplete = true
				return
			}
			slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
			for _, d := range entries {
				walk(path.Join(p, d.Name()), dev, depth+1, false)
				if ctx.Err() != nil || r.Scanned >= o.MaxEntries {
					break
				}
			}
			return
		}
		if !fi.Mode().IsRegular() {
			return
		}
		f, after, e := safefile.OpenRooted(root, rel)
		if e != nil || !os.SameFile(fi, after) {
			if f != nil {
				f.Close()
			}
			r.Incomplete = true
			return
		}
		cap, e := o.capRead(f)
		latest, statErr := f.Stat()
		f.Close()
		if statErr != nil || latest.Mode() != fi.Mode() || !latest.ModTime().Equal(fi.ModTime()) {
			r.Incomplete = true
			return
		}
		_, latestUID, latestGID := metadata(latest)
		if latestUID != uid || latestGID != gid {
			r.Incomplete = true
			return
		}
		if e != nil {
			capsOK = false
			r.Incomplete = true
		}
		suid, sgid := fi.Mode()&os.ModeSetuid != 0, fi.Mode()&os.ModeSetgid != 0
		if !suid && !sgid && cap.Permitted == 0 && cap.Inheritable == 0 {
			return
		}
		if len(r.Files) >= 10000 {
			r.Incomplete = true
			return
		}
		entry := model.FilePrivilege{Path: p, Mode: fi.Mode().String(), UID: uid, GID: gid, SUID: suid, SGID: sgid, Permitted: cap.Permitted, Inheritable: cap.Inheritable, Effective: cap.Effective, RootID: cap.RootID}
		r.Files = append(r.Files, entry)
	}
	for _, p := range roots {
		walk(path.Clean(p), 0, 0, true)
	}
	paths := map[string]bool{}
	for _, f := range r.Files {
		paths[f.Path] = true
	}
	owned, e := integrity.OwnersFor(o.HostRoot, paths)
	if e != nil {
		r.Incomplete = true
		r.Warnings = append(r.Warnings, i18n.T("warn.fs_packages"))
	}
	for i := range r.Files {
		f := &r.Files[i]
		if owned != nil {
			v := owned[f.Path]
			f.PackageOwned = &v
		}
		risky := dangerousName(path.Base(f.Path)) || under(f.Path, "/tmp") || under(f.Path, "/var/tmp") || under(f.Path, "/dev/shm") || under(f.Path, "/home")
		if f.SUID || f.SGID {
			risk := model.RiskInfo
			if risky {
				risk = model.RiskCritical
			}
			add(r, "fs_suid_inventory", f.Path, risk, fmt.Sprintf("%s uid=%d gid=%d package=%v", f.Mode, f.UID, f.GID, f.PackageOwned != nil && *f.PackageOwned))
		}
		if f.Permitted != 0 || f.Inheritable != 0 {
			risk := model.RiskLow
			if (f.Permitted|f.Inheritable)&dangerousCaps != 0 {
				risk = model.RiskHigh
			}
			if risky && f.Effective && f.Permitted&(1<<7) != 0 {
				risk = model.RiskCritical
			}
			if f.PackageOwned != nil && *f.PackageOwned && f.Permitted == 1<<13 && f.Inheritable == 0 && slices.Contains([]string{"ping", "mtr-packet", "gst-ptp-helper"}, path.Base(f.Path)) {
				risk = model.RiskInfo
			}
			add(r, "fs_capabilities", f.Path, risk, fmt.Sprintf("permitted=%#x inheritable=%#x effective=%v rootid=%d", f.Permitted, f.Inheritable, f.Effective, f.RootID))
		}
	}
	if !capsOK {
		r.Warnings = append(r.Warnings, i18n.T("warn.fs_capabilities", runtime.GOOS))
	}
	if r.Incomplete {
		r.Warnings = append(r.Warnings, i18n.T("warn.fs_incomplete", "read errors, cancellation or traversal limits"))
	}
	slices.SortFunc(r.Files, func(a, b model.FilePrivilege) int { return strings.Compare(a.Path, b.Path) })
	return r
}

const dangerousCaps uint64 = 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<6 | 1<<7 | 1<<16 | 1<<19 | 1<<21

func dangerousName(s string) bool {
	for _, n := range []string{"bash", "sh", "dash", "python", "perl", "node", "vim", "find", "cp", "gdb", "ruby", "php", "busybox"} {
		if s == n || (strings.HasPrefix(s, n) && len(s) > len(n) && s[len(n)] >= '0' && s[len(n)] <= '9') {
			return true
		}
	}
	return false
}
func ids(root *os.Root, p string, col int) (map[uint32]bool, bool) {
	b, _, e := safefile.ReadRooted(root, p, 1<<20)
	out := map[uint32]bool{}
	if e != nil {
		return out, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) <= col {
			return out, false
		}
		n, e := strconv.ParseUint(f[col], 10, 32)
		if e != nil {
			return out, false
		}
		out[uint32(n)] = true
	}
	return out, len(out) > 0
}

func statePath(o Options) string { return filepath.Join(o.StateDir, "baseline.json") }

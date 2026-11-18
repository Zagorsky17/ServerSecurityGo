package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/fsinspect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

func (a *auditor) filesystemChecks() []model.AuditCheck {
	out := []model.AuditCheck{}
	mounts := newCheck("fs_tmp_noexec", model.AuditGroupFS, model.RiskLow, "audit.fs_tmp_noexec.title")
	b, _, e := safefile.ReadRegular(filepath.Join(a.opt.ProcRoot, "self/mountinfo"), 4<<20, true)
	parsed, parseErr := fsinspect.ParseMountInfo(string(b))
	if e != nil || parseErr != nil {
		mounts.Status = model.AuditUnknown
	} else {
		for _, p := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
			m, ok := fsinspect.MountAt(parsed, p)
			if !ok {
				mounts.Status = model.AuditUnknown
				continue
			}
			var missing []string
			for _, flag := range []string{"noexec", "nosuid", "nodev"} {
				if !m.Options[flag] {
					missing = append(missing, flag)
				}
			}
			addEv(&mounts, i18n.L(fmt.Sprintf("%s mount=%s missing=%s", p, m.Point, strings.Join(missing, ","))))
			if len(missing) > 0 && mounts.Status != model.AuditUnknown {
				mounts.Status = model.AuditWarn
			}
			if p == "/dev/shm" && !m.Options["noexec"] {
				mounts.Severity = model.RiskMedium
			}
		}
	}
	mounts.Recommendation = i18n.T("audit.fs_tmp_noexec.rec")
	out = append(out, mounts)
	perms := newCheck("fs_sensitive_perms", model.AuditGroupFS, model.RiskHigh, "audit.fs_sensitive_perms.title")
	root, e := os.OpenRoot(a.opt.HostRoot)
	if e != nil {
		perms.Status = model.AuditUnknown
	} else {

		defer root.Close()
		shadowGID := -1
		if data, e := a.readHost("etc/group"); e == nil {
			for _, g := range parseGroup(string(data)) {
				if g.Name == "shadow" {
					shadowGID = g.GID
				}
			}
		}
		seen := 0
		for _, p := range []string{"etc/shadow", "etc/gshadow", "etc/sudoers", "root", "etc/crontab", "etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly", "boot/grub/grub.cfg"} {
			fi, e := root.Lstat(p)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				if perms.Status != model.AuditFail {
					perms.Status = model.AuditUnknown
				}
				continue
			}
			seen++
			_, gid, owned := owner(fi)
			if !owned && perms.Status != model.AuditFail {
				perms.Status = model.AuditUnknown
			}
			bad := !a.isRoot(fi) || fi.Mode().Perm()&0022 != 0 || fi.Mode()&os.ModeSymlink != 0
			if p == "root" {
				bad = bad || fi.Mode().Perm()&0077 != 0
			}
			if p == "etc/shadow" || p == "etc/gshadow" || p == "etc/sudoers" {
				bad = bad || fi.Mode().Perm()&0007 != 0
				if (p == "etc/shadow" || p == "etc/gshadow") && fi.Mode().Perm()&0040 != 0 && owned && gid != 0 && gid != shadowGID {
					bad = true
				}
			}
			if bad {
				perms.Status = model.AuditFail
				addEv(&perms, i18n.L("/"+p+" "+describe(fi)))
			}
		}
		if seen == 0 {
			perms.Status = model.AuditUnknown
		}
	}
	perms.Recommendation = i18n.T("audit.fs_sensitive_perms.rec")
	out = append(out, perms)
	for _, id := range []string{"fs_world_writable_system", "fs_unowned", "fs_suid_inventory", "fs_capabilities"} {
		c := newCheck(id, model.AuditGroupFS, model.RiskInfo, "audit.fs_inventory.title")
		c.Title = i18n.T("audit.fs_inventory.title", id)
		c.Recommendation = i18n.T("rec.fs_review")
		if a.opt.Inventory == nil || a.opt.Inventory.Incomplete {
			c.Status = model.AuditUnknown
		}
		if a.opt.Inventory != nil {
			addEv(&c, i18n.T("ev.fs_inventory", a.opt.Inventory.Scanned, len(a.opt.Inventory.Files), a.opt.Inventory.Time.UTC().Format("2006-01-02T15:04:05Z")))
			for _, f := range a.opt.Inventory.Findings {
				if f.ID == id || ((id == "fs_suid_inventory" || id == "fs_capabilities") && f.ID == "fs_privilege_new") {
					c.Severity = max(c.Severity, f.Risk)
					if f.Risk >= model.RiskHigh {
						c.Status = model.AuditFail
					} else if f.Risk > model.RiskInfo && c.Status != model.AuditFail && c.Status != model.AuditUnknown {
						c.Status = model.AuditWarn
					}
					addEv(&c, i18n.L(f.Path))
					for _, ev := range f.Evidence {
						addEv(&c, ev)
					}
				}
			}
		}
		out = append(out, c)
	}
	return out
}

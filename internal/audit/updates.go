package audit

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

func hostName(root *os.Root, p string) (string, error) {
	p = strings.TrimPrefix(p, "/")
	parent, e := safefile.ResolveRooted(root, path.Dir(p))
	if e != nil {
		return "", e
	}
	return path.Join(parent, path.Base(p)), nil
}
func (a *auditor) readHost(p string) ([]byte, error) { return a.readHostLimit(p, maxConfigFile) }
func (a *auditor) readHostLimit(p string, limit int64) ([]byte, error) {
	root, e := os.OpenRoot(a.opt.HostRoot)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	p, e = hostName(root, p)
	if e != nil {
		return nil, e
	}
	b, _, e := safefile.ReadRooted(root, p, limit)
	return b, e
}
func (a *auditor) statHost(p string) (os.FileInfo, error) {
	root, e := os.OpenRoot(a.opt.HostRoot)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	p, e = hostName(root, p)
	if e != nil {
		return nil, e
	}
	return root.Lstat(p)
}
func (a *auditor) updateChecks() []model.AuditCheck {
	var out []model.AuditCheck
	c := newCheck("upd_reboot_required", model.AuditGroupUpdates, model.RiskMedium, "audit.upd_reboot_required.title")
	if fi, e := a.statHost("var/run/reboot-required"); e == nil {
		if !fi.Mode().IsRegular() {
			c.Status = model.AuditUnknown
		} else {
			c.Status = model.AuditWarn
			addEv(&c, i18n.L("/var/run/reboot-required"))
			if b, e := a.readHost("var/run/reboot-required.pkgs"); e == nil {
				addEv(&c, i18n.L(truncate(string(b), 2000)))
			}
		}
	} else if !os.IsNotExist(e) {
		c.Status = model.AuditUnknown
	}
	c.Recommendation = i18n.T("audit.upd_reboot_required.rec")
	out = append(out, c)
	c = newCheck("upd_kernel_mismatch", model.AuditGroupUpdates, model.RiskMedium, "audit.upd_kernel_mismatch.title")
	running, _, e := safefile.ReadRegular(filepath.Join(a.opt.ProcRoot, "sys/kernel/osrelease"), 4096, true)
	if e != nil {
		c.Status = model.AuditUnknown
	} else {
		current := strings.TrimSpace(string(running))
		addEv(&c, i18n.L(current))
		root, e := os.OpenRoot(a.opt.HostRoot)
		if e != nil {
			c.Status = model.AuditUnknown
		} else {
			found, readOK := false, false
			for _, dir := range []string{"boot", "lib/modules", "usr/lib/modules"} {
				resolved, err := safefile.ResolveRooted(root, dir)
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					continue
				}
				entries, err := safefile.ReadDirRooted(root, resolved, 4096)
				if err != nil {
					continue
				}
				readOK = true
				for _, entry := range entries {
					name := entry.Name()
					if dir == "boot" {
						if !strings.HasPrefix(name, "vmlinuz-") {
							continue
						}
						name = strings.TrimPrefix(name, "vmlinuz-")
					}
					newer, comparable := KernelNewer(name, current)
					if comparable {
						found = true
					}
					if newer {
						c.Status = model.AuditWarn
						addEv(&c, i18n.L(name))
					}
				}
			}
			root.Close()
			if !found || !readOK {
				c.Status = model.AuditUnknown
			}
		}
	}
	c.Recommendation = i18n.T("audit.upd_kernel_mismatch.rec")
	out = append(out, c)
	c = newCheck("upd_stale", model.AuditGroupUpdates, model.RiskMedium, "audit.upd_stale.title")
	var last time.Time
	for _, p := range []string{"var/lib/apt/periodic/update-success-stamp", "var/lib/apt/lists"} {
		fi, e := a.statHost(p)
		if e == nil && fi.Mode()&os.ModeSymlink == 0 {
			if fi.ModTime().After(last) {
				last = fi.ModTime()
			}
			addEv(&c, i18n.L(p+" "+fi.ModTime().UTC().Format(time.RFC3339)))
		}
	}
	if last.IsZero() || last.After(a.opt.Now.Add(5*time.Minute)) {
		c.Status = model.AuditUnknown
	} else if a.opt.Now.Sub(last) > 14*24*time.Hour {
		c.Status = model.AuditWarn
		if a.opt.Now.Sub(last) > 60*24*time.Hour {
			c.Severity = model.RiskHigh
		}
	}
	c.Recommendation = i18n.T("audit.upd_stale.rec")
	c.FixCommand = "apt-get update"
	out = append(out, c)
	c = newCheck("upd_unattended", model.AuditGroupUpdates, model.RiskLow, "audit.upd_unattended.title")
	status, e := a.readHostLimit("var/lib/dpkg/status", 64<<20)
	if e != nil {
		c.Status = model.AuditUnknown
	} else {
		installed := false
		for _, block := range strings.Split(string(status), "\n\n") {
			if strings.HasPrefix(block, "Package: unattended-upgrades\n") && strings.Contains("\n"+block+"\n", "\nStatus: install ok installed\n") {
				installed = true
			}
		}
		enabled, known := a.autoUpgrades()
		if !known {
			c.Status = model.AuditUnknown
		} else if !installed || !enabled {
			c.Status = model.AuditWarn
		}
		addEv(&c, i18n.L(fmt.Sprintf("package=%v periodic=%v", installed, enabled)))
	}
	c.Recommendation = i18n.T("audit.upd_unattended.rec")
	out = append(out, c)
	return append(out, a.releaseSupport())
}

var kernelVersion = regexp.MustCompile(`^([0-9]+(?:[.+-][0-9]+)*)([a-zA-Z+_-].*)?$`)

func KernelNewer(candidate, current string) (bool, bool) {
	a, b := kernelVersion.FindStringSubmatch(candidate), kernelVersion.FindStringSubmatch(current)
	if a == nil || b == nil || a[2] != b[2] {
		return false, false
	}
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	}
	aa, bb := split(a[1]), split(b[1])
	if len(aa) > 20 || len(bb) > 20 {
		return false, false
	}
	result := 0
	for i := 0; i < max(len(aa), len(bb)); i++ {
		var av, bv uint64
		var e error
		if i < len(aa) {
			av, e = strconv.ParseUint(aa[i], 10, 64)
			if e != nil {
				return false, false
			}
		}
		if i < len(bb) {
			bv, e = strconv.ParseUint(bb[i], 10, 64)
			if e != nil {
				return false, false
			}
		}
		if result == 0 {
			if av > bv {
				result = 1
			} else if av < bv {
				result = -1
			}
		}
	}
	return result > 0, true
}

var periodicSetting = regexp.MustCompile(`APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)\s+"?([a-zA-Z0-9]+)"?\s*;`)

func (a *auditor) autoUpgrades() (bool, bool) {
	root, e := os.OpenRoot(a.opt.HostRoot)
	if e != nil {
		return false, false
	}
	defer root.Close()
	entries, e := safefile.ReadDirRooted(root, "etc/apt/apt.conf.d", 256)
	if e != nil {
		return false, false
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") || strings.Contains(entry.Name(), ".") {
			continue
		}
		names = append(names, "etc/apt/apt.conf.d/"+entry.Name())
	}
	names = append(names, "etc/apt/apt.conf")
	vals := map[string]bool{}
	budget := int64(4 << 20)
	for _, name := range names {
		b, _, err := safefile.ReadRooted(root, name, min(maxConfigFile, budget))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, false
		}
		budget -= int64(len(b))
		text := string(b)
		if strings.Contains(text, "#include") || strings.Contains(text, "#clear") {
			return false, false
		}
		text = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(text, "")
		var clean []string
		for _, line := range strings.Split(text, "\n") {
			line, _, _ = strings.Cut(line, "//")
			clean = append(clean, line)
		}
		if regexp.MustCompile(`APT::Periodic\s*\{`).MatchString(strings.Join(clean, "\n")) {
			return false, false
		}
		for _, m := range periodicSetting.FindAllStringSubmatch(strings.Join(clean, "\n"), -1) {
			n, e := strconv.ParseUint(m[2], 10, 32)
			if m[2] == "always" {
				vals[m[1]] = true
				continue
			}
			if e != nil {
				return false, false
			}
			vals[m[1]] = n > 0
		}
	}
	return vals["Update-Package-Lists"] && vals["Unattended-Upgrade"], true
}

// Даты окончания публичной поддержки; расширенные договоры проверяет владелец.
// Источники сверены 18.11.2026: ubuntu.com/about, debian.org/releases/index.
var publicSupport = map[string]string{
	"ubuntu:14.04": "2019-06-01", "ubuntu:16.04": "2021-06-01", "ubuntu:18.04": "2023-06-01", "ubuntu:20.04": "2025-06-01", "ubuntu:22.04": "2027-06-01", "ubuntu:24.04": "2029-06-01", "ubuntu:26.04": "2031-06-01", "ubuntu:24.10": "2025-07-10", "ubuntu:25.04": "2026-01-15", "ubuntu:25.10": "2026-07-09", "ubuntu:26.10": "2027-08-01",
	"debian:10": "2024-07-01", "debian:11": "2026-09-01", "debian:12": "2028-07-01", "debian:13": "2030-07-01",
}

func (a *auditor) releaseSupport() model.AuditCheck {
	c := newCheck("upd_eol_release", model.AuditGroupUpdates, model.RiskHigh, "audit.upd_eol_release.title")
	root, e := os.OpenRoot(a.opt.HostRoot)
	var b []byte
	if e == nil {
		defer root.Close()
		var n string
		n, e = safefile.ResolveRooted(root, "etc/os-release")
		if e == nil {
			b, _, e = safefile.ReadRooted(root, n, maxConfigFile)
		}
	}
	if e != nil {
		c.Status = model.AuditUnknown
		return c
	}
	vals := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			vals[k] = strings.Trim(v, "\"'")
		}
	}
	end, ok := publicSupport[vals["ID"]+":"+vals["VERSION_ID"]]
	if !ok {
		c.Status = model.AuditUnknown
		addEv(&c, i18n.L(vals["ID"]+" "+vals["VERSION_ID"]))
	} else {
		deadline, _ := time.Parse("2006-01-02", end)
		addEv(&c, i18n.L(vals["ID"]+" "+vals["VERSION_ID"]+" public support before "+end+"; table 2026-11-18"))
		if !a.opt.Now.Before(deadline) {
			c.Status = model.AuditWarn
		}
	}
	c.Recommendation = i18n.T("audit.upd_eol_release.rec")
	c.References = []string{"https://ubuntu.com/about/release-cycle", "https://www.debian.org/releases/"}
	return c
}

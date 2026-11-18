package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func checksByID(cs []model.AuditCheck) map[string]model.AuditCheck {
	out := map[string]model.AuditCheck{}
	for _, c := range cs {
		out[c.ID] = c
	}
	return out
}
func putHardening(t *testing.T, root, p, data string) {
	t.Helper()
	n := filepath.Join(root, p)
	if e := os.MkdirAll(filepath.Dir(n), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(n, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestHardeningSysctlsAndCoreHandler(t *testing.T) {
	proc := t.TempDir()
	a := &auditor{opt: Options{HostRoot: t.TempDir(), ProcRoot: proc}}
	for _, r := range hardeningSysctls {
		putHardening(t, proc, "sys/"+r.name, strconv.Itoa(r.want))
		c := a.sysctlCheck(r)
		if c.Status != model.AuditPass {
			t.Fatal(r.id, c)
		}
		putHardening(t, proc, "sys/"+r.name, "garbage")
		if a.sysctlCheck(r).Status != model.AuditUnknown {
			t.Fatal(r.id)
		}
		putHardening(t, proc, "sys/"+r.name, "1 2")
		if a.sysctlCheck(r).Status != model.AuditUnknown {
			t.Fatal("multi-value accepted", r.id)
		}
		putHardening(t, proc, "sys/"+r.name, strconv.Itoa(r.want))
	}
	for _, tc := range []struct{ value, status string }{{"|/usr/lib/systemd/systemd-coredump %P", model.AuditInfo}, {"|/tmp/handler", model.AuditFail}, {"|/usr/lib/../../tmp/handler", model.AuditFail}, {"", model.AuditUnknown}, {"core", model.AuditPass}, {"/tmp/core", model.AuditWarn}} {
		putHardening(t, proc, "sys/kernel/core_pattern", tc.value)
		if c := checksByID(a.hardeningKernel())["kern_core_pattern"]; c.Status != tc.status {
			t.Fatal(tc, c)
		}
	}
	putHardening(t, proc, "sys/net/ipv4/conf/all/rp_filter", "3")
	if c := checksByID(a.hardeningKernel())["net_rp_filter"]; c.Status != model.AuditUnknown {
		t.Fatal(c)
	}
	putHardening(t, proc, "sys/user/max_user_namespaces", "65536")
	putHardening(t, proc, "sys/kernel/sysrq", "176")
	m := checksByID(a.hardeningKernel())
	if m["kern_userns"].Status != model.AuditInfo || m["kern_sysrq"].Status != model.AuditInfo {
		t.Fatal(m)
	}
	os.Remove(filepath.Join(proc, "sys/kernel/yama/ptrace_scope"))
	if c := checksByID(a.hardeningKernel())["kern_ptrace"]; c.Status != model.AuditNA {
		t.Fatal(c)
	}
}
func TestFilesystemAuditMountPermissionsInventory(t *testing.T) {
	root := t.TempDir()
	proc := t.TempDir()
	a := &auditor{opt: Options{HostRoot: root, ProcRoot: proc, RootUID: os.Getuid()}}
	putHardening(t, proc, "self/mountinfo", "1 0 1:1 / / rw,nosuid,nodev,noexec - ext4 /dev/a rw\n")
	putHardening(t, root, "etc/shadow", "SECRET_HASH")
	putHardening(t, root, "etc/group", fmt.Sprintf("shadow:x:%d:\n", os.Getgid()))
	os.Chmod(filepath.Join(root, "etc/shadow"), 0640)
	m := checksByID(a.filesystemChecks())
	if m["fs_tmp_noexec"].Status != model.AuditPass || m["fs_sensitive_perms"].Status != model.AuditPass || m["fs_suid_inventory"].Status != model.AuditUnknown {
		t.Fatal(m)
	}
	os.Chmod(filepath.Join(root, "etc/shadow"), 0666)
	putHardening(t, proc, "self/mountinfo", "1 0 1:1 / / rw - ext4 /dev/a rw\n")
	a.opt.Inventory = &model.FileInventory{Time: time.Now(), Incomplete: true, Findings: []model.SystemFinding{{Path: "/tmp/suid", Risk: model.RiskCritical, Finding: model.Finding{ID: "fs_suid_inventory", Evidence: []i18n.Msg{i18n.L("setuid")}}}}}
	m = checksByID(a.filesystemChecks())
	if m["fs_sensitive_perms"].Status != model.AuditFail || m["fs_tmp_noexec"].Severity != model.RiskMedium || m["fs_suid_inventory"].Status != model.AuditFail {
		t.Fatal(m)
	}
	for _, c := range m {
		for _, e := range c.Evidence {
			if strings.Contains(e.In(i18n.EN), "SECRET_HASH") {
				t.Fatal("shadow content leaked")
			}
		}
	}
	putHardening(t, proc, "self/mountinfo", "broken")
	if c := checksByID(a.filesystemChecks())["fs_tmp_noexec"]; c.Status != model.AuditUnknown {
		t.Fatal(c)
	}
}
func TestUpdatesVersionsMetadataAndAptOverrides(t *testing.T) {
	for _, tc := range []struct {
		a, b         string
		newer, known bool
	}{{"6.8.0-100-generic", "6.8.0-99-generic", true, true}, {"6.8.0-99-generic", "6.8.0-100-generic", false, true}, {"6.8.0-100-aws", "6.8.0-99-generic", false, false}, {"6.8.0-100-generic", "6.8.0-100-generic", false, true}, {"broken", "6.8.0", false, false}, {strings.Repeat("9", 100), "1", false, false}} {
		n, k := KernelNewer(tc.a, tc.b)
		if n != tc.newer || k != tc.known {
			t.Fatal(tc, n, k)
		}
	}
	root := t.TempDir()
	proc := t.TempDir()
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	a := &auditor{opt: Options{HostRoot: root, ProcRoot: proc, Now: now}}
	putHardening(t, root, "run/reboot-required", "")
	putHardening(t, root, "run/reboot-required.pkgs", "linux-image")
	os.MkdirAll(filepath.Join(root, "var"), 0700)
	os.Symlink("/run", filepath.Join(root, "var/run"))
	putHardening(t, proc, "sys/kernel/osrelease", "6.8.0-99-generic")
	putHardening(t, root, "boot/vmlinuz-6.8.0-100-generic", "")
	putHardening(t, root, "var/lib/apt/periodic/update-success-stamp", "")
	old := now.Add(-61 * 24 * time.Hour)
	os.Chtimes(filepath.Join(root, "var/lib/apt/periodic/update-success-stamp"), old, old)
	putHardening(t, root, "var/lib/dpkg/status", "Package: unattended-upgrades\nStatus: install ok installed\n\n")
	putHardening(t, root, "etc/apt/apt.conf.d/20auto-upgrades", `APT::Periodic::Update-Package-Lists "1"; APT::Periodic::Unattended-Upgrade "1";`)
	putHardening(t, root, "usr/lib/os-release", "ID=debian\nVERSION_ID=11\n")
	os.Symlink("/usr/lib/os-release", filepath.Join(root, "etc/os-release"))
	m := checksByID(a.updateChecks())
	for _, id := range []string{"upd_reboot_required", "upd_kernel_mismatch", "upd_stale", "upd_eol_release"} {
		if m[id].Status != model.AuditWarn {
			t.Fatal(id, m[id])
		}
	}
	if m["upd_stale"].Severity != model.RiskHigh || m["upd_unattended"].Status != model.AuditPass {
		t.Fatal(m)
	}
	putHardening(t, root, "etc/apt/apt.conf", `APT::Periodic::Unattended-Upgrade "0";`)
	if enabled, known := a.autoUpgrades(); enabled || !known {
		t.Fatal(enabled, known)
	}
	putHardening(t, root, "etc/apt/apt.conf", `APT::Periodic::Unattended-Upgrade "always";`)
	if enabled, known := a.autoUpgrades(); !enabled || !known {
		t.Fatal(enabled, known)
	}
	for _, invalid := range []string{`#include "/tmp/config";`, `APT::Periodic { Unattended-Upgrade "1"; };`, `APT::Periodic::Unattended-Upgrade "bad";`} {
		putHardening(t, root, "etc/apt/apt.conf", invalid)
		if _, known := a.autoUpgrades(); known {
			t.Fatal(invalid)
		}
	}
	future := now.Add(time.Hour)
	os.Chtimes(filepath.Join(root, "var/lib/apt/periodic/update-success-stamp"), future, future)
	if c := checksByID(a.updateChecks())["upd_stale"]; c.Status != model.AuditUnknown {
		t.Fatal(c)
	}
	putHardening(t, root, "usr/lib/os-release", "ID=unknown\nVERSION_ID=99\n")
	if a.releaseSupport().Status != model.AuditUnknown {
		t.Fatal("unsupported table version clean")
	}
}
func TestFirewallSavedPolicyAndUnknownTables(t *testing.T) {
	root := t.TempDir()
	proc := t.TempDir()
	a := &auditor{opt: Options{HostRoot: root, ProcRoot: proc}}
	if c := checksByID(a.firewallChecks())["fw_ufw_state"]; c.Status != model.AuditUnknown {
		t.Fatal(c)
	}
	putHardening(t, root, "etc/ufw/ufw.conf", "ENABLED=yes\n")
	putHardening(t, root, "etc/default/ufw", "DEFAULT_INPUT_POLICY=DROP\n")
	a.opt.Exposure = &model.ExposureReport{Entries: []model.Exposure{{Scope: model.ScopePublic, Port: 22}}}
	if c := checksByID(a.firewallChecks())["fw_ufw_state"]; c.Status != model.AuditPass {
		t.Fatal(c)
	}
	putHardening(t, root, "etc/default/ufw", "DEFAULT_INPUT_POLICY=ACCEPT\n")
	if c := checksByID(a.firewallChecks())["fw_ufw_state"]; c.Status != model.AuditWarn {
		t.Fatal(c)
	}
	putHardening(t, root, "etc/ufw/ufw.conf", "ENABLED=no\n")
	if c := checksByID(a.firewallChecks())["fw_ufw_state"]; c.Status != model.AuditWarn {
		t.Fatal(c)
	}
	putHardening(t, root, "etc/nftables.conf", "table inet filter {}\n")
	putHardening(t, root, "usr/lib/systemd/system/nftables.service", "[Service]\n")
	os.MkdirAll(filepath.Join(root, "etc/systemd/system/multi-user.target.wants"), 0700)
	os.Symlink("/usr/lib/systemd/system/nftables.service", filepath.Join(root, "etc/systemd/system/multi-user.target.wants/nftables.service"))
	m := checksByID(a.firewallChecks())
	if m["fw_nft_present"].Status != model.AuditInfo || m["fw_none"].Status != model.AuditPass {
		t.Fatal(m)
	}
	a.opt.Exposure.Incomplete = true
	if c := checksByID(a.firewallChecks())["fw_ufw_state"]; c.Status != model.AuditUnknown {
		t.Fatal(c)
	}
}

func FuzzKernelVersion(f *testing.F) {
	f.Add("6.8.0-101-generic", "6.8.0-99-generic")
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 4096 || len(b) > 4096 {
			t.Skip()
		}
		ab, ok1 := KernelNewer(a, b)
		ba, ok2 := KernelNewer(b, a)
		if ok1 != ok2 || (ab && ba) {
			t.Fatalf("inconsistent ordering: %q %q", a, b)
		}
	})
}

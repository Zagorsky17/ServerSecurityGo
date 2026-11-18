package audit

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

var hardeningSysctls = []sysctlRule{
	{id: "kern_aslr", name: "kernel/randomize_va_space", want: 2, op: opEq, sev: model.RiskHigh, bad: model.AuditFail, optional: false, title: "audit.kern_aslr.title", rec: "audit.hardening.rec"},
	{id: "kern_kptr", name: "kernel/kptr_restrict", want: 1, op: opMin, sev: model.RiskLow, bad: model.AuditWarn, optional: false, title: "audit.kern_kptr.title", rec: "audit.hardening.rec"},
	{id: "kern_dmesg", name: "kernel/dmesg_restrict", want: 1, op: opEq, sev: model.RiskLow, bad: model.AuditWarn, optional: false, title: "audit.kern_dmesg.title", rec: "audit.hardening.rec"},
	{id: "kern_ptrace", name: "kernel/yama/ptrace_scope", want: 1, op: opMin, sev: model.RiskMedium, bad: model.AuditWarn, optional: true, title: "audit.kern_ptrace.title", rec: "audit.hardening.rec"},
	{id: "kern_bpf", name: "kernel/unprivileged_bpf_disabled", want: 1, op: opMin, sev: model.RiskMedium, bad: model.AuditWarn, optional: true, title: "audit.kern_bpf.title", rec: "audit.hardening.rec"},
	{id: "kern_protected_symlinks", name: "fs/protected_symlinks", want: 1, op: opEq, sev: model.RiskMedium, bad: model.AuditWarn, optional: false, title: "audit.kern_protected_symlinks.title", rec: "audit.hardening.rec"},
	{id: "kern_protected_hardlinks", name: "fs/protected_hardlinks", want: 1, op: opEq, sev: model.RiskMedium, bad: model.AuditWarn, optional: false, title: "audit.kern_protected_hardlinks.title", rec: "audit.hardening.rec"},
	{id: "kern_protected_fifos", name: "fs/protected_fifos", want: 1, op: opMin, sev: model.RiskLow, bad: model.AuditWarn, optional: false, title: "audit.kern_protected_fifos.title", rec: "audit.hardening.rec"},
	{id: "kern_protected_regular", name: "fs/protected_regular", want: 1, op: opMin, sev: model.RiskLow, bad: model.AuditWarn, optional: false, title: "audit.kern_protected_regular.title", rec: "audit.hardening.rec"},
	{id: "kern_suid_dumpable", name: "fs/suid_dumpable", want: 0, op: opEq, sev: model.RiskMedium, bad: model.AuditWarn, optional: false, title: "audit.kern_suid_dumpable.title", rec: "audit.hardening.rec"},
	{id: "net_accept_redirects", name: "net/ipv4/conf/all/accept_redirects", want: 0, op: opEq, sev: model.RiskLow, bad: model.AuditWarn, optional: false, title: "audit.net_accept_redirects.title", rec: "audit.hardening.rec"},
	{id: "net_send_redirects", name: "net/ipv4/conf/all/send_redirects", want: 0, op: opEq, sev: model.RiskLow, bad: model.AuditWarn, optional: false, title: "audit.net_send_redirects.title", rec: "audit.hardening.rec"},
	{id: "net_source_route", name: "net/ipv4/conf/all/accept_source_route", want: 0, op: opEq, sev: model.RiskLow, bad: model.AuditWarn, optional: false, title: "audit.net_source_route.title", rec: "audit.hardening.rec"},
	{id: "net_rp_filter", name: "net/ipv4/conf/all/rp_filter", want: 1, op: opMin, sev: model.RiskLow, bad: model.AuditWarn, optional: false, title: "audit.net_rp_filter.title", rec: "audit.hardening.rec"},
}

func (a *auditor) hardeningKernel() []model.AuditCheck {
	var out []model.AuditCheck
	for _, r := range hardeningSysctls {
		c := a.sysctlCheck(r)
		if r.id == "net_rp_filter" {
			if v, e := a.sysctl(r.name); e == nil && (v < 0 || v > 2) {
				c.Status = model.AuditUnknown
			}
		}
		out = append(out, c)
	}
	for _, p := range []struct{ id, path string }{
		{"kern_userns", "kernel/unprivileged_userns_clone"}, {"kern_modules_disabled", "kernel/modules_disabled"}, {"net_ip_forward", "net/ipv4/ip_forward"}, {"kern_tainted", "kernel/tainted"}, {"kern_sysrq", "kernel/sysrq"},
	} {
		c := newCheck(p.id, model.AuditGroupKernel, model.RiskInfo, "audit.kernel_inventory.title")
		val, e := a.sysctl(p.path)
		if p.id == "kern_userns" && os.IsNotExist(e) {
			p.path = "user/max_user_namespaces"
			val, e = a.sysctl(p.path)
		}
		c.Status = model.AuditInfo
		if e != nil {
			c.Status = model.AuditUnknown
			addEv(&c, i18n.T("ev.audit_no_access", "/proc/sys/"+p.path))
		} else {
			addEv(&c, i18n.L(p.path+" = "+strconv.Itoa(val)))
		}
		if p.id == "kern_sysrq" && e == nil && val != 0 && val != 176 {
			c.Status = model.AuditWarn
			c.Severity = model.RiskLow
		}
		c.Recommendation = i18n.T("audit.kernel_inventory.rec")
		out = append(out, c)
	}
	c := newCheck("kern_core_pattern", model.AuditGroupKernel, model.RiskHigh, "audit.kern_core_pattern.title", "T1546")
	data, _, e := safefile.ReadRegular(filepath.Join(a.opt.ProcRoot, "sys/kernel/core_pattern"), maxSysctl, true)
	if e != nil {
		c.Status = model.AuditUnknown
	} else {
		value := strings.TrimSpace(string(data))
		addEv(&c, i18n.L("kernel.core_pattern = "+value))
		command := strings.TrimSpace(strings.TrimPrefix(value, "|"))
		fields := strings.Fields(command)
		if len(fields) == 0 {
			c.Status = model.AuditUnknown
		} else if strings.HasPrefix(value, "|") {
			fields[0] = path.Clean(fields[0])
			if !strings.HasPrefix(fields[0], "/usr/lib/") && !strings.HasPrefix(fields[0], "/usr/share/") && !strings.HasPrefix(fields[0], "/usr/libexec/") {
				c.Status = model.AuditFail
			} else {
				c.Status = model.AuditInfo
			}
		} else if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "/var/lib/") && !strings.HasPrefix(value, "/var/crash/") {
			c.Status = model.AuditWarn
		}
	}
	c.Recommendation = i18n.T("audit.kern_core_pattern.rec")
	return append(out, c)
}

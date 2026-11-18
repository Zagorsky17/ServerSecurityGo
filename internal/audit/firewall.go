package audit

import (
	"os"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/exposure"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
	"github.com/Zagorsky17/ServerSecurityGo/internal/ufw"
)

func (a *auditor) firewallChecks() []model.AuditCheck {
	u := ufw.Read(a.opt.HostRoot)
	exp := a.opt.Exposure
	socketsKnown := exp != nil && len(exp.Warnings) == 0 && !exp.Incomplete
	if exp == nil {
		socketsKnown = true
		socketsKnown = procfs.NetTablesComplete(a.opt.ProcRoot)
		fs := procfs.New(a.opt.ProcRoot, a.opt.HostRoot)
		sockets, dropped := fs.ReadNetTables(0, "")
		if dropped > 0 {
			socketsKnown = false
		}
		exp = exposure.Build(exposure.Input{HostRoot: a.opt.HostRoot, Sockets: sockets})
	}
	public := false
	for _, entry := range exp.Entries {
		if entry.Scope == model.ScopePublic {
			public = true
		}
	}
	c := newCheck("fw_ufw_state", model.AuditGroupFirewall, model.RiskMedium, "audit.fw_ufw_state.title")
	c.Recommendation = i18n.T("audit.firewall.rec")
	policy := ""
	for _, s := range u.Settings {
		if s.Key == "DEFAULT_INPUT_POLICY" {
			policy = s.Value.In(i18n.EN)
		}
	}
	addEv(&c, i18n.L("UFW="+u.State+" DEFAULT_INPUT_POLICY="+policy))
	switch u.State {
	case "enabled":
		if policy != "DROP" && policy != "REJECT" {
			if policy == "ACCEPT" {
				c.Status = model.AuditWarn
			} else {
				c.Status = model.AuditUnknown
			}
		}
	case "disabled", "absent":
		c.Status = model.AuditInfo
		if !socketsKnown {
			c.Status = model.AuditUnknown
		} else if public {
			c.Status = model.AuditWarn
		}
	default:
		c.Status = model.AuditUnknown
	}
	out := []model.AuditCheck{c}
	c = newCheck("fw_nft_present", model.AuditGroupFirewall, model.RiskInfo, "audit.fw_nft_present.title")
	c.Status = model.AuditInfo
	c.Recommendation = i18n.T("audit.firewall.rec")
	nft, err := a.readHost("etc/nftables.conf")
	nftPresent := err == nil && len(strings.TrimSpace(string(nft))) > 0
	enabled := false
	root, e := os.OpenRoot(a.opt.HostRoot)
	if e == nil {
		p, e := safefile.ResolveRooted(root, "etc/systemd/system/multi-user.target.wants/nftables.service")
		if e == nil {
			fi, e := root.Lstat(p)
			enabled = e == nil && fi.Mode().IsRegular()
		}
		root.Close()
	}
	if err != nil && !os.IsNotExist(err) {
		c.Status = model.AuditUnknown
	}
	addEv(&c, i18n.L("nftables.conf="+boolText(nftPresent)+" enabled symlink="+boolText(enabled)))
	out = append(out, c)
	c = newCheck("fw_none", model.AuditGroupFirewall, model.RiskMedium, "audit.fw_none.title")
	iptables := false
	unknown := u.State == "unknown" || (err != nil && !os.IsNotExist(err))
	for _, p := range []string{"etc/iptables/rules.v4", "etc/iptables/rules.v6"} {
		b, e := a.readHost(p)
		if e == nil && len(strings.TrimSpace(string(b))) > 0 {
			iptables = true
		}
		if e != nil && !os.IsNotExist(e) {
			unknown = true
		}
	}
	if u.State != "enabled" && !(nftPresent && enabled) && !iptables {
		if unknown {
			c.Status = model.AuditUnknown
		} else {
			c.Status = model.AuditWarn
		}
	}
	c.Recommendation = i18n.T("audit.firewall.rec")
	out = append(out, c)
	c = newCheck("fw_docker_bypass", model.AuditGroupFirewall, model.RiskHigh, "audit.fw_docker_bypass.title")
	if !socketsKnown {
		c.Status = model.AuditUnknown
	}
	for _, f := range exposure.SystemFindings(exp) {
		if f.ID == "fw_docker_bypass" {
			c.Status = model.AuditWarn
			for _, ev := range f.Evidence {
				addEv(&c, ev)
			}
		}
	}
	c.Recommendation = i18n.T("audit.firewall.rec")
	return append(out, c)
}
func boolText(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

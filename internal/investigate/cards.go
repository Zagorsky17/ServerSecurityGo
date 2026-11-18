package investigate

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
)

func contextFor(id, category, path string) model.FindingContext {
	c := model.FindingContext{Why: i18n.T("card.why.general"), Legitimate: i18n.T("card.legitimate.general"), Confidence: i18n.T("card.confidence.general")}
	switch category {
	case model.CatLocation, model.CatIntegrity:
		c.Why = i18n.T("card.why.file")
		c.Legitimate = i18n.T("card.legitimate.file")
	case model.CatMasquerade:
		c.Why = i18n.T("card.why.name")
		c.Legitimate = i18n.T("card.legitimate.name")
	case model.CatPersistence:
		c.Why = i18n.T("card.why.persistence")
		c.Legitimate = i18n.T("card.legitimate.persistence")
	case model.CatNetwork:
		c.Why = i18n.T("card.why.network")
		c.Legitimate = i18n.T("card.legitimate.network")
	case model.CatBehavior:
		c.Why = i18n.T("card.why.load")
		c.Legitimate = i18n.T("card.legitimate.load")
	case model.CatChain, model.CatContent:
		c.Why = i18n.T("card.why.execution")
		c.Legitimate = i18n.T("card.legitimate.execution")
	case model.CatPrivilege, model.CatEnvironment:
		c.Why = i18n.T("card.why.privilege")
		c.Legitimate = i18n.T("card.legitimate.privilege")
	case model.CatInfo:
		c.Why = i18n.T("card.why.info")
	}
	switch id {
	case "new_public_listener":
		c.ReviewFirst = true
		c.Why = i18n.T("card.why.new_listener")
		c.Confidence = i18n.T("card.confidence.new_listener")
	case "fs_privilege_new":
		c.ReviewFirst = true
		c.Why = i18n.T("card.why.new_privilege")
		c.Confidence = i18n.T("card.confidence.new_privilege")
	case "kern_core_pattern":
		c.Attack = []string{"T1546"}
	case "acct_uid0_extra", "acct_new":
		c.Attack = []string{"T1136.001"}
	case "acct_empty_password":
		c.Attack = []string{"T1078"}
	case "acct_priv_groups":
		c.Attack = []string{"T1098"}
	case "fw_ssh_ratelimit", "ssh_root_login", "ssh_password_auth", "ssh_empty_passwords", "ssh_kbd_interactive":
		c.Attack = []string{"T1110"}
	case "ssh_authkeys_file":
		c.Attack = []string{"T1098.004"}
	case "sudo_nopasswd_all", "sudo_no_auth", "sudo_gtfobins", "sudo_writable_cmd", "sudo_changed":
		c.Attack = []string{"T1548.003"}
	case "sudo_env_keep":
		c.Attack = []string{"T1574.006"}

	case "bpf_unexpected":
		c.Attack = []string{"T1014"}
	case "raw_packet_socket", "iface_promisc":
		c.Attack = []string{"T1040"}
	case "webshell_pattern":
		c.Attack = []string{"T1505.003"}
	case "exe_packed":
		c.Attack = []string{"T1027.002"}
	case "exe_in_temp":
		c.Attack = []string{"T1036.005"}
	case "exe_hidden_path":
		c.Attack = []string{"T1564.001"}
	case "exe_deleted":
		c.Attack = []string{"T1070.004"}
	case "exe_memfd":
		c.Attack = []string{"T1620"}
	case "kthread_masquerade", "system_name_masquerade", "name_mismatch":
		c.Attack = []string{"T1036.004"}
	case "web_spawns_shell":
		c.Attack = []string{"T1505.003", "T1059.004"}
	case "stdio_socket", "revshell_pattern", "shell_network":
		c.Attack = []string{"T1059.004"}
	case "pool_port", "miner_pattern", "miner_name", "cpu_sustained":
		c.Attack = []string{"T1496"}
	case "download_exec":
		c.Attack = []string{"T1105"}
	case "ld_preload", "ld_so_preload":
		c.Attack = []string{"T1574.006"}
	case "ssh_key_command", "ssh_keys_recent":
		c.Attack = []string{"T1098.004"}
		if id == "ssh_keys_recent" {
			c.ReviewFirst = true
			c.Why = i18n.T("card.why.recent_keys")
			c.Confidence = i18n.T("card.confidence.recent_keys")
		}
	case "exe_setuid_nonstd", "fs_suid_unusual":
		c.Attack = []string{"T1548.001"}
	case "unicode_control":
		c.Attack = []string{"T1036"}
	}
	if strings.HasPrefix(id, "autostart_") || id == "scheduler_suspicious" {
		switch {
		case strings.Contains(path, "/cron"), strings.Contains(path, "/crontab"):
			c.Attack = []string{"T1053.003"}
		case strings.Contains(path, "/systemd/"):
			c.Attack = []string{"T1543.002"}
		}
	}
	return c
}

// Process events never join by PID or executable alone: the PID may have been reused.
func indexEvents(events []model.Event) map[string][]model.Event {
	idx := map[string][]model.Event{}
	add := func(k string, e model.Event) {
		if len(idx[k]) < 8 {
			idx[k] = append(idx[k], e)
		}
	}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Key != "" {
			add("key:"+e.Key, e)
		}
		if e.Exe != "" {
			add("path:"+e.Exe, e)
		}
		if e.Type == model.EvAudit && e.Name != "" {
			add("audit:"+e.Name, e)
		}
	}
	return idx
}

func AttachAudit(checks []model.AuditCheck, events []model.Event) {
	idx := indexEvents(events)
	for i := range checks {
		c := &checks[i]
		c.FindingContext = model.FindingContext{Why: i18n.T("card.why.audit"), Legitimate: i18n.T("card.legitimate.audit"), Confidence: i18n.T("card.confidence.audit"), RelatedEvents: idx["audit:"+c.ID]}
		for _, ref := range c.References {
			if validTechnique(ref) {
				c.Attack = append(c.Attack, ref)
			}
		}
		c.VerifyCommands = []string{"serversecuritygo audit --all --format json"}
	}
}
func validTechnique(s string) bool {
	if len(s) != 5 && len(s) != 9 || s[0] != 'T' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if i == 5 {
			if s[i] != '.' {
				return false
			}
		} else if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

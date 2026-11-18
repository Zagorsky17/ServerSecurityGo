package investigate

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
)

// Explain читает только каталог: значения параметров берутся из конкретного отчёта.
func Explain(id string) (model.Finding, error) {
	f := model.Finding{ID: id}
	prefix := "rule." + id
	title := prefix + ".title"
	if i18n.Has("audit." + id + ".title") {
		prefix = "audit." + id
		title = prefix + ".title"
	}
	if alias := explanationTitles[id]; alias != "" {
		title = alias
	}
	if !i18n.Has(title) {
		return f, i18n.Errorf("err.explain_unknown", id)
	}
	f.Title = i18n.T(title)
	f.Category = explanationCategories[id]
	f.FindingContext = contextFor(id, f.Category, "")
	rec := prefix + ".rec"
	switch {
	case strings.HasPrefix(id, "fs_") && title == "rule.fs_observation.title":
		rec = "rec.fs_review"
	case strings.HasPrefix(title, "audit."):
		f.Why = i18n.T("card.why.audit")
		f.Legitimate = i18n.T("card.legitimate.audit")
		if !i18n.Has(rec) && (strings.HasPrefix(id, "kern_") || strings.HasPrefix(id, "net_")) {
			rec = "audit.hardening.rec"
		}
	}
	if i18n.Has(rec) {
		f.Recommendation = i18n.T(rec)
	}
	f.VerifyCommands = Commands(id, 0, "")
	if strings.HasPrefix(title, "audit.") {
		f.VerifyCommands = []string{"serversecuritygo audit --all --format json"}
	}
	return f, nil
}

var explanationTitles = map[string]string{
	"advanced_process_pending": "warn.advanced_process_pending", "promisc_unavailable": "warn.promisc_unavailable",
	"fs_world_writable_system": "rule.fs_observation.title", "fs_unowned": "rule.fs_observation.title", "fs_suid_inventory": "rule.fs_observation.title", "fs_suid_unusual": "rule.fs_observation.title", "fs_capabilities": "rule.fs_observation.title", "fs_privilege_new": "rule.fs_observation.title",
	"fs_inventory_pending": "warn.fs_pending", "fs_inventory_unavailable": "warn.fs_incomplete", "advanced_pending": "warn.advanced_pending", "advanced_unavailable": "warn.advanced_incomplete", "packet_inventory_unavailable": "warn.packet_incomplete", "ports_baseline_unavailable": "warn.baseline_ports",
	"kern_userns": "audit.kernel_inventory.title", "kern_modules_disabled": "audit.kernel_inventory.title", "net_ip_forward": "audit.kernel_inventory.title", "kern_tainted": "audit.kernel_inventory.title", "kern_sysrq": "audit.kernel_inventory.title",
}

var explanationCategories = map[string]string{
	"bpf_unexpected": model.CatPrivilege, "raw_packet_socket": model.CatNetwork, "exe_packed": model.CatIntegrity, "exe_static_in_temp": model.CatIntegrity,
	"advanced_pending":              model.CatInfo,
	"autostart_suspicious":          model.CatPersistence,
	"cmdline_truncated":             model.CatMasquerade,
	"cpu_sustained":                 model.CatBehavior,
	"cwd_in_temp":                   model.CatLocation,
	"download_exec":                 model.CatContent,
	"empty_cmdline":                 model.CatMasquerade,
	"exe_deleted":                   model.CatIntegrity,
	"exe_hidden_path":               model.CatLocation,
	"exe_in_temp":                   model.CatLocation,
	"exe_memfd":                     model.CatIntegrity,
	"exe_setuid_nonstd":             model.CatIntegrity,
	"exe_system_nonroot":            model.CatIntegrity,
	"exe_world_writable":            model.CatIntegrity,
	"fail2ban_log_unavailable":      model.CatInfo,
	"fail2ban_not_running":          model.CatExposure,
	"fail2ban_sshd_disabled":        model.CatExposure,
	"fs_capabilities":               model.CatPrivilege,
	"fs_inventory_pending":          model.CatInfo,
	"fs_privilege_new":              model.CatPrivilege,
	"fs_suid_inventory":             model.CatPrivilege,
	"fs_suid_unusual":               model.CatPrivilege,
	"fs_unowned":                    model.CatPrivilege,
	"fs_world_writable_system":      model.CatPrivilege,
	"iface_promisc":                 model.CatNetwork,
	"info_access":                   model.CatInfo,
	"info_container":                model.CatInfo,
	"info_listen":                   model.CatInfo,
	"kthread_masquerade":            model.CatMasquerade,
	"ld_preload":                    model.CatEnvironment,
	"ld_so_preload":                 model.CatPersistence,
	"mem_sustained":                 model.CatBehavior,
	"miner_name":                    model.CatMasquerade,
	"miner_pattern":                 model.CatContent,
	"name_mismatch":                 model.CatMasquerade,
	"new_public_listener":           model.CatNetwork,
	"package_ownership_unavailable": model.CatInfo,
	"pool_port":                     model.CatNetwork,
	"ports_baseline_unavailable":    model.CatInfo,
	"revshell_pattern":              model.CatContent,
	"root_from_writable":            model.CatPrivilege,
	"scheduler_suspicious":          model.CatPersistence,
	"shell_network":                 model.CatNetwork,
	"ssh_key_command":               model.CatPersistence,
	"ssh_keys_not_regular":          model.CatPersistence,
	"ssh_keys_recent":               model.CatPersistence,
	"stdio_socket":                  model.CatNetwork,
	"suspicious_listen":             model.CatNetwork,
	"system_name_masquerade":        model.CatMasquerade,
	"unicode_control":               model.CatMasquerade,
	"unusual_name":                  model.CatMasquerade,
	"web_spawns_shell":              model.CatChain,
	"webshell_pattern":              model.CatContent,
}

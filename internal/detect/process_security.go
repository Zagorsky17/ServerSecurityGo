package detect

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
)

// Фиксированные ключи также проверяются тестом полноты переводов.
var securityMessages = map[string][2]string{
	"ptrace_attached":      {"rule.ptrace_attached.title", "rule.ptrace_attached.rec"},
	"lib_from_temp":        {"rule.lib_from_temp.title", "rule.lib_from_temp.rec"},
	"lib_deleted":          {"rule.lib_deleted.title", "rule.lib_deleted.rec"},
	"anon_exec_memory":     {"rule.anon_exec_memory.title", "rule.anon_exec_memory.rec"},
	"history_disabled":     {"rule.history_disabled.title", "rule.history_disabled.rec"},
	"prompt_command_net":   {"rule.prompt_command_net.title", "rule.prompt_command_net.rec"},
	"ld_library_path_temp": {"rule.ld_library_path_temp.title", "rule.ld_library_path_temp.rec"},
	"proc_dangerous_caps":  {"rule.proc_dangerous_caps.title", "rule.proc_dangerous_caps.rec"},
	"proc_ambient_caps":    {"rule.proc_ambient_caps.title", "rule.proc_ambient_caps.rec"},
}

func securityFinding(id string, cat string, weight int, strong bool, facts ...string) model.Finding {
	keys := securityMessages[id]
	return model.Finding{ID: id, Title: i18n.T(keys[0]), Category: cat, Weight: weight, Strong: strong, Evidence: i18n.Ls(facts), Recommendation: i18n.T(keys[1])}
}

func ruleProcessSecurity(p *model.Process, c *Context) []model.Finding {
	if skipUserRules(p) {
		return nil
	}
	var out []model.Finding
	if s := p.Security; s != nil {
		if s.TracerPID > 0 {
			weight, strong := 25, false
			facts := []string{fmt.Sprintf("TracerPid=%d", s.TracerPID)}
			t := c.ByPID[s.TracerPID]
			if t != nil && t.Key == s.TracerKey && s.TracerKey != "" {
				facts = append(facts, fmt.Sprintf("%s: %s (uid=%d)", t.Key, t.Exe, t.UID))
				strong = t.Exe == "" || inTemp(t.Exe) || t.ExeDeleted
				trusted := hasAnyPrefix(t.Exe, distroDirs) && !strong
				if trusted && set("gdb", "strace", "ltrace", "lldb", "perf")[progName(t)] && t.UID == p.UID && !set("sshd", "sudo", "chrome", "chromium", "firefox")[progName(p)] {
					weight = 3
				}
			}
			f := securityFinding("ptrace_attached", model.CatIntegrity, weight, strong, facts...)
			if t == nil || t.Key != s.TracerKey || s.TracerKey == "" {
				f.Evidence = append(f.Evidence, i18n.T("ev.tracer_unavailable"))
			}
			out = append(out, f)
		}
		var dangerous []string
		for _, cap := range s.CapEff {
			if set("CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_SETUID")[cap] {
				dangerous = append(dangerous, cap)
			}
		}
		if p.EUID != 0 && len(dangerous) > 0 {
			weight := 25
			if hasAnyPrefix(p.Exe, distroDirs) && (strings.HasPrefix(progName(p), "systemd-") || progName(p) == "dbus-daemon") {
				weight = 5
			}
			out = append(out, securityFinding("proc_dangerous_caps", model.CatPrivilege, weight, false, dangerous...))
		}
		if isShell(p) && len(s.CapAmb) > 0 {
			out = append(out, securityFinding("proc_ambient_caps", model.CatPrivilege, 20, false, s.CapAmb...))
		}
	}
	flags := slices.Clone(p.EnvFlags)
	if isShell(p) && unsetHistory.MatchString(cmdText(p)) {
		flags = append(flags, "history_disabled")
	}
	for _, id := range []string{"history_disabled", "prompt_command_net", "ld_library_path_temp"} {
		if !slices.Contains(flags, id) {
			continue
		}
		weight := 15
		if id == "prompt_command_net" {
			weight = 30
		}
		out = append(out, securityFinding(id, model.CatEnvironment, weight, false))
	}
	temp, deleted := []string{}, []string{}
	anon, upgrade := false, true
	for _, m := range p.Maps {
		if m.Path == "" {
			anon = true
			continue
		}
		base := filepath.Base(m.Path)
		if !strings.Contains(base, ".so") {
			continue
		}
		if (procfs.UnsafeLibraryPath(m.Path) || (p.EUID == 0 && knownDaemons[progName(p)] && (strings.HasPrefix(m.Path, "/home/") || strings.HasPrefix(m.Path, "/root/")))) && len(temp) < 8 {
			temp = append(temp, m.Path)
		}
		if m.Deleted {
			if len(deleted) < 8 {
				deleted = append(deleted, m.Path)
			}
			// База хоста не доказывает принадлежность библиотеки контейнера.
			if !m.Replacement || !c.Owners[m.Path] || p.Container != "" || slices.Contains(p.ForeignNS, "mnt") {
				upgrade = false
			}
		}
	}
	if len(temp) > 0 {
		out = append(out, securityFinding("lib_from_temp", model.CatLocation, 25, true, temp...))
	}
	if len(deleted) > 0 {
		weight := 20
		if upgrade {
			weight = 3
		}
		f := securityFinding("lib_deleted", model.CatIntegrity, weight, false, deleted...)
		if upgrade {
			f.Evidence = append(f.Evidence, i18n.T("ev.library_upgrade"))
		}
		out = append(out, f)
	}
	if anon {
		weight := 20
		name := progName(p)
		if hasAnyPrefix(p.Exe, systemDirs) && (set("java", "node", "nodejs", "dotnet", "chrome", "chromium", "chromium-browser", "firefox", "firefox-bin", "pypy", "pypy3", "php")[name] || strings.HasPrefix(name, "qemu-") || (strings.HasPrefix(name, "python") && slices.Contains(p.EnvFlags, "PYTHON_JIT"))) {
			weight = 3
		}
		out = append(out, securityFinding("anon_exec_memory", model.CatIntegrity, weight, false))
	}
	return out
}

var unsetHistory = regexp.MustCompile(`(^|[;&|\s])unset\s+(-[a-zA-Z]+\s+)?HISTFILE([;&|\s]|$)`)

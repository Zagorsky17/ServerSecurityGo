package detect

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"testing"
)

func securityByID(p *model.Process, c *Context) map[string]model.Finding {
	out := map[string]model.Finding{}
	for _, f := range ruleProcessSecurity(p, c) {
		out[f.ID] = f
	}
	return out
}
func TestProcessSecurityRules(t *testing.T) {
	p := &model.Process{PID: 10, Name: "bash", Exe: "/usr/bin/bash", UID: 1000, EUID: 1000, EnvFlags: []string{"history_disabled", "prompt_command_net", "ld_library_path_temp"}, Security: &model.ProcessSecurity{TracerPID: 20, TracerKey: "20-100", CapEff: []string{"CAP_SYS_ADMIN"}, CapAmb: []string{"CAP_SETUID"}}, Maps: []model.MemoryMap{{Path: "/tmp/x.so", Perms: "r-xp", Deleted: true}, {Perms: "rwxp"}}}
	tracer := &model.Process{PID: 20, Key: "20-100", Exe: "/tmp/injector", UID: 0}
	c := &Context{ByPID: map[int]*model.Process{20: tracer}}
	got := securityByID(p, c)
	for _, id := range []string{"ptrace_attached", "lib_from_temp", "lib_deleted", "anon_exec_memory", "history_disabled", "prompt_command_net", "ld_library_path_temp", "proc_dangerous_caps", "proc_ambient_caps"} {
		if got[id].ID == "" {
			t.Errorf("missing %s", id)
		}
	}
	if !got["ptrace_attached"].Strong || got["history_disabled"].Strong {
		t.Fatal("strength")
	}
	tracer.Exe = "/usr/bin/gdb"
	tracer.UID = 1000
	if f := securityByID(p, c)["ptrace_attached"]; f.Weight != 3 || f.Strong {
		t.Fatalf("debugger %+v", f)
	}
	tracer.Key = "20-101"
	tracer.Exe = "/tmp/reused"
	if f := securityByID(p, c)["ptrace_attached"]; f.Strong || len(f.Evidence) != 2 {
		t.Fatalf("PID reuse %+v", f)
	}
}
func TestSecurityBenignCases(t *testing.T) {
	p := &model.Process{Name: "java", Exe: "/usr/bin/java", UID: 1000, EUID: 1000, Maps: []model.MemoryMap{{Perms: "rwxp"}, {Path: "/usr/lib/libc.so.6", Perms: "r-xp", Deleted: true, Replacement: true}}}
	c := &Context{Owners: map[string]bool{"/usr/lib/libc.so.6": true}}
	got := securityByID(p, c)
	if got["anon_exec_memory"].Weight != 3 || got["lib_deleted"].Weight != 3 {
		t.Fatalf("%+v", got)
	}
	p.Container = "abcdef"
	if securityByID(p, c)["lib_deleted"].Weight != 20 {
		t.Fatal("host ownership applied to container")
	}
	p.Container = ""
	p.ForeignNS = []string{"mnt"}
	if securityByID(p, c)["lib_deleted"].Weight != 20 {
		t.Fatal("host ownership applied to foreign mount namespace")
	}
	p.Name = "systemd-resolved"
	p.Exe = "/usr/lib/systemd/systemd-resolved"
	p.Security = &model.ProcessSecurity{CapEff: []string{"CAP_DAC_OVERRIDE"}}
	if securityByID(p, c)["proc_dangerous_caps"].Weight != 5 {
		t.Fatal("systemd calibration")
	}
	p.EUID = 0
	if _, ok := securityByID(p, c)["proc_dangerous_caps"]; ok {
		t.Fatal("root advisory")
	}
	p.Kernel = true
	if len(securityByID(p, c)) != 0 {
		t.Fatal("kernel thread")
	}
}
func TestSecurityAllowlistAndContext(t *testing.T) {
	p := &model.Process{PID: 1, Name: "bash", Exe: "/usr/bin/bash", Args: []string{"bash", "-c", "unset HISTFILE"}}
	Analyze([]*model.Process{p}, &Context{})
	found := false
	for _, f := range p.Findings {
		if f.ID == "history_disabled" {
			found = true
		}
	}
	if !found {
		t.Fatal("unset HISTFILE")
	}
}

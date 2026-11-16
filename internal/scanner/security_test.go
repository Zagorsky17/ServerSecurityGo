package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityPipelineAndBudgets(t *testing.T) {
	sc, _, root := newDemoScanner(t)
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	status, err := os.ReadFile(filepath.Join(root, "3202/status"))
	if err != nil {
		t.Fatal(err)
	}
	write("3202/status", string(status)+"TracerPid:\t3301\nCapEff:\t0000000000200000\nCapAmb:\t0000000000000080\nSeccomp:\t2\nNoNewPrivs:\t1\n")
	write("3202/maps", "1000-2000 r-xp 0 00:00 0 /tmp/evil.so (deleted)\n2000-3000 rwxp 0 00:00 0\n")
	write("3202/environ", "HISTFILE=/dev/null\x00PROMPT_COMMAND=curl SECRET_SENTINEL\x00")
	snap, err := sc.ScanOnce()
	if err != nil {
		t.Fatal(err)
	}
	p := byPID(snap, 3202)
	ids := map[string]bool{}
	for _, f := range p.Findings {
		ids[f.ID] = true
	}
	for _, id := range []string{"ptrace_attached", "lib_from_temp", "lib_deleted", "anon_exec_memory", "history_disabled", "prompt_command_net", "proc_ambient_caps"} {
		if !ids[id] {
			t.Errorf("missing %s %v", id, ids)
		}
	}
	if p.Security.TracerKey != byPID(snap, 3301).Key {
		t.Fatal("tracer generation")
	}
	b, _ := json.Marshal(snap)
	if strings.Contains(string(b), "SECRET_SENTINEL") {
		t.Fatal("secret in snapshot")
	}
	oldMaps, oldEnv := scanMapsBudget, scanEnvBudget
	scanMapsBudget = 0
	scanEnvBudget = 0
	t.Cleanup(func() { scanMapsBudget = oldMaps; scanEnvBudget = oldEnv })
	snap, err = sc.ScanOnce()
	if err != nil {
		t.Fatal(err)
	}
	p = byPID(snap, 3202)
	if len(p.Maps) != 0 || len(p.EnvFlags) != 0 || !strings.Contains(fmt.Sprint(p.Access), "maps:budget") || !strings.Contains(fmt.Sprint(p.Access), "environ:budget") {
		t.Fatalf("budget %+v", p)
	}
}

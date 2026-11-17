package main

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticsCLIReadOnlyAndValidation(t *testing.T) {
	root := t.TempDir()
	data := t.TempDir()
	t.Setenv("SSG_HOST_ROOT", root)
	t.Setenv("SSG_PROC_ROOT", "/proc")
	t.Setenv("SSG_DATA_DIR", data)
	out := filepath.Join(t.TempDir(), "explain.json")
	code, e := runDiagnostics("explain", []string{"exe_memfd", "--format", "json", "--output", out})
	if e != nil || code != 0 {
		t.Fatal(code, e)
	}
	b, _ := os.ReadFile(out)
	var f model.Finding
	if e := json.Unmarshal(b, &f); e != nil || f.ID != "exe_memfd" || len(f.Attack) != 1 {
		t.Fatal(f, e)
	}
	fi, _ := os.Stat(out)
	if fi.Mode().Perm() != 0600 {
		t.Fatal(fi.Mode())
	}
	for _, args := range [][]string{nil, {"unknown"}, {"exe_memfd", "--format", "sarif"}, {"exe_memfd", "extra"}} {
		if _, e = runDiagnostics("explain", args); e == nil {
			t.Fatal(args)
		}
	}
	for _, format := range []string{"text", "json", "sarif"} {
		code, e = runDiagnostics("doctor", []string{"--format", format, "--output", out})
		if e != nil || code != report.ExitIncomplete {
			t.Fatal(format, code, e)
		}
	}
	files, _ := os.ReadDir(data)
	if len(files) != 0 {
		t.Fatal("doctor mutated state")
	}
	for _, kind := range []string{"recent", "timeline", "collect"} {
		if _, e := runInvestigation(kind, []string{"--format", "sarif"}); e == nil {
			t.Fatal("discarded non-SARIF content", kind)
		}
	}
	code, e = runInvestigation("triage", []string{"--format", "sarif", "--output", out, "--fail-on", "none"})
	if e != nil || code != report.ExitIncomplete {
		t.Fatal(code, e)
	}
	b, _ = os.ReadFile(out)
	var v struct{ Version string }
	if e = json.Unmarshal(b, &v); e != nil || v.Version != "2.1.0" {
		t.Fatal(string(b), e)
	}
}

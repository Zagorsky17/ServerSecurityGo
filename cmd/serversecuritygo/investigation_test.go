package main

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
	"os"
	"path/filepath"
	"testing"
)

func TestInvestigationOfflineAndValidation(t *testing.T) {
	root := t.TempDir()
	data := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0700)
	os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0::/root:/bin/bash\n"), 0600)
	t.Setenv("SSG_HOST_ROOT", root)
	t.Setenv("SSG_PROC_ROOT", "/proc")
	t.Setenv("SSG_DATA_DIR", data)
	t.Setenv("SSG_ALLOWLIST_FILE", filepath.Join(root, "missing"))
	out := filepath.Join(t.TempDir(), "triage.json")
	code, e := runInvestigation("triage", []string{"--format", "json", "--output", out, "--fail-on", "none"})
	if e != nil || code != report.ExitIncomplete {
		t.Fatalf("%d %v", code, e)
	}
	b, _ := os.ReadFile(out)
	var r report.Investigation
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	if r.Snapshot == nil || len(r.Snapshot.Processes) != 0 || !r.Incomplete {
		t.Fatal("live host mixed into image")
	}
	files, _ := os.ReadDir(data)
	if len(files) != 0 {
		t.Fatal("one-shot command wrote service state")
	}
	for _, args := range [][]string{{"--days", "0"}, {"--since", "-1h"}, {"--since", "10000h"}, {"--format", "bogus"}, {"unexpected"}} {
		if _, e = runInvestigation("recent", args); e == nil {
			t.Fatal(args)
		}
	}
}

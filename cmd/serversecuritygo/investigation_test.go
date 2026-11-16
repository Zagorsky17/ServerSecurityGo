package main

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestInvestigationIncludesSelfCheckAndUFW(t *testing.T) {
	proc, host, err := fakeproc.Demo(time.Now()).Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	t.Setenv("SSG_HOST_ROOT", host)
	t.Setenv("SSG_PROC_ROOT", proc)
	t.Setenv("SSG_DATA_DIR", data)
	t.Setenv("SSG_ALLOWLIST_FILE", filepath.Join(host, "missing"))
	out := filepath.Join(t.TempDir(), "triage.json")
	code, err := runInvestigation("triage", []string{"--format", "json", "--output", out, "--fail-on", "none"})
	if err != nil || code != report.ExitIncomplete {
		t.Fatalf("%d %v", code, err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var r report.Investigation
	if err = json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Snapshot == nil || r.Snapshot.UFW == nil || r.Snapshot.Auth == nil {
		t.Fatal("combined investigation sources missing")
	}
	found := false
	for _, f := range r.Snapshot.System {
		found = found || f.ID == "self_check_unavailable"
	}
	if !found || !r.Incomplete {
		t.Fatal("missing baseline reported as verified")
	}
	files, err := os.ReadDir(data)
	if err != nil || len(files) != 0 {
		t.Fatal("one-shot command changed service state", err)
	}
}

package main

import (
	"encoding/json"
	"errors"
	"github.com/Zagorsky17/ServerSecurityGo/internal/baseline"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaselineCLIAndDiffReadOnly(t *testing.T) {
	tree := fakeproc.Demo(time.Now())
	tree.Procs = nil
	tree.Socks = nil
	proc, root, e := tree.Write(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "etc/machine-id"), []byte(strings.Repeat("a", 32)), 0600); e != nil {
		t.Fatal(e)
	}
	state := t.TempDir()
	out := filepath.Join(t.TempDir(), "report.json")
	t.Setenv("SSG_HOST_ROOT", root)
	t.Setenv("SSG_PROC_ROOT", proc)
	t.Setenv("SSG_DATA_DIR", state)
	t.Setenv("SSG_ALLOWLIST_FILE", filepath.Join(state, "absent"))
	t.Setenv("SSG_FS_SCAN_RATE", "100000")
	e = cmdBaseline("baseline", []string{"save", "--name", "before", "--format", "json", "--output", out})
	var status exitStatus
	if e != nil && (!errors.As(e, &status) || int(status) != 3) {
		t.Fatal(e)
	}
	s := baseline.New(state)
	b, e := s.Load("before")
	if e != nil || len(b.Sections) != 11 {
		t.Fatal(b, e)
	}
	if e = cmdBaseline("baseline", []string{"save", "--name", "before", "--output", out}); e == nil {
		t.Fatal("overwrite")
	}
	names, _ := s.List()
	if len(names) != 1 {
		t.Fatal(names)
	}
	e = cmdBaseline("diff", []string{"--from", "before", "--to", "before", "--format", "json", "--output", out})
	if e != nil && (!errors.As(e, &status) || int(status) != 3) {
		t.Fatal(e)
	}
	data, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	var d model.BaselineDiff
	if e = json.Unmarshal(data, &d); e != nil || len(d.Changes) != 0 {
		t.Fatal(d, e)
	}
	after, _ := s.List()
	if len(after) != len(names) {
		t.Fatal("diff wrote baseline")
	}
	for _, args := range [][]string{{"accept"}, {"save", "--ports"}, {"save", "--name", "../escape"}} {
		if e := cmdBaseline("baseline", args); e == nil {
			t.Fatal(args)
		}
	}
}

package advanced

import (
	"context"
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAdvancedHelperProcess(t *testing.T) {
	if os.Getenv("SSG_ADVANCED_HELPER") != "1" {
		return
	}
	fmt.Println("ready")
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestRealDeletedELF(t *testing.T) {
	// Собственный helper подтверждает готовность; системный sleep может быть обёрткой.
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(self)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "helper")
	if e = os.WriteFile(path, data, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-test.run=^TestAdvancedHelperProcess$")
	cmd.Env = append(os.Environ(), "SSG_ADVANCED_HELPER=1")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	ready := make([]byte, 6)
	if _, e = io.ReadFull(stdout, ready); e != nil || string(ready) != "ready\n" {
		t.Fatalf("helper readiness: %q %v", ready, e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	fs := procfs.New("/proc", "/")
	raw, e := fs.ReadProcess(cmd.Process.Pid, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if !raw.Proc.ExeDeleted {
		t.Fatal("fixture executable still present")
	}
	r := New(Options{HostRoot: "/", ProcRoot: "/proc"})
	r.Scan(ctx, &model.Snapshot{Processes: []*model.Process{raw.Proc}})
	if missing := r.Apply([]*model.Process{raw.Proc}); missing != 0 || raw.Proc.Executable == nil || !raw.Proc.Executable.ELF || raw.Proc.Executable.Incomplete {
		t.Fatalf("missing=%d metadata=%+v cached=%+v findings=%+v", missing, raw.Proc.ExeInfo, r.executables[raw.Proc.Key], r.Findings())
	}
}

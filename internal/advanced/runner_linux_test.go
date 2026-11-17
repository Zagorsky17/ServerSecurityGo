package advanced

import (
	"context"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRealDeletedELF(t *testing.T) {
	// Запускается копия системного sleep, только в приватном каталоге теста.
	data, e := os.ReadFile("/bin/sleep")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "sleep")
	if e = os.WriteFile(path, data, 0700); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(path, "60")
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
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
	r.Scan(context.Background(), &model.Snapshot{Processes: []*model.Process{raw.Proc}})
	if missing := r.Apply([]*model.Process{raw.Proc}); missing != 0 || raw.Proc.Executable == nil || !raw.Proc.Executable.ELF || raw.Proc.Executable.Incomplete {
		t.Fatal(missing, raw.Proc.Executable)
	}
}

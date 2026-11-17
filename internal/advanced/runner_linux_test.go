package advanced

import (
	"context"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
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
		t.Logf("process=%+v cached=%+v findings=%+v", raw.Proc.ExeInfo, r.executables[raw.Proc.Key], r.Findings())
		statPath := filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "stat")
		b, _, se := safefile.ReadRegular(statPath, 8192, false)
		st, pe := procfs.ParseStat(string(b))
		file, info, oe := safefile.Open(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe"), true)
		if file != nil {
			file.Close()
		}
		fd, directErr := syscall.Open(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe"), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if directErr == nil {
			syscall.Close(fd)
		}
		t.Logf("reader uid/euid=%d/%d process uid/euid=%d/%d direct open=%v", os.Getuid(), os.Geteuid(), raw.Proc.UID, raw.Proc.EUID, directErr)
		t.Fatalf("missing=%d stat=%v parse=%v start=%d/%d open=%v info=%+v target=%q", missing, se, pe, st.StartTicks, raw.Proc.StartTicks, oe, info, raw.Proc.Exe)
	}
}

//go:build linux

package rootkit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestRealThreadsAreNotHiddenProcesses(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	other := make(chan int)
	release := make(chan struct{})
	go func() { runtime.LockOSThread(); defer runtime.UnlockOSThread(); other <- syscall.Gettid(); <-release }()
	defer close(release)
	otherTID := <-other
	tid := syscall.Gettid()
	if tid == os.Getpid() {
		tid = otherTID
	}
	if tid == os.Getpid() {
		t.Fatal("test must use a nonleader thread")
	}
	pid := os.Getpid()
	p, err := processIdentity(filepath.Join("/proc", strconv.Itoa(tid)))
	if err != nil {
		t.Fatal(err)
	}
	if p.pid != tid || p.tgid != pid {
		t.Fatalf("%+v", p)
	}
	listed, err := pidList("/proc")
	if err != nil {
		t.Fatal(err)
	}
	if tid != pid && listed[tid] {
		t.Fatal("nonleader unexpectedly listed")
	}
	f, err := confirmHidden(context.Background(), "/proc", listed, []int{tid, pid}, 0, pidList)
	if err != nil || len(f) != 0 {
		t.Fatalf("ordinary threads: %+v %v", f, err)
	}
}
func TestRealKernelModules(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root check runs separately in CI")
	}
	f, _, err := moduleChecks(context.Background(), "/proc", "/", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range f {
		if v.Risk == model.RiskCritical {
			t.Fatalf("unexpected module discrepancy on CI host: %+v", v)
		}
	}
}

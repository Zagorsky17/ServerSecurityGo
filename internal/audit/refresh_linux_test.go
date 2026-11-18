//go:build linux

package audit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/fsinspect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestRealInventoryCompletionRefreshesAudit(t *testing.T) {
	root, proc := t.TempDir(), t.TempDir()
	putHardening(t, root, "etc/passwd", fmt.Sprintf("root:x:%d:%d::/root:/bin/sh\n", os.Getuid(), os.Getgid()))
	putHardening(t, root, "etc/group", fmt.Sprintf("root:x:%d:\n", os.Getgid()))
	putHardening(t, root, "var/lib/dpkg/status", "Package: fixture\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n")
	putHardening(t, root, "var/lib/dpkg/info/fixture.list", "/usr/bin/fixture\n")
	putHardening(t, root, "usr/bin/fixture", "fixture")
	putHardening(t, proc, "self/mountinfo", "1 0 1:1 / / rw - ext4 /dev/fixture rw\n")
	inventory := fsinspect.New(fsinspect.Options{HostRoot: root, ProcRoot: proc, Rate: 1000000, ReadOnly: true})
	runner := NewRunner(RunnerOptions{HostRoot: root, ProcRoot: proc, RootUID: os.Getuid(), Inventory: inventory.Report, InventoryUpdates: inventory.Updates(), Logger: quiet()})
	first := runner.RunOnce()
	if checksByID(first.Checks)["fs_capabilities"].Status != model.AuditUnknown {
		t.Fatal("first audit unexpectedly complete")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runner.Run(ctx) }()
	defer func() { cancel(); <-done }()
	collected := inventory.RunOnce(ctx)
	if collected.Incomplete {
		t.Fatal(collected.Warnings)
	}
	waitFor(t, func() bool { return runner.Report() != first })
	next := runner.Report()
	if checksByID(next.Checks)["fs_capabilities"].Status != model.AuditPass || !next.InventorySource.Time.Equal(collected.Time) || !next.Time.Equal(first.Time) {
		t.Fatal(next)
	}
	if !next.UpdatedAt.After(first.UpdatedAt) || time.Since(next.UpdatedAt) > 5*time.Second {
		t.Fatal("refresh delayed")
	}
}

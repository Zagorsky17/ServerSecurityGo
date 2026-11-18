package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/fsinspect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/rootkit"
)

func TestQuickRunPreservesIncompleteSweeps(t *testing.T) {
	for _, quick := range []bool{true, false} {
		sc, _, proc := newDemoScanner(t)
		path := filepath.Join(proc, "sys/kernel/pid_max")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("16"), 0600); err != nil {
			t.Fatal(err)
		}
		sc.opt.Quick = quick
		sc.opt.Interval = 20 * time.Millisecond
		sc.opt.Rootkit = rootkit.New(rootkit.Options{ProcRoot: proc, HostRoot: sc.opt.FS.HostRoot, ReadOnly: true})
		sc.opt.Inventory = fsinspect.New(fsinspect.Options{ProcRoot: proc, HostRoot: sc.opt.FS.HostRoot, ReadOnly: true, Rate: 100000})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); sc.Run(ctx) }()
		deadline := time.Now().Add(3 * time.Second)
		for sc.seq.Load() < 3 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !quick {
			for sc.opt.Inventory.Report() == nil && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
		}
		cancel()
		<-done
		if sc.seq.Load() < 3 {
			t.Fatal("scanner did not run")
		}
		found := false
		for _, f := range sc.opt.Rootkit.Check(context.Background()) {
			if f.ID == "rootkit_sweep_complete" {
				found = true
			}
		}
		if found == quick {
			t.Fatalf("quick=%v complete=%v", quick, found)
		}
		if quick {
			pending := map[string]bool{}
			for _, f := range sc.Snapshot().System {
				pending[f.ID] = true
			}
			for _, id := range []string{"rootkit_sweep_pending", "fs_inventory_pending"} {
				if !pending[id] {
					t.Fatalf("quick mode hid incomplete check: %s", id)
				}
			}
		}
		if quick && sc.opt.Inventory.Report() != nil {
			t.Fatal("quick mode started file inventory")
		}
		if !quick && sc.opt.Inventory.Report() == nil {
			t.Fatal("full mode skipped file inventory")
		}
	}
}

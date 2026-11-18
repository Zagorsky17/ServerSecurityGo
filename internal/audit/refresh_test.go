package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestInventoryRefreshPreservesOtherChecksAndBaseline(t *testing.T) {
	var inventory atomic.Pointer[model.FileInventory]
	updates := make(chan struct{}, 1)
	var runs atomic.Int32
	root, dir := accountsTree(t, nil), t.TempDir()
	hist, err := history.Open(history.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := NewRunner(RunnerOptions{HostRoot: root, RootUID: os.Getuid(), StateDir: dir, Logger: quiet(),
		Inventory: inventory.Load, InventoryUpdates: updates,
		Record: func(now time.Time, checks []model.AuditCheck) []model.Event {
			runs.Add(1)
			if len(checks) < 60 {
				t.Error("partial check list would erase history")
			}
			return hist.RecordAudit(now, checks)
		},
	})
	first := r.RunOnce()
	original, _ := json.Marshal(first)
	base, err := os.ReadFile(filepath.Join(dir, baselineFile))
	if err != nil {
		t.Fatal(err)
	}
	if first.InventorySource.Ready || checksByID(first.Checks)["fs_unowned"].Status != model.AuditUnknown {
		t.Fatal(first)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	defer func() { cancel(); <-done }()
	// Изменение учётки не должно перечитываться при обновлении только инвентаря.
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(passwd+"bob:x:0:0::/root:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	partial := &model.FileInventory{Time: time.Now(), Incomplete: true, Findings: []model.SystemFinding{{Risk: model.RiskHigh, Finding: model.Finding{ID: "fs_unowned"}}}}
	inventory.Store(partial)
	updates <- struct{}{}
	waitFor(t, func() bool { return r.Report() != first })
	second := r.Report()
	m := checksByID(second.Checks)
	if m["fs_unowned"].Status != model.AuditFail || m["fs_capabilities"].Status != model.AuditUnknown || !second.InventorySource.Incomplete {
		t.Fatal(m)
	}
	if !second.Time.Equal(first.Time) || !second.UpdatedAt.After(first.UpdatedAt) || m["fs_unowned"].Why.IsZero() {
		t.Fatal(second)
	}
	before := checksByID(first.Checks)
	for _, c := range second.Checks {
		if c.ID != "fs_unowned" && c.ID != "fs_suid_inventory" && c.ID != "fs_capabilities" && c.ID != "fs_world_writable_system" {
			a, _ := json.Marshal(c)
			b, _ := json.Marshal(before[c.ID])
			if string(a) != string(b) {
				t.Fatal("unrelated check changed", c.ID)
			}
		}
	}
	current, _ := os.ReadFile(filepath.Join(dir, baselineFile))
	if string(current) != string(base) {
		t.Fatal("partial refresh rewrote baseline")
	}
	after, _ := json.Marshal(first)
	if string(after) != string(original) {
		t.Fatal("published report mutated")
	}
	complete := &model.FileInventory{Time: time.Now(), Findings: []model.SystemFinding{{Risk: model.RiskMedium, Finding: model.Finding{ID: "fs_unowned"}}}}
	inventory.Store(complete)
	updates <- struct{}{}
	waitFor(t, func() bool { return r.Report() != second })
	third := r.Report()
	if checksByID(third.Checks)["fs_unowned"].Status != model.AuditWarn || checksByID(third.Checks)["fs_capabilities"].Status != model.AuditPass || third.InventorySource.Incomplete {
		t.Fatal(third)
	}
	for range 10 {
		select {
		case updates <- struct{}{}:
		default:
		}
	}
	time.Sleep(50 * time.Millisecond)
	if r.Report() != third || runs.Load() != 3 {
		t.Fatal("duplicate inventory caused repeated audit", runs.Load())
	}
	// Ручная проверка сохраняет прежнее назначение и видит изменение учётки.
	if !r.RunNow() {
		t.Fatal("manual audit refused")
	}
	waitFor(t, func() bool { return r.Report() != third })
	if c := checksByID(r.Report().Checks)["acct_new"]; c.Status != model.AuditFail {
		t.Fatal(c)
	}
}

func TestInventoryArrivesDuringAuditAndCancellation(t *testing.T) {
	var inventory atomic.Pointer[model.FileInventory]
	updates := make(chan struct{}, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var runs, active atomic.Int32
	r := NewRunner(RunnerOptions{HostRoot: accountsTree(t, nil), RootUID: os.Getuid(), Logger: quiet(), Inventory: inventory.Load, InventoryUpdates: updates,
		Record: func(time.Time, []model.AuditCheck) []model.Event {
			if active.Add(1) != 1 {
				t.Error("parallel audit")
			}
			defer active.Add(-1)
			if runs.Add(1) == 1 {
				close(entered)
				<-release
			}
			return nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	<-entered
	if r.RunNow() {
		t.Fatal("manual request accepted during audit")
	}
	inventory.Store(&model.FileInventory{Time: time.Now()})
	updates <- struct{}{}
	close(release)
	waitFor(t, func() bool { return r.Report() != nil && r.Report().InventorySource.Ready })
	if runs.Load() != 2 {
		t.Fatal("lost or duplicated inventory notification", runs.Load())
	}
	cancel()
	<-done
	previous := r.Report()
	inventory.Store(&model.FileInventory{Time: time.Now(), Incomplete: true})
	updates <- struct{}{}
	r.Run(ctx)
	if r.Report() != previous || runs.Load() != 2 {
		t.Fatal("cancelled runner restarted")
	}
}

package scanner

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/selfcheck"
)

func TestSelfCheckWhileScanIsBlocked(t *testing.T) {
	sc, _, _ := newDemoScanner(t)
	first, err := sc.ScanOnce()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(first)
	sc.self = selfcheck.New(selfcheck.Options{HostRoot: t.TempDir(), Executable: "/absent", Interval: time.Second, Progress: sc.LastSuccess, Record: sc.History().RecordSelfCheck, Logger: sc.opt.Logger})
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	sc.opt.BeforeScan = func() { close(entered); <-release }
	go func() { defer close(done); sc.ScanOnce() }()
	<-entered
	now := time.Now()
	sc.mu.Lock()
	sc.lastSuccess = now.Add(-4 * time.Second)
	sc.mu.Unlock()
	sc.self.Check(now)
	if sc.Healthy(now) {
		t.Fatal("blocked scanner healthy")
	}
	snap := sc.Snapshot()
	found := false
	for _, f := range snap.System {
		if f.ID == "self_scan_stalled" {
			found = true
		}
	}
	if !found {
		t.Fatal("stale finding absent from snapshot")
	}
	after, _ := json.Marshal(first)
	if string(before) != string(after) {
		t.Fatal("published snapshot was mutated")
	}
	close(release)
	<-done
	sc.self.Check(time.Now())
	if !sc.Healthy(time.Now()) {
		t.Fatal("successful scan did not restore health")
	}
	for _, f := range sc.Snapshot().System {
		if f.ID == "self_scan_stalled" {
			t.Fatal("stalled finding not cleared")
		}
	}
	var count int
	for _, e := range sc.History().Events(100) {
		if e.Name == "self_scan_stalled" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("want stall + recovery events; got %d", count)
	}
}

func TestFailedScanDoesNotAdvanceProgress(t *testing.T) {
	sc, _, _ := newDemoScanner(t)
	if _, err := sc.ScanOnce(); err != nil {
		t.Fatal(err)
	}
	last := sc.LastSuccess()
	sc.opt.FS.Root = "/nonexistent-ssg-proc"
	if _, err := sc.ScanOnce(); err == nil {
		t.Fatal("expected collection failure")
	}
	if !sc.LastSuccess().Equal(last) {
		t.Fatal("failed scan refreshed health")
	}
}

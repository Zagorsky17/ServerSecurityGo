package scanner

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRecentRunsOutsideForegroundScan(t *testing.T) {
	base, _, _ := newDemoScanner(t)
	opt := base.opt
	opt.Recent = true
	sc := New(opt)
	first, err := sc.ScanOnce()
	if err != nil {
		t.Fatal(err)
	}
	if first.Recent == nil || !first.Recent.Incomplete || len(first.Recent.Files) != 0 || len(first.Recent.Warnings) == 0 {
		t.Fatal("foreground scan performed metadata traversal or hid pending state")
	}
	before, _ := json.Marshal(first)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); sc.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("background worker did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		snap := sc.Snapshot()
		if snap.Recent != nil && len(snap.Recent.Files) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background result not published")
		}
		time.Sleep(10 * time.Millisecond)
	}
	after, _ := json.Marshal(first)
	if string(before) != string(after) {
		t.Fatal("published snapshot mutated")
	}
	if !sc.Healthy(time.Now()) {
		t.Fatal("metadata traversal stopped process progress")
	}
}

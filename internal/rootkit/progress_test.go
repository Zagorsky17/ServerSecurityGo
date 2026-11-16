package rootkit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
)

func TestSweepTiming(t *testing.T) {
	start := time.Now()
	for _, tc := range []struct {
		name              string
		checked           int
		elapsed           time.Duration
		running, complete bool
		want              string
	}{
		{"initial", 0, 0, true, false, "calculating"},
		{"half", 1024, 2 * time.Minute, true, false, "elapsed 00:02:00, remaining ≈ 00:02:00 (50%)"},
		{"round up", 1024, 1500 * time.Millisecond, true, false, "remaining ≈ 00:00:02"},
		{"stopped", 1024, 2 * time.Minute, false, false, "stopped after 00:02:00"},
		{"complete", 2048, 4 * time.Minute, false, true, "finished in 00:04:00"},
		{"long", 1024, 2*time.Hour + time.Minute, true, false, "elapsed 02:01:00, remaining ≈ 02:01:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Checker{started: start, total: 2049, checked: tc.checked, running: tc.running, complete: tc.complete}
			now := start.Add(tc.elapsed)
			if !tc.running {
				c.finished = now
				now = now.Add(time.Hour)
			}
			f := c.sweepFinding(now)
			if got := f.Title.In(i18n.EN); !strings.Contains(got, tc.want) {
				t.Fatalf("%s", got)
			}
			if f.Incomplete() == tc.complete {
				t.Fatal("wrong completeness")
			}
			if got := f.Title.In(i18n.RU); strings.Contains(got, "{0}") || got == f.Title.In(i18n.EN) {
				t.Fatal(got)
			}
		})
	}
	c := &Checker{}
	if got := c.sweepFinding(start).Title.In(i18n.EN); !strings.Contains(got, "has not finished") {
		t.Fatal(got)
	}
}

func TestSweepTimingLifecycle(t *testing.T) {
	p, h := hostFixture(t)
	c := New(Options{ProcRoot: p, HostRoot: h})
	c.batchPause = 0
	c.confirmDelay = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.Sweep(ctx) == nil {
		t.Fatal("cancel ignored")
	}
	if c.running || c.started.IsZero() || c.finished.IsZero() || c.complete {
		t.Fatal("cancelled clock still running")
	}
	old := c.started
	if err := c.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.running || !c.complete || !c.started.After(old) || c.finished.Before(c.started) {
		t.Fatal("clock did not restart/finish")
	}
	for _, f := range c.Check(context.Background()) {
		if f.ID == "rootkit_sweep_complete" && !strings.Contains(f.Title.In(i18n.EN), "finished in") {
			t.Fatal(f)
		}
	}
}

package fsinspect

import (
	"context"
	"testing"
)

func TestInventoryNotificationsCoalesceAndPublishLatest(t *testing.T) {
	opt, _ := fixture(t)
	r := New(opt)
	first := r.RunOnce(context.Background())
	latest := r.RunOnce(context.Background())
	if first == latest || r.Report() != latest {
		t.Fatal("latest report not published")
	}
	select {
	case <-r.Updates():
	default:
		t.Fatal("missing notification")
	}
	select {
	case <-r.Updates():
		t.Fatal("notifications not coalesced")
	default:
	}
	opt.MaxEntries = 1
	partial := New(opt)
	rep := partial.RunOnce(context.Background())
	if !rep.Incomplete {
		t.Fatal("fixture expected incomplete")
	}
	select {
	case <-partial.Updates():
	default:
		t.Fatal("incomplete result not published")
	}
}

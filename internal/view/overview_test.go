package view

import (
	"reflect"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestOverviewKeepsIncompleteAndChanges(t *testing.T) {
	fs := []model.SystemFinding{
		{Finding: model.Finding{ID: "routine"}},
		{Finding: model.Finding{ID: "integrity_unavailable"}},
		{Finding: model.Finding{ID: "changed", FindingContext: model.FindingContext{RelatedEvents: []model.Event{{Type: model.EvSystem}}}}},
		{Risk: model.RiskLow},
	}
	got := OverviewSystem(fs)
	if got.Attention != 3 || got.Incomplete != 1 || !reflect.DeepEqual(got.Details, []int{0}) {
		t.Fatal(got)
	}
	for _, status := range []string{model.AuditPass, model.AuditInfo, model.AuditNA} {
		if AuditAttention(model.AuditCheck{Status: status}) {
			t.Fatal(status)
		}
		if !AuditAttention(model.AuditCheck{Status: status, Change: true}) {
			t.Fatal("hidden change", status)
		}
	}
	for _, status := range []string{model.AuditFail, model.AuditWarn, model.AuditUnknown, "future-status"} {
		if !AuditAttention(model.AuditCheck{Status: status}) {
			t.Fatal("hidden uncertainty", status)
		}
	}
}

func TestLoginGroupsPreserveEveryRecord(t *testing.T) {
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	base := model.LoginEvent{Time: at, Kind: "failed", IP: "192.0.2.1", Source: "auth.log", Method: "password"}
	events := []model.LoginEvent{base, base, base, base, base, base, base, base, base, base}
	events[0].Time = at.Add(14 * time.Minute)
	events[0].Risk = model.RiskHigh
	events[1].Time = at.In(time.FixedZone("offset", 10800))
	events[1].User = "other-user"
	events[2].Time = at.Add(15 * time.Minute)
	events[3].Source = "btmp"
	events[4].Kind = "login"
	events[5].IP = ""
	events[6].Source = ""
	events[7].Time = time.Time{}
	events[8].Method = "publickey"
	events[9].IP = "192.0.2.2"
	before := append([]model.LoginEvent(nil), events...)
	groups := GroupLogins(events)
	if len(groups) != 9 {
		t.Fatal(groups)
	}
	seen := make([]int, len(events))
	merged := false
	for i, g := range groups {
		if i > 0 && g.Last.After(groups[i-1].Last) {
			t.Fatal("unordered")
		}
		for _, j := range g.Indices {
			seen[j]++
		}
		if len(g.Indices) > 1 {
			merged = true
			if !reflect.DeepEqual(g.Indices, []int{0, 1}) || g.Risk != model.RiskHigh || !g.First.Equal(at) || !g.Last.Equal(events[0].Time) {
				t.Fatal(g)
			}
		}
	}
	for i, n := range seen {
		if n != 1 {
			t.Fatal(i, n)
		}
	}
	if !merged || !reflect.DeepEqual(before, events) {
		t.Fatal("lost group or mutated input")
	}
}

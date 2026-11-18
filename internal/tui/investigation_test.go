package tui

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
	"testing"
	"time"
)

func TestInvestigationPanels(t *testing.T) {
	a, _ := newTestApp(t, 180, 50)
	now := time.Now()
	a.data.Auth = &model.AuthReport{Events: []model.LoginEvent{{Time: now, User: "investigator", IP: "192.0.2.99", Method: "publickey", Fingerprint: "SHA256:demo", Source: "/var/log/auth.log"}}}
	a.data.Timeline = []model.TimelineEvent{{Time: now, Kind: "file", Source: "/etc/crontab", Detail: i18n.L("timeline-test"), VerifyCommands: []string{"stat -- '/etc/crontab'"}}}
	a.rebuild()
	for _, p := range []panelID{pAuth, pTimeline} {
		a.focusPanel(p)
		a.render()
		text := a.scr.String()
		want := "investigator"
		if p == pTimeline {
			want = "timeline-test"
		}
		if !strings.Contains(text, want) {
			t.Fatalf("%d missing %s", p, want)
		}
	}
}
func TestInvestigationSmallTerminal(t *testing.T) {
	a, _ := newTestApp(t, 100, 24)
	a.data.Auth = &model.AuthReport{}
	a.data.Timeline = []model.TimelineEvent{}
	a.rebuild()
	a.focusPanel(pAuth)
	a.render()
	for _, p := range a.visible() {
		r := a.rects[p]
		if r.h < 0 || r.y+r.h > 23 {
			t.Fatalf("invalid geometry %d: %+v", p, r)
		}
	}
	if a.rects[pAuth].h < 6 {
		t.Fatal("active panel lost", a.rects[pAuth])
	}
}

func TestOverviewFiltersAndLoginDetails(t *testing.T) {
	a, out := newTestApp(t, 180, 50)
	a.data.System = []model.SystemFinding{{Finding: model.Finding{ID: "routine"}}, {Finding: model.Finding{ID: "integrity_unavailable"}}}
	a.rebuild()
	if len(a.system) != 1 || a.system[0].ID != "integrity_unavailable" {
		t.Fatal(a.system)
	}
	a.focusPanel(pSys)
	a.runeKey('i', pSys)
	if len(a.system) != 2 {
		t.Fatal("toggle lost INFO")
	}
	a.runeKey('i', pSys)
	a.lists[pSys].filter = "routine"
	a.rebuild()
	if len(a.system) != 1 || a.system[0].ID != "routine" {
		t.Fatal("search lost INFO")
	}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	a.data.Auth = &model.AuthReport{Time: now, Since: now.Add(-time.Hour), Incomplete: true}
	for _, user := range []string{"first-member", "last-member"} {
		a.data.Auth.Events = append(a.data.Auth.Events, model.LoginEvent{Time: now, Kind: "failed", IP: "192.0.2.1", Source: "auth.log", User: user})
	}
	a.rebuild()
	if a.count(pAuth) != 1 {
		t.Fatal(a.loginGroups)
	}
	a.focusPanel(pAuth)
	_, lines := a.mainContent(180)
	var text strings.Builder
	for _, line := range lines {
		for _, segment := range line {
			text.WriteString(segment.t)
		}
	}
	for _, want := range []string{"first-member", "last-member"} {
		if !strings.Contains(text.String(), want) {
			t.Fatal("missing", want)
		}
	}
	a.copyJSON()
	var copied []model.LoginEvent
	if err := json.Unmarshal([]byte(osc52Text(t, out.String())), &copied); err != nil || len(copied) != 2 {
		t.Fatal("group copy", err, copied)
	}
	a.lists[pAuth].filter = "last-member"
	a.rebuild()
	if len(a.logins) != 1 || a.count(pAuth) != 1 {
		t.Fatal("group search")
	}
	a.copyJSON()
	var single model.LoginEvent
	if err := json.Unmarshal([]byte(osc52Text(t, out.String())), &single); err != nil || single.User != "last-member" {
		t.Fatal("single copy", err, single)
	}
}

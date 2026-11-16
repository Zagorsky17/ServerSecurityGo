package tui

import (
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

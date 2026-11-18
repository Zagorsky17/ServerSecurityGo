package tui

import (
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/investigate"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestReviewCardSectionsAndMarker(t *testing.T) {
	a, _ := newTestApp(t, 100, 24)
	snap := &model.Snapshot{System: []model.SystemFinding{{Risk: model.RiskLow, Path: "/root/.ssh/authorized_keys", Finding: model.Finding{ID: "ssh_keys_recent", Title: i18n.L("key file changed"), Evidence: i18n.Ls([]string{"mtime observation\x1b[2J"})}}}}
	investigate.Attach(snap)
	a.data.System = snap.System
	a.lang = i18n.EN
	a.rebuild()
	a.focusPanel(pSys)
	_, lines := a.mainContent(120)
	var b strings.Builder
	for _, l := range lines {
		for _, s := range l {
			b.WriteString(s.t)
		}
		b.WriteByte('\n')
	}
	text := b.String()
	last := -1
	for _, part := range []string{"key file changed", "mtime observation", "Risk and consequences", "Confidence and limitations", "How to verify", "ssh-keygen"} {
		n := strings.Index(text, part)
		if n < 0 || n <= last {
			t.Fatalf("section missing or out of order: %s", part)
		}
		last = n
	}
	if strings.Contains(text, "\x1b") || !strings.Contains(screen(a), "[!]") {
		t.Fatal("escaping or change marker failed")
	}
	a.data.System[0].Suppressed = true
	a.rebuild()
	if strings.Contains(screen(a), "[!]") {
		t.Fatal("suppressed finding has priority marker")
	}
	a.data.Changes = &model.ChangesReport{Installation: &model.BaselineDiff{Changes: []model.BaselineChange{{Section: "ssh_keys", Kind: "added", Key: "SHA256:fixture", ReviewFirst: true}}}}
	a.focusPanel(pChanges)
	if !strings.Contains(screen(a), "Change — review first") {
		t.Fatal("baseline change marker missing")
	}
}

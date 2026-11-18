package tui

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
	"testing"
	"time"
)

func TestChangesPanelAndFindingContext(t *testing.T) {
	a, _ := newTestApp(t, 160, 50)
	a.data.Changes = &model.ChangesReport{Installation: &model.BaselineDiff{From: time.Now().Add(-time.Hour), To: time.Now(), Changes: []model.BaselineChange{{Section: "users", Key: "test", Kind: "added", After: "1001"}}}}
	a.focus = pChanges
	a.expanded = pChanges
	a.rebuild()
	s := screen(a)
	for _, want := range []string{"Изменения", "users added test", "1001"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s: %s", want, s)
		}
	}
	b := &lb{w: 120, lang: i18n.EN}
	b.findingContext(model.FindingContext{Why: i18n.L("reason"), Legitimate: i18n.L("maintenance"), Attack: []string{"T1620"}, RelatedEvents: []model.Event{{Time: time.Now(), Details: i18n.L("history marker")}}})
	var text strings.Builder
	for _, line := range b.lines {
		for _, seg := range line {
			text.WriteString(seg.t)
		}
	}
	for _, want := range []string{"reason", "maintenance", "https://attack.mitre.org/techniques/T1620/", "history marker"} {
		if !strings.Contains(text.String(), want) {
			t.Fatal(text.String())
		}
	}
}

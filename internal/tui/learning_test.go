package tui

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
	"strings"
	"testing"
	"time"
)

func TestLearningPanelAndSearch(t *testing.T) {
	a, _ := newTestApp(t, 160, 50)
	a.data.Learning = &model.LearningReport{Enabled: true, Until: time.Now().Add(time.Hour), Candidates: []model.LearningCandidate{{Exe: "/opt/fixture", User: "worker", Rule: "cpu_sustained", Count: 3, Proposal: `{"rules":[]}`}}, Warnings: []i18n.Msg{i18n.L("review fixture")}}
	a.focus = pLearning
	a.expanded = pLearning
	a.rebuild()
	a.lists[pLearning].cursor = 1
	text := screen(a)
	for _, s := range []string{"/opt/fixture", "cpu_sustained", "review fixture"} {
		if !strings.Contains(text, s) {
			t.Fatal(s, text)
		}
	}
	p := view.Summary{User: "worker", Container: "container-marker", Ports: []int{23456}, Findings: []view.FindingBrief{{ID: "exe_memfd", Title: i18n.L("title")}}}
	for _, q := range []string{"worker", "container-marker", "23456", "exe_memfd"} {
		if !procMatches(i18n.EN, q, p) {
			t.Fatal(q)
		}
	}
	if procMatches(i18n.EN, "missing", p) {
		t.Fatal("unrelated match")
	}
}

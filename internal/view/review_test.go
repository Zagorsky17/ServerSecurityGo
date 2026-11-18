package view

import (
	"reflect"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestReviewOrderPreservesCriticalAndRisk(t *testing.T) {
	s := &model.Snapshot{System: []model.SystemFinding{
		{Path: "background-high", Risk: model.RiskHigh},
		{Path: "ssh-mtime", Risk: model.RiskLow, Finding: model.Finding{FindingContext: model.FindingContext{ReviewFirst: true}}},
		{Path: "critical", Risk: model.RiskCritical},
		{Path: "suppressed", Risk: model.RiskHigh, Finding: model.Finding{Suppressed: true, FindingContext: model.FindingContext{ReviewFirst: true}}},
		{Path: "new-port", Risk: model.RiskHigh, Finding: model.Finding{FindingContext: model.FindingContext{ReviewFirst: true}}},
		{Path: "medium-a", Risk: model.RiskMedium},
		{Path: "medium-b", Risk: model.RiskMedium},
	}}
	before := append([]model.SystemFinding(nil), s.System...)
	got := SortedSystem(s)
	for i, want := range []string{"critical", "new-port", "ssh-mtime", "background-high", "suppressed", "medium-a", "medium-b"} {
		if got[i].Path != want {
			t.Fatalf("position %d: %s != %s", i, got[i].Path, want)
		}
	}
	if got[2].Risk != model.RiskLow || !reflect.DeepEqual(s.System, before) {
		t.Fatal("presentation modified source or risk")
	}
}

package investigate

import (
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestChangeConfidenceAndSuppression(t *testing.T) {
	snap := &model.Snapshot{}
	for _, id := range []string{"new_public_listener", "ssh_keys_recent", "fs_privilege_new", "fs_capabilities"} {
		snap.System = append(snap.System, model.SystemFinding{Path: "/tmp/file'$(ignored)", Risk: model.RiskLow, Finding: model.Finding{ID: id}})
	}
	snap.System = append(snap.System, model.SystemFinding{Risk: model.RiskHigh, Finding: model.Finding{ID: "fs_privilege_new", Suppressed: true}})
	Attach(snap)
	for i, f := range snap.System {
		if f.ReviewFirst != (i < 3) || f.Confidence.IsZero() || len(f.VerifyCommands) == 0 {
			t.Fatal(f)
		}
		if i < 4 && f.Risk != model.RiskLow {
			t.Fatal("review priority changed risk")
		}
	}
	if !strings.Contains(snap.System[1].Confidence.In(i18n.EN), "mtime") || !strings.Contains(snap.System[1].VerifyCommands[1], Quote(snap.System[1].Path)) {
		t.Fatal("SSH evidence limitations or quoting missing")
	}
	if !strings.Contains(snap.System[2].Confidence.In(i18n.EN), "Package ownership does not dismiss") {
		t.Fatal("package membership treated as trust")
	}
	f, err := Explain("fs_privilege_new")
	if err != nil || f.Title.Key != "rule.fs_privilege_new.title" || f.Recommendation.IsZero() || f.Confidence.IsZero() {
		t.Fatal(f, err)
	}
	checks := []model.AuditCheck{{Status: model.AuditUnknown}}
	AttachAudit(checks, nil)
	if !strings.Contains(checks[0].Confidence.In(i18n.EN), "Unknown means insufficient data") {
		t.Fatal("unknown audit expressed as certainty")
	}
}

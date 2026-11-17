package report

import (
	"bytes"
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
	"net/url"
	"testing"
)

func TestSARIFScanAuditAndTriage(t *testing.T) {
	finding := model.Finding{ID: "exe_memfd", Category: model.CatLocation, Title: i18n.L("<script>\"test\""), Suppressed: true, FindingContext: model.FindingContext{Attack: []string{"T1620"}}}
	snap := &model.Snapshot{Processes: []*model.Process{{PID: 5, Key: "5-1", Exe: "/tmp/a #?\n.php", Risk: model.RiskHigh, Findings: []model.Finding{finding}}}, System: []model.SystemFinding{{Finding: model.Finding{ID: "advanced_pending", Category: model.CatInfo, Title: i18n.L("pending")}}}}
	checks := []model.AuditCheck{{ID: "known", Title: i18n.L("known"), Status: model.AuditPass}, {ID: "unknown", Title: i18n.L("unknown"), Status: model.AuditUnknown}, {ID: "failed", Title: i18n.L("failed"), Status: model.AuditFail, Severity: model.RiskHigh}, {ID: "info", Title: i18n.L("info"), Status: model.AuditInfo}}
	audit := &model.AuditReport{Checks: checks}
	triage := &Investigation{Snapshot: snap, Audit: audit, Kind: "triage", Version: "test"}
	triage.Summarize()
	scan := NewScan(snap, model.RiskInfo, "test")
	a := &Audit{View: view.BuildAudit(true, false, 0, audit), Version: "test"}
	for name, render := range map[string]func(*bytes.Buffer) error{"scan": func(b *bytes.Buffer) error { return scan.Render(b, SARIF, i18n.EN) }, "audit": func(b *bytes.Buffer) error { return a.Render(b, SARIF, i18n.EN) }, "triage": func(b *bytes.Buffer) error { return triage.Render(b, SARIF, i18n.EN) }} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			if e := render(&b); e != nil {
				t.Fatal(e)
			}
			var doc struct {
				Version string
				Runs    []struct {
					Results     []sarifResult
					Invocations []struct{ ExecutionSuccessful bool }
					Tool        struct {
						Driver struct {
							Name  string
							Rules []struct{ ID string }
						}
					}
				}
			}
			if e := json.Unmarshal(b.Bytes(), &doc); e != nil {
				t.Fatal(e)
			}
			if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
				t.Fatal(b.String())
			}
			run := doc.Runs[0]
			if run.Invocations[0].ExecutionSuccessful || run.Tool.Driver.Name != "ServerSecurityGo" {
				t.Fatal(b.String())
			}
			rules := map[string]bool{}
			for _, r := range run.Tool.Driver.Rules {
				if rules[r.ID] {
					t.Fatal("duplicate rule")
				}
				rules[r.ID] = true
			}
			for _, r := range run.Results {
				if !rules[r.RuleID] || r.Message["text"] == "" {
					t.Fatal(r)
				}
				if r.RuleID == "exe_memfd" {
					if r.Level != "error" || len(r.Suppressions) != 1 || r.Properties["processKey"] != "5-1" {
						t.Fatal(r)
					}
					uri := r.Locations[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
					u, e := url.Parse(uri)
					if e != nil || u.Path != snap.Processes[0].Exe || u.Host != "" {
						t.Fatal(uri, e)
					}
				}
				if r.RuleID == "unknown" && (r.Level != "none" || r.Kind != "review") {
					t.Fatal(r)
				}
				if r.RuleID == "info" && r.Kind != "informational" {
					t.Fatal(r)
				}
			}
		})
	}
}

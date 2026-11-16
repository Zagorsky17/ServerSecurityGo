package report

import (
	"bytes"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
	"testing"
	"time"
)

func TestInvestigationEscapingAndPriority(t *testing.T) {
	r := &Investigation{Kind: "triage", Time: time.Now(), Snapshot: &model.Snapshot{Host: model.HostInfo{IsRoot: true}, System: []model.SystemFinding{{Finding: model.Finding{Title: i18n.L("<script>alert(1)</script>"), VerifyCommands: []string{"stat -- '/tmp/`injected`'"}}, Risk: model.RiskCritical}}}}
	r.Summarize()
	if len(r.Priority) != 1 || !strings.Contains(r.Verdict.In(i18n.EN), "High likelihood") {
		t.Fatal(r)
	}
	for _, f := range []Format{Text, JSON, HTML, Markdown} {
		var b bytes.Buffer
		if e := r.Render(&b, f, i18n.EN); e != nil {
			t.Fatal(e)
		}
		if f == HTML && strings.Contains(b.String(), "<script>alert") {
			t.Fatal("HTML injection")
		}
	}
}

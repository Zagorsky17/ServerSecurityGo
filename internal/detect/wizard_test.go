package detect

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"testing"
)

func TestAllowlistProposalExactAndBounded(t *testing.T) {
	p := &model.Process{Exe: "/opt/[app]*?\\bin", User: "service", Risk: model.RiskLow}
	f := model.Finding{ID: "cpu_sustained", Weight: 8, Category: model.CatBehavior}
	text := AllowlistProposal(p, f)
	var doc struct{ Rules []AllowRule }
	if e := json.Unmarshal([]byte(text), &doc); e != nil || len(doc.Rules) != 1 {
		t.Fatal(text, e)
	}
	cfg := Config{Allow: doc.Rules}
	if !cfg.Allowed(p, f.ID) || cfg.Allowed(p, "stdio_socket") {
		t.Fatal("rule scope")
	}
	other := *p
	other.Exe = "/opt/aZZbin"
	if cfg.Allowed(&other, f.ID) {
		t.Fatal("path wildcard widened")
	}
	other = *p
	other.User = "root"
	if cfg.Allowed(&other, f.ID) {
		t.Fatal("user widened")
	}
	p.Risk = model.RiskCritical
	if AllowlistProposal(p, f) != "" {
		t.Fatal("critical suggested")
	}
	p.Risk = model.RiskLow
	f.Strong = true
	if AllowlistProposal(p, f) != "" {
		t.Fatal("strong suggested")
	}
	f.Strong = false
	p.Exe = "/tmp/escape\npath"
	if AllowlistProposal(p, f) != "" {
		t.Fatal("control path suggested")
	}
	if len(WeakAllowRules([]AllowRule{{Exe: "/opt/*", Rules: []string{"a"}}, {Exe: "/opt/exact", Exact: true, Rules: []string{"a"}}})) != 1 {
		t.Fatal("weak scope detection")
	}
}

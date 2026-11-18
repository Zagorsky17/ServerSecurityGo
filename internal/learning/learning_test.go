package learning

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lowProcess() *model.Process {
	return &model.Process{Exe: "/opt/app", User: "app", Risk: model.RiskLow, Findings: []model.Finding{{ID: "cpu_sustained", Weight: 8, Category: model.CatBehavior}}}
}
func TestLearningWindowPersistenceAndNoAutomaticTrust(t *testing.T) {
	dir := t.TempDir()
	tr := New(dir, 1, nil)
	now := time.Now()
	p := lowProcess()
	var r *model.LearningReport
	for _, d := range []time.Duration{0, 2 * time.Minute, 5 * time.Minute} {
		r = tr.Observe(now.Add(d), []*model.Process{p, p})
	}
	if !strings.HasPrefix(r.BaselineCommand, "serversecuritygo baseline save --name reviewed-") || len(r.Candidates) != 1 || r.Candidates[0].Count != 3 || p.Findings[0].Suppressed || p.Risk != model.RiskLow {
		t.Fatal(r, p)
	}
	var proposal struct{ Rules []detect.AllowRule }
	if e := json.Unmarshal([]byte(r.Candidates[0].Proposal), &proposal); e != nil || len(proposal.Rules) != 1 || !proposal.Rules[0].Exact {
		t.Fatal(proposal, e)
	}
	before, _ := json.Marshal(r)
	restart := New(dir, 1, nil)
	r2 := restart.Observe(now.Add(2*time.Hour), []*model.Process{p})
	if r2.Enabled || !r2.Until.Equal(r.Until) || len(r2.Candidates) != 1 {
		t.Fatal(r2)
	}
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("mutated prior report")
	}
	p.Risk = model.RiskCritical
	if got := restart.Observe(now.Add(3*time.Hour), []*model.Process{p}); len(got.Candidates) != 0 || got.BaselineCommand != "" {
		t.Fatal("critical proposal", got)
	}
	p.Risk = model.RiskLow
	p.Findings[0].Strong = true
	if got := restart.Observe(now.Add(4*time.Hour), []*model.Process{p}); len(got.Candidates) != 0 || got.BaselineCommand != "" {
		t.Fatal("strong proposal", got)
	}
	if e := New("", 0, nil); e != nil {
		t.Fatal("disabled learning allocated state")
	}
	fi, e := os.Stat(filepath.Join(dir, "learning.json"))
	if e != nil || fi.Mode().Perm() != 0600 {
		t.Fatal(fi, e)
	}
}
func TestLearningCorruptStateClockAndUnusedRules(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "learning.json"), []byte("{}"), 0600)
	tr := New(dir, 1, nil)
	r := tr.Observe(time.Now(), []*model.Process{lowProcess()})
	if len(r.Warnings) == 0 || len(r.Candidates) != 0 {
		t.Fatal(r)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "learning.json"))
	if string(data) != "{}" {
		t.Fatal("overwrote bad state")
	}
	now := time.Now()
	tr = New("", 1, []detect.AllowRule{{Exe: "/opt/unused", Exact: true, Rules: []string{"cpu_sustained"}}})
	tr.Observe(now, nil)
	r = tr.Observe(now.Add(31*24*time.Hour), nil)
	found := false
	for _, w := range r.Warnings {
		found = found || strings.Contains(w.In(i18n.EN), "not matched")
	}
	if !found {
		t.Fatal(r)
	}
	r = tr.Observe(now, nil)
	if len(r.Warnings) == 0 || r.Enabled {
		t.Fatal("clock reversal accepted", r)
	}
}

func TestUsageBudgetCannotClaimUnusedWhenUnobserved(t *testing.T) {
	rules := make([]detect.AllowRule, 1000)
	for i := range rules {
		rules[i] = detect.AllowRule{Exe: "/opt/unused", Exact: true, Rules: []string{"cpu_sustained"}}
	}
	ps := make([]*model.Process, 101)
	for i := range ps {
		ps[i] = lowProcess()
	}
	tr := New("", 0, rules)
	now := time.Now()
	tr.Observe(now, ps)
	r := tr.Observe(now.Add(31*24*time.Hour), ps)
	limited := false
	for _, w := range r.Warnings {
		limited = limited || w.Key == "warn.learning_limit"
	}
	if !limited {
		t.Fatal("missing comparison limit")
	}
	// Все правила одинаковы и разделяют ключ; последнее неполное наблюдение сбрасывает возраст.
	u := tr.state.Rules[digest(rules[0])]
	if !u.First.Equal(now.Add(31 * 24 * time.Hour)) {
		t.Fatal(u)
	}
}

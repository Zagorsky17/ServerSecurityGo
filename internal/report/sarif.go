package report

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"io"
	"net/url"
	"strings"
)

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Kind         string            `json:"kind,omitempty"`
	Message      map[string]string `json:"message"`
	Locations    []any             `json:"locations,omitempty"`
	Suppressions []any             `json:"suppressions,omitempty"`
	Properties   map[string]any    `json:"properties"`
}

func sarifFinding(f model.Finding, risk model.Risk, path string, l i18n.Lang) sarifResult {
	level := "note"
	if risk >= model.RiskHigh {
		level = "error"
	} else if risk >= model.RiskLow {
		level = "warning"
	}
	if f.Category == model.CatInfo {
		level = "note"
	}
	text := f.Title.In(l)
	for _, e := range f.Evidence {
		text += "\n" + e.In(l)
	}
	r := sarifResult{RuleID: f.ID, Level: level, Message: map[string]string{"text": text}, Properties: map[string]any{"risk": risk.String(), "category": f.Category, "attack": nonNil(f.Attack), "recommendation": f.Recommendation.In(l), "why": f.Why.In(l), "legitimate": f.Legitimate.In(l), "verifyCommands": nonNil(f.VerifyCommands)}}
	if f.Suppressed {
		r.Suppressions = []any{map[string]string{"kind": "external", "status": "accepted"}}
	}
	if strings.HasPrefix(path, "/") {
		u := url.URL{Scheme: "file", Path: path}
		r.Locations = []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": u.String()}}}}
	}
	return r
}
func (s *Scan) sarifResults(l i18n.Lang) []sarifResult {
	out := []sarifResult{}
	for _, p := range s.procs {
		for _, f := range p.Findings {
			r := sarifFinding(f, p.Risk, p.Exe, l)
			r.Properties["processKey"] = p.Key
			r.Properties["pid"] = p.PID
			r.Properties["user"] = p.User
			out = append(out, r)
		}
	}
	for _, f := range s.system {
		out = append(out, sarifFinding(f.Finding, f.Risk, f.Path, l))
	}
	return out
}
func auditSARIF(checks []model.AuditCheck, l i18n.Lang) []sarifResult {
	out := []sarifResult{}
	for _, c := range checks {
		f := model.Finding{ID: c.ID, Title: c.Title, Evidence: c.Evidence, Recommendation: c.Recommendation, FindingContext: c.FindingContext, VerifyCommands: c.VerifyCommands}
		r := sarifFinding(f, c.Severity, "", l)
		r.Properties["status"] = c.Status
		switch c.Status {
		case model.AuditInfo:
			r.Kind = "informational"
			r.Level = "note"
		case model.AuditPass:
			r.Kind = "pass"
			r.Level = "none"
		case model.AuditNA:
			r.Kind = "notApplicable"
			r.Level = "none"
		case model.AuditUnknown:
			r.Kind = "review"
			r.Level = "none"
		default:
			r.Kind = "fail"
		}
		out = append(out, r)
	}
	return out
}
func renderSARIF(w io.Writer, version, kind string, incomplete bool, results []sarifResult) error {
	rules := []any{}
	seen := map[string]bool{}
	for _, r := range results {
		if !seen[r.RuleID] {
			seen[r.RuleID] = true
			rules = append(rules, map[string]any{"id": r.RuleID})
		}
	}
	out := map[string]any{"version": "2.1.0", "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "ServerSecurityGo", "version": version, "rules": rules}},
		"results": nonNil(results), "invocations": []any{map[string]any{"executionSuccessful": !incomplete}}, "properties": map[string]any{"kind": kind, "incomplete": incomplete},
	}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

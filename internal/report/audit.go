package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

// Audit — отчёт проверки настроек безопасности.
type Audit struct {
	View     view.AuditView
	Hostname string
	Version  string
	// All — выводить и пройденные/неприменимые проверки (в тексте и
	// Markdown; HTML и JSON содержат все проверки всегда).
	All bool
}

// Verdict — наивысшая важность среди проблем (fail и warn).
func (a *Audit) Verdict() (model.Risk, bool) {
	v, found := model.RiskInfo, false
	for _, c := range a.View.Checks {
		if c.Status == model.AuditFail || c.Status == model.AuditWarn {
			v, found = max(v, c.Severity), true
		}
	}
	return v, found
}

// Incomplete — часть проверок не выполнена из-за нехватки прав.
func (a *Audit) Incomplete() bool { return a.View.Summary.Unknown > 0 }

// ExitCode — код выхода по порогу --fail-on.
func (a *Audit) ExitCode(f FailOn) int {
	v, found := a.Verdict()
	return ExitCode(found, v, f, a.Incomplete())
}

// Render выводит отчёт в нужном формате на языке l.
func (a *Audit) Render(w io.Writer, f Format, l i18n.Lang) error {
	switch f {
	case JSON:
		v, found := a.Verdict()
		out, err := i18n.RenderJSON(map[string]any{
			"schema_version": SchemaVersion, "kind": "audit", "tool": "serversecuritygo", "version": a.Version, "hostname": a.Hostname,
			"verdict": v, "found": found, "incomplete": a.Incomplete(),
			// Поля представления — как в GET /api/audit.
			"time": a.View.Time, "passed": a.View.Passed, "total": a.View.Total, "summary": a.View.Summary, "groups": a.View.Groups, "checks": a.View.Checks,
		}, l)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case HTML:
		return renderHTML(w, a.doc(l, true))
	case Markdown:
		return renderMarkdown(w, a.doc(l, a.All))
	}
	return a.renderText(w, l)
}

// shown — проверка попадает в краткий вывод: только то, на что стоит
// посмотреть (не пройденные и не неприменимые).
func (a *Audit) shown(c model.AuditCheck, all bool) bool {
	return all || (c.Status != model.AuditPass && c.Status != model.AuditNA)
}

// renderText — вывод для терминала. Факты — строки конфигов, они идут
// через view.Printable; команда исправления — постоянный текст.
func (a *Audit) renderText(w io.Writer, l i18n.Lang) error {
	pr := view.Printable
	v := a.View
	s := v.Summary
	fmt.Fprintln(w, i18n.T("cli.audit.header", v.Passed, v.Total, s.Fail, s.Warn, s.Info).In(l))
	for _, c := range v.Checks {
		if !a.shown(c, a.All) {
			continue
		}
		fmt.Fprintf(w, "\n[%s] %s · %s · %s\n", strings.ToUpper(c.Status), c.Severity, c.Group, pr(c.Title.In(l)))
		for _, e := range c.Evidence {
			fmt.Fprintln(w, "    "+pr(e.In(l)))
		}
		if !c.Recommendation.IsZero() {
			fmt.Fprintln(w, "  → "+pr(c.Recommendation.In(l)))
		}
		if c.FixCommand != "" {
			fmt.Fprintln(w, "  $ "+pr(c.FixCommand))
		}
	}
	_, err := fmt.Fprintln(w, "\n"+i18n.T("cli.audit.footer").In(l))
	return err
}

func (a *Audit) doc(l i18n.Lang, all bool) *doc {
	tr := func(k string, args ...any) string { return i18n.T(k, args...).In(l) }
	v := a.View
	verdict, found := a.Verdict()
	d := &doc{Lang: string(l),
		Title:    tr("report.title_audit", view.Printable(a.Hostname)),
		Subtitle: tr("report.generated_audit", v.Time.Local().Format("2006-01-02 15:04:05"), a.Version),
		Verdict:  verdict.String(), Class: "risk-" + verdict.String(),
		Summary: tr("web.audit.score", v.Passed, v.Total, v.Summary.Fail, v.Summary.Warn, v.Summary.Info, v.Summary.NA+v.Summary.Unknown),
		Footer:  tr("cli.audit.footer"),
	}
	if !found {
		d.Verdict, d.Class = tr("report.verdict_ok"), "st-pass"
	}
	if a.Incomplete() {
		d.Notes = append(d.Notes, tr("report.audit_incomplete", v.Summary.Unknown))
	}
	sec := section{Title: tr("report.h.checks"), Empty: tr("report.no_problems"),
		Columns: []string{tr("web.col.status"), tr("web.col.group"), tr("tui.title.check"), tr("web.col.severity"), tr("tui.h.facts"), tr("tui.h.recommendation")}}
	for _, c := range v.Checks {
		if !a.shown(c, all) {
			continue
		}
		var ev []string
		for _, e := range c.Evidence {
			ev = append(ev, e.In(l))
		}
		sev := ""
		if c.Status == model.AuditFail || c.Status == model.AuditWarn {
			sev = c.Severity.String()
		}
		sevCell := txt(sev)
		if sev != "" {
			sevCell = badge("risk-"+sev, sev)
		}
		rec := txt(c.Recommendation.In(l))
		if c.FixCommand != "" {
			rec = withCode(rec, c.FixCommand)
		}
		sec.Rows = append(sec.Rows, []cell{badge(statusClass(c.Status), statusText(c.Status, l)), txt(groupText(c.Group, l)), txt(c.Title.In(l)), sevCell, list(ev), rec})
	}
	d.Sections = []section{sec}
	return d
}

func statusClass(s string) string {
	switch s {
	case model.AuditFail:
		return "st-fail"
	case model.AuditWarn:
		return "st-warn"
	case model.AuditPass:
		return "st-pass"
	case model.AuditInfo:
		return "st-info"
	}
	return "st-na"
}

func statusText(s string, l i18n.Lang) string { return view.AuditStatusText(s).In(l) }

func groupText(g string, l i18n.Lang) string { return view.AuditGroupText(g).In(l) }

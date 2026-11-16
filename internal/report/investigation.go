package report

import (
	"encoding/json"
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
	"io"
	"sort"
	"strings"
	"time"
)

type Priority struct {
	Risk     model.Risk `json:"risk"`
	Title    i18n.Msg   `json:"title"`
	Commands []string   `json:"commands"`
}
type Investigation struct {
	SchemaVersion int                   `json:"schema_version"`
	Version       string                `json:"version"`
	Time          time.Time             `json:"time"`
	Kind          string                `json:"kind"`
	Snapshot      *model.Snapshot       `json:"snapshot,omitempty"`
	Audit         *model.AuditReport    `json:"audit,omitempty"`
	Recent        *model.RecentReport   `json:"recent,omitempty"`
	Timeline      []model.TimelineEvent `json:"timeline,omitempty"`
	Priority      []Priority            `json:"priority,omitempty"`
	Verdict       i18n.Msg              `json:"verdict"`
	Incomplete    bool                  `json:"incomplete"`
	Warnings      []i18n.Msg            `json:"warnings"`
}

func (r *Investigation) Summarize() {
	r.SchemaVersion = 1
	highest := model.RiskInfo
	if r.Snapshot != nil {
		r.Incomplete = r.Incomplete || NewScan(r.Snapshot, model.RiskInfo, r.Version).Incomplete()
		r.Warnings = append(r.Warnings, r.Snapshot.Warnings...)
		for _, p := range r.Snapshot.Processes {
			if p.Risk < model.RiskLow {
				continue
			}
			for _, f := range p.Findings {
				if f.Suppressed {
					continue
				}
				r.Priority = append(r.Priority, Priority{p.Risk, f.Title, f.VerifyCommands})
			}
			highest = max(highest, p.Risk)
		}
		for _, f := range r.Snapshot.System {
			if f.Risk < model.RiskLow || f.Suppressed {
				continue
			}
			r.Priority = append(r.Priority, Priority{f.Risk, f.Title, f.VerifyCommands})
			highest = max(highest, f.Risk)
		}
	}
	sort.SliceStable(r.Priority, func(i, j int) bool { return r.Priority[i].Risk > r.Priority[j].Risk })
	if len(r.Priority) > 10 {
		r.Priority = r.Priority[:10]
	}
	r.Verdict = i18n.T("report.triage_none")
	if highest >= model.RiskLow {
		r.Verdict = i18n.T("report.triage_review")
	}
	if highest >= model.RiskCritical {
		r.Verdict = i18n.T("report.triage_high")
	}
	if r.Recent != nil {
		r.Incomplete = r.Incomplete || r.Recent.Incomplete
		r.Warnings = append(r.Warnings, r.Recent.Warnings...)
	}
	r.Warnings = append(r.Warnings, i18n.T("warn.triage_trust"))
}
func (r *Investigation) Render(w io.Writer, f Format, l i18n.Lang) error {
	if f == JSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	d := &doc{Lang: string(l), Title: r.Kind, Subtitle: r.Time.Format(time.RFC3339), Verdict: r.Verdict.In(l), Summary: i18n.T("report.investigation_state", r.Incomplete).In(l)}
	for _, n := range r.Warnings {
		d.Notes = append(d.Notes, view.Printable(n.In(l)))
	}
	priorities := section{Title: i18n.T("report.priority").In(l), Columns: []string{i18n.T("web.col.risk").In(l), i18n.T("report.priority").In(l), i18n.T("report.verify").In(l)}}
	for _, p := range r.Priority {
		priorities.Rows = append(priorities.Rows, []cell{txt(p.Risk.String()), txt(p.Title.In(l)), list(p.Commands)})
	}
	d.Sections = append(d.Sections, priorities)
	if r.Snapshot != nil && r.Snapshot.Auth != nil {
		s := section{Title: i18n.T("web.tab.logins").In(l), Columns: []string{"UTC", i18n.T("tui.title.event").In(l), i18n.T("tui.k.user").In(l), "IP", i18n.T("web.auth.method").In(l), i18n.T("web.auth.key").In(l)}}
		for _, e := range r.Snapshot.Auth.Events {
			s.Rows = append(s.Rows, []cell{txt(e.Time.UTC().Format(time.RFC3339)), txt(e.Kind), txt(e.User), txt(e.IP), txt(e.Method), txt(e.Fingerprint + " " + e.KeyComment)})
		}
		d.Sections = append(d.Sections, s)
	}
	if r.Audit != nil {
		s := section{Title: i18n.T("web.tab.audit").In(l), Columns: []string{"ID", i18n.T("tui.panel.status").In(l), i18n.T("web.col.risk").In(l)}}
		for _, c := range r.Audit.Checks {
			s.Rows = append(s.Rows, []cell{txt(c.ID), txt(c.Status), txt(c.Severity.String())})
		}
		d.Sections = append(d.Sections, s)
	}
	if r.Recent != nil {
		s := section{Title: "recent", Columns: []string{i18n.T("tui.k.file").In(l), "mtime", "ctime", i18n.T("report.package_window").In(l)}}
		for _, e := range r.Recent.Files {
			s.Rows = append(s.Rows, []cell{txt(e.Path), txt(e.ModTime.Format(time.RFC3339)), txt(e.ChangeTime.Format(time.RFC3339)), txt(fmt.Sprint(e.PackageWindow))})
		}
		d.Sections = append(d.Sections, s)
	}
	if r.Timeline != nil {
		s := section{Title: i18n.T("web.tab.timeline").In(l), Columns: []string{"UTC", i18n.T("tui.title.event").In(l), i18n.T("tui.k.file").In(l), i18n.T("tui.title.details").In(l)}}
		for _, e := range r.Timeline {
			s.Rows = append(s.Rows, []cell{txt(e.Time.UTC().Format(time.RFC3339)), txt(e.Kind), txt(e.Source), txt(e.Detail.In(l))})
		}
		d.Sections = append(d.Sections, s)
	}
	switch f {
	case HTML:
		return renderHTML(w, d)
	case Markdown:
		return renderMarkdown(w, d)
	default:
		if _, e := fmt.Fprintf(w, "%s\n%s\n", view.Printable(d.Verdict), d.Summary); e != nil {
			return e
		}
		for _, n := range d.Notes {
			if _, e := fmt.Fprintln(w, n); e != nil {
				return e
			}
		}
		for _, s := range d.Sections {
			fmt.Fprintln(w, s.Title)
			for _, row := range s.Rows {
				var cols []string
				for _, c := range row {
					cols = append(cols, c.Text+strings.Join(c.List, "; "))
				}
				if _, e := fmt.Fprintln(w, strings.Join(cols, " | ")); e != nil {
					return e
				}
			}
		}
		return nil
	}
}

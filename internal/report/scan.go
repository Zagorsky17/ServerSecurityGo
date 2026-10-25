package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/exposure"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

// Scan — отчёт разового сканирования процессов.
type Scan struct {
	Snap    *model.Snapshot
	MinRisk model.Risk // ниже этого уровня процессы и находки не выводятся
	Version string

	procs    []*model.Process      // от MinRisk, по убыванию риска
	system   []model.SystemFinding // от MinRisk
	exposure *model.ExposureReport
	ports    []model.Exposure // публичные порты
}

// NewScan готовит отчёт по снимку.
func NewScan(snap *model.Snapshot, min model.Risk, version string) *Scan {
	s := &Scan{Snap: snap, MinRisk: min, Version: version}
	for _, p := range snap.Processes {
		if p.Risk >= min {
			s.procs = append(s.procs, p)
		}
	}
	sort.SliceStable(s.procs, func(i, j int) bool {
		if s.procs[i].Risk != s.procs[j].Risk {
			return s.procs[i].Risk > s.procs[j].Risk
		}
		return s.procs[i].Score > s.procs[j].Score
	})
	for _, f := range snap.System {
		if f.Risk >= min {
			s.system = append(s.system, f)
		}
	}
	s.exposure = view.Exposure(snap)
	for _, e := range s.exposure.Entries {
		if e.Scope == model.ScopePublic {
			s.ports = append(s.ports, e)
		}
	}
	return s
}

// Verdict — наивысший уровень среди всех процессов и системных находок
// (независимо от MinRisk) и есть ли находки уровня LOW и выше.
func (s *Scan) Verdict() (model.Risk, bool) {
	v := model.RiskInfo
	for _, p := range s.Snap.Processes {
		v = max(v, p.Risk)
	}
	for _, f := range s.Snap.System {
		v = max(v, f.Risk)
	}
	return v, v >= model.RiskLow
}

// Incomplete — часть данных не прочитана (нет прав на процессы).
func (s *Scan) Incomplete() bool {
	return s.Snap.Stats.Restricted > 0 || !s.Snap.Host.IsRoot
}

// ExitCode — код выхода по порогу --fail-on.
func (s *Scan) ExitCode(f FailOn) int {
	v, found := s.Verdict()
	return ExitCode(found, v, f, s.Incomplete())
}

// Render выводит отчёт в нужном формате на языке l.
func (s *Scan) Render(w io.Writer, f Format, l i18n.Lang) error {
	switch f {
	case JSON:
		return s.renderJSON(w, l)
	case HTML:
		return renderHTML(w, s.doc(l))
	case Markdown:
		return renderMarkdown(w, s.doc(l))
	}
	return s.renderText(w, l)
}

// renderJSON — стабильная схема (schema_version). Поля прежнего вывода
// scan --format json сохранены; сообщения отданы готовым текстом.
func (s *Scan) renderJSON(w io.Writer, l i18n.Lang) error {
	v, found := s.Verdict()
	out, err := i18n.RenderJSON(map[string]any{
		"schema_version": SchemaVersion, "kind": "scan", "tool": "serversecuritygo", "version": s.Version,
		"time": s.Snap.Time, "host": s.Snap.Host, "stats": s.Snap.Stats, "warnings": s.Snap.Warnings,
		"minRisk": s.MinRisk, "verdict": v, "found": found, "incomplete": s.Incomplete(),
		"processes": nonNil(s.procs), "system": nonNil(s.system), "exposure": s.exposure,
	}, l)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// renderText — таблица для терминала. Всё, что задаёт процесс, проходит
// через view.Printable: ESC-последовательности из имени процесса сменили
// бы заголовок окна или записали бы буфер обмена (OSC 52).
func (s *Scan) renderText(w io.Writer, l i18n.Lang) error {
	tr := func(k string, a ...any) string { return i18n.T(k, a...).In(l) }
	pr := view.Printable
	snap := s.Snap
	fmt.Fprintln(w, tr("cli.scan.host", pr(snap.Host.Hostname), pr(snap.Host.OS), pr(snap.Host.Kernel), snap.Stats.Total, snap.Stats.Sockets, snap.Duration.Round(time.Millisecond)))
	for _, m := range snap.Warnings {
		fmt.Fprintln(w, "! "+pr(m.In(l)))
	}
	by := snap.Stats.ByRisk
	fmt.Fprintln(w, tr("cli.scan.levels", by["CRITICAL"], by["HIGH"], by["MEDIUM"], by["LOW"], by["INFO"]))
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, tr("cli.scan.header"))
	for _, p := range s.procs {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t%s\n", p.Risk, p.Score, p.PID, pr(p.User), pr(p.Name), pr(exeText(p, l)), pr(strings.Join(findingTitles(p, l), "; ")))
	}
	tw.Flush()
	if len(s.procs) == 0 {
		fmt.Fprintln(w, tr("cli.scan.none", s.MinRisk))
	}
	if len(s.system) > 0 {
		fmt.Fprintln(w, "\n"+tr("cli.scan.system"))
		for _, f := range s.system {
			fmt.Fprintf(w, "  [%s] %s — %s\n", f.Risk, pr(f.Title.In(l)), pr(f.Path))
			for _, e := range f.Evidence {
				fmt.Fprintln(w, "      "+pr(e.In(l)))
			}
		}
	}
	if len(s.ports) > 0 {
		fmt.Fprintln(w, "\n"+tr("cli.scan.ports"))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  "+tr("cli.scan.ports_header"))
		for _, e := range s.ports {
			svc, owner, fw := portCells(e, l)
			risk := e.Risk.String()
			if e.Suppressed {
				risk += "*"
			}
			fmt.Fprintf(tw, "  %s\t%s %s\t%s\t%s\t%s\n", risk, e.Proto, pr(exposure.Endpoint(e.Addr, e.Port)), pr(svc), pr(owner), fw)
		}
		tw.Flush()
	}
	_, err := fmt.Fprintln(w, "\n"+tr("cli.scan.footer"))
	return err
}

func exeText(p *model.Process, l i18n.Lang) string {
	if p.ExeDeleted {
		return p.Exe + " " + i18n.T("tui.deleted").In(l)
	}
	return p.Exe
}

func findingTitles(p *model.Process, l i18n.Lang) []string {
	var out []string
	for _, f := range p.Findings {
		if f.Category != model.CatInfo && !f.Suppressed {
			out = append(out, f.Title.In(l))
		}
	}
	return out
}

// portCells — сервис, владелец и состояние межсетевого экрана порта.
func portCells(e model.Exposure, l i18n.Lang) (svc, owner, fw string) {
	svc, owner, fw = "—", "—", "—"
	if e.Service != nil {
		svc = e.Service.Name
	}
	switch {
	case e.PID != 0:
		owner = fmt.Sprintf("%s (%d)", e.ProcName, e.PID)
	case e.Container != "":
		owner = "docker " + e.Container
	}
	switch e.Firewall {
	case model.FwOpen:
		fw = i18n.T("tui.fw.open").In(l)
	case model.FwFiltered:
		fw = i18n.T("tui.fw.filtered").In(l)
	case model.FwBypassed:
		fw = i18n.T("tui.fw.bypassed").In(l)
	}
	return svc, owner, fw
}

// doc — отчёт для HTML и Markdown.
func (s *Scan) doc(l i18n.Lang) *doc {
	tr := func(k string, a ...any) string { return i18n.T(k, a...).In(l) }
	snap := s.Snap
	v, found := s.Verdict()
	d := &doc{Lang: string(l),
		Title:    tr("report.title_scan", view.Printable(snap.Host.Hostname)),
		Subtitle: tr("report.generated", snap.Time.Local().Format("2006-01-02 15:04:05"), view.Printable(snap.Host.OS), view.Printable(snap.Host.Kernel), s.Version),
		Verdict:  v.String(), Class: "risk-" + v.String(),
		Footer: tr("cli.scan.footer"),
	}
	by := snap.Stats.ByRisk
	// Системные находки — как в сводке панели: от LOW (подавленные
	// allowlist и справочные не считаются).
	sysCount := 0
	for _, f := range snap.System {
		if f.Risk >= model.RiskLow {
			sysCount++
		}
	}
	d.Summary = tr("report.scan_summary", snap.Stats.Total, by["CRITICAL"], by["HIGH"], by["MEDIUM"], by["LOW"], sysCount, snap.Stats.PublicPorts, snap.Stats.DangerousPorts)
	if !found {
		d.Verdict, d.Class = tr("report.verdict_ok"), "st-pass"
	}
	for _, m := range snap.Warnings {
		d.Notes = append(d.Notes, view.Printable(m.In(l)))
	}

	procs := section{Title: tr("report.h.processes", s.MinRisk), Empty: tr("cli.scan.none", s.MinRisk),
		Columns: []string{tr("web.col.risk"), tr("web.col.score"), "PID", tr("tui.k.user"), tr("tui.k.name"), tr("tui.k.path"), tr("tui.h.findings"), tr("tui.h.recommendations")}}
	for _, p := range s.procs {
		var recs []string
		for _, r := range p.Recommendations {
			recs = append(recs, r.In(l))
		}
		procs.Rows = append(procs.Rows, []cell{badge("risk-"+p.Risk.String(), p.Risk.String()), txt(fmt.Sprint(p.Score)), txt(fmt.Sprint(p.PID)),
			txt(p.User), txt(p.Name), txt(exeText(p, l)), list(findingTitles(p, l)), list(recs)})
	}
	sys := section{Title: tr("cli.scan.system"), Empty: tr("web.empty.system"),
		Columns: []string{tr("web.col.risk"), tr("tui.title.check"), tr("tui.k.file"), tr("tui.h.facts"), tr("tui.h.recommendation")}}
	for _, f := range s.system {
		var ev []string
		for _, e := range f.Evidence {
			ev = append(ev, e.In(l))
		}
		sys.Rows = append(sys.Rows, []cell{badge("risk-"+f.Risk.String(), f.Risk.String()), txt(f.Title.In(l)), txt(f.Path), list(ev), txt(f.Recommendation.In(l))})
	}
	ports := section{Title: tr("cli.scan.ports"), Empty: tr("report.no_public_ports"),
		Columns: []string{tr("web.col.risk"), tr("tui.k.address"), tr("tui.k.service"), tr("tui.title.process"), tr("tui.k.firewall"), tr("tui.h.recommendation")}}
	for _, e := range s.ports {
		svc, owner, fw := portCells(e, l)
		ports.Rows = append(ports.Rows, []cell{badge("risk-"+e.Risk.String(), e.Risk.String()), txt(e.Proto + " " + exposure.Endpoint(e.Addr, e.Port)),
			txt(svc), txt(owner), txt(fw), txt(e.Recommendation.In(l))})
	}
	d.Sections = []section{procs, sys, ports}
	return d
}

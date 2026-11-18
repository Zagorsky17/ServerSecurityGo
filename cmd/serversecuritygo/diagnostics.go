package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/doctor"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/investigate"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func cmdDiagnostics(kind string, args []string) error {
	code, e := runDiagnostics(kind, args)
	if e != nil {
		return report.AsRunError(e)
	}
	return exitCode(code)
}
func runDiagnostics(kind string, args []string) (int, error) {
	id := ""
	if kind == "explain" {
		if len(args) == 0 {
			return 0, i18n.Errorf("cli.diagnostics_usage")
		}
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	env := fs.String("env-file", "", i18n.S("cli.flag.env_file"))
	format := fs.String("format", "text", i18n.S("cli.flag.format"))
	output := fs.String("output", "", i18n.S("cli.flag.output"))
	if e := fs.Parse(args); e != nil {
		return 0, e
	}
	if fs.NArg() != 0 {
		return 0, i18n.Errorf("cli.diagnostics_usage")
	}
	f, e := report.ParseFormat(*format)
	if e != nil {
		return 0, e
	}
	if kind == "explain" && f != report.Text && f != report.JSON {
		return 0, i18n.Errorf("cli.diagnostics_usage")
	}
	cfg, e := loadConfig(*env)
	if e != nil {
		return 0, e
	}
	lang := i18n.Default()
	if kind == "explain" {
		explanation, e := investigate.Explain(id)
		if e != nil {
			return 0, e
		}
		return 0, report.Write(*output, func(w io.Writer) error {
			if f == report.JSON {
				v, e := i18n.RenderJSON(explanation, lang)
				if e != nil {
					return e
				}
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(v)
			}
			_, e := fmt.Fprintf(w, "%s\n%s\n\n%s\n%s\n%s\n%s\n", id, view.Printable(explanation.Title.In(lang)), i18n.T("cli.explain_template").In(lang), explanation.Why.In(lang), explanation.Legitimate.In(lang), explanation.Recommendation.In(lang))
			if e != nil {
				return e
			}
			for _, a := range explanation.Attack {
				if _, e = fmt.Fprintln(w, a); e != nil {
					return e
				}
			}
			if _, e = fmt.Fprintf(w, "%s\n%s\n%s\n", i18n.T("card.confidence").In(lang), explanation.Confidence.In(lang), i18n.T("card.verify").In(lang)); e != nil {
				return e
			}
			for _, c := range explanation.VerifyCommands {
				if _, e = fmt.Fprintln(w, view.Printable(c)); e != nil {
					return e
				}
			}
			return nil
		})
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	r := doctor.Run(ctx, cfg)
	a := &report.Audit{View: view.BuildAudit(true, false, 0, r), Version: version, All: true}
	if e := report.Write(*output, func(w io.Writer) error { return a.Render(w, f, lang) }); e != nil {
		return 0, e
	}
	return a.ExitCode(report.FailOn{Level: model.RiskLow}), nil
}

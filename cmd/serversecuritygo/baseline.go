package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/audit"
	"github.com/Zagorsky17/ServerSecurityGo/internal/baseline"
	"github.com/Zagorsky17/ServerSecurityGo/internal/config"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func cmdBaseline(kind string, args []string) error {
	action := "diff"
	if kind == "baseline" {
		if len(args) == 0 {
			return i18n.Errorf("err.baseline_usage")
		}
		action, args = args[0], args[1:]
	}
	if action != "diff" && action != "save" && action != "list" && action != "accept" {
		return i18n.Errorf("err.baseline_usage")
	}
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	env := fs.String("env-file", "", i18n.S("cli.flag.env_file"))
	name := fs.String("name", "", i18n.S("cli.baseline.name"))
	from := fs.String("from", "installation", i18n.S("cli.baseline.from"))
	to := fs.String("to", "now", i18n.S("cli.baseline.to"))
	ports := fs.Bool("ports", false, i18n.S("cli.baseline.ports"))
	format := fs.String("format", "text", i18n.S("cli.flag.format"))
	output := fs.String("output", "", i18n.S("cli.flag.output"))
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || (*format != "text" && *format != "json") || (action == "accept" && !*ports) || (action != "accept" && *ports) {
		return i18n.Errorf("err.baseline_usage")
	}
	cfg, e := loadConfig(*env)
	if e != nil {
		return e
	}
	store := baseline.New(cfg.DataDir)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var result any
	incomplete := false
	switch action {
	case "list":
		result, e = store.List()
	case "save", "accept":
		if cfg.DataDir == "" {
			return i18n.Errorf("err.baseline_private")
		}
		if e = os.MkdirAll(cfg.DataDir, 0700); e != nil {
			return e
		}
		var b *model.BaselineSnapshot
		b, e = captureBaseline(ctx, cfg, action == "accept")
		if e != nil {
			return e
		}
		if action == "accept" {
			e = store.AcceptPorts(b)
			result = map[string]string{"accepted": "ports"}
		} else {
			if *name == "" {
				*name = "manual-" + fmt.Sprint(b.Time.UnixNano())
			}
			e = store.Save(*name, b)
			result = struct {
				Name     string                  `json:"name"`
				Snapshot *model.BaselineSnapshot `json:"snapshot"`
			}{*name, b}
			for _, s := range b.Sections {
				incomplete = incomplete || !s.Complete
			}
		}
	case "diff":
		var a, b *model.BaselineSnapshot
		a, e = store.Load(*from)
		if e != nil {
			return e
		}
		if *to == "now" {
			b, e = captureBaseline(ctx, cfg, false)
		} else {
			b, e = store.Load(*to)
		}
		if e != nil {
			return e
		}
		d := baseline.Diff(a, b)
		result = d
		incomplete = d.Incomplete
	}
	if e != nil {
		return e
	}
	e = report.Write(*output, func(w io.Writer) error {
		if *format == "json" {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		}
		if d, ok := result.(*model.BaselineDiff); ok {
			fmt.Fprintf(w, "%s → %s\n", d.From.Format(time.RFC3339), d.To.Format(time.RFC3339))
			for _, c := range d.Changes {
				fmt.Fprintln(w, view.Printable(c.Section+" "+c.Kind+" "+c.Key+" | "+c.Before+" → "+c.After))
			}
			for _, msg := range d.Warnings {
				fmt.Fprintln(w, msg.In(i18n.Default()))
			}
			return nil
		}
		if names, ok := result.([]string); ok {
			sort.Strings(names)
			for _, n := range names {
				fmt.Fprintln(w, n)
			}
			return nil
		}
		fmt.Fprintln(w, i18n.S("cli.baseline.saved", *name))
		if incomplete {
			fmt.Fprintln(w, i18n.S("warn.baseline_partial"))
		}
		return nil
	})
	if e != nil {
		return e
	}
	if incomplete {
		return exitCode(report.ExitIncomplete)
	}
	return nil
}
func captureBaseline(ctx context.Context, cfg config.Config, portsOnly bool) (*model.BaselineSnapshot, error) {
	if filepath.Clean(cfg.HostRoot) != "/" && filepath.Clean(cfg.ProcRoot) == "/proc" {
		cfg.ProcRoot = filepath.Join(cfg.HostRoot, "proc")
	}
	det, e := cfg.DetectConfig()
	if e != nil {
		return nil, e
	}
	h, e := history.Open(history.Options{})
	if e != nil {
		return nil, e
	}
	pfs := procfs.New(cfg.ProcRoot, cfg.HostRoot)
	pfs.MaxFiles = cfg.MaxFiles
	pfs.MaxSockets = cfg.NetMaxSockets
	fi := fileInventory(cfg, true)
	if !portsOnly {
		fi.RunOnce(ctx)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	sc := scanner.New(scanner.Options{FS: pfs, Detect: det, History: h, Logger: newLogger("error"), Inventory: fi, Auth: authCollector(cfg, true)})
	snap, e := sc.ScanOnce()
	if e != nil {
		return nil, e
	}
	var ar *model.AuditReport
	if !portsOnly {
		checks, _ := audit.Run(audit.Options{HostRoot: cfg.HostRoot, ProcRoot: cfg.ProcRoot, Inventory: snap.Inventory, Exposure: snap.Exposure})
		ar = &model.AuditReport{Time: time.Now(), Checks: checks}
	}
	b := baseline.Capture(ctx, cfg.HostRoot, cfg.ProcRoot, snap, ar)
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return b, nil
}

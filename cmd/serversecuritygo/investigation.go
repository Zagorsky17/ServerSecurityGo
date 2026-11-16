package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/audit"
	"github.com/Zagorsky17/ServerSecurityGo/internal/collect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/investigate"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
	"github.com/Zagorsky17/ServerSecurityGo/internal/rootkit"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
)

func cmdInvestigation(kind string, args []string) error {
	code, err := runInvestigation(kind, args)
	if err != nil {
		return report.AsRunError(err)
	}
	return exitCode(code)
}
func runInvestigation(kind string, args []string) (int, error) {
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	env := fs.String("env-file", "", i18n.S("cli.flag.env_file"))
	format := fs.String("format", "text", i18n.S("cli.flag.format"))
	output := fs.String("output", "", i18n.S("cli.flag.output"))
	full := fs.Bool("full", false, i18n.S("cli.flag.full"))
	days := fs.Int("days", 3, i18n.S("cli.flag.days"))
	since := fs.Duration("since", 48*time.Hour, i18n.S("cli.flag.since"))
	failOn := fs.String("fail-on", "HIGH", i18n.S("cli.flag.fail_on"))
	if e := fs.Parse(args); e != nil {
		return 0, e
	}
	if fs.NArg() != 0 || *days < 1 || *days > 365 || *since <= 0 || *since > 365*24*time.Hour {
		return 0, i18n.Errorf("err.investigation_window")
	}
	f, e := report.ParseFormat(*format)
	if e != nil {
		return 0, e
	}
	fail, e := report.ParseFailOn(*failOn)
	if e != nil {
		return 0, e
	}
	cfg, e := loadConfig(*env)
	if e != nil {
		return 0, e
	}
	det, e := cfg.DetectConfig()
	if e != nil {
		return 0, e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	now := time.Now()
	cutoff := now.Add(-*since)
	rep := &report.Investigation{Version: version, Time: now, Kind: kind}
	if kind == "recent" {
		rep.Recent = investigate.Recent(ctx, cfg.HostRoot, now.Add(-time.Duration(*days)*24*time.Hour), now)
	} else {
		offline := filepath.Clean(cfg.HostRoot) != "/" && filepath.Clean(cfg.ProcRoot) == "/proc"
		if offline {
			cfg.ProcRoot = filepath.Join(cfg.HostRoot, "proc")
			cfg.DataDir = ""
			rep.Incomplete = true
			rep.Warnings = append(rep.Warnings, i18n.T("warn.triage_offline"))
			rep.Snapshot = &model.Snapshot{Time: now, System: detect.SystemChecks(cfg.HostRoot, now, det), Host: model.HostInfo{IsRoot: os.Geteuid() == 0}}
			if ac := authCollector(cfg, true); ac != nil {
				rep.Snapshot.Auth = ac.Build(now, nil)
				rep.Snapshot.System = append(rep.Snapshot.System, rep.Snapshot.Auth.Findings...)
			}
		}
		if !offline {
			h, _ := history.Open(history.Options{})
			pfs := procfs.New(cfg.ProcRoot, cfg.HostRoot)
			pfs.MaxFiles = cfg.MaxFiles
			rk := rootkit.New(rootkit.Options{ProcRoot: cfg.ProcRoot, HostRoot: cfg.HostRoot, StateDir: cfg.DataDir, ReadOnly: true, Interval: cfg.RootkitInterval})
			ir := integrityRunner(cfg, det, true)
			if *full {
				if e = rk.Sweep(ctx); e != nil {
					return 0, e
				}
				if e = ir.Check(ctx); e != nil {
					return 0, e
				}
			}
			sc := scanner.New(scanner.Options{FS: pfs, Detect: det, History: h, Interval: cfg.ScanInterval, Logger: newLogger("error"), Auth: authCollector(cfg, true), LogDays: cfg.LogDays, Rootkit: rk, Integrity: ir})
			attachSelfCheck(sc, cfg, "", newLogger("error"), false)
			rep.Snapshot, e = sc.ScanOnce()
			if e != nil {
				return 0, e
			}
		}
		investigate.Attach(rep.Snapshot)
		checks, _ := audit.Run(audit.Options{HostRoot: cfg.HostRoot, ProcRoot: cfg.ProcRoot, Now: now})
		rep.Audit = &model.AuditReport{Time: now, Checks: checks}
		if kind == "collect" {
			res, e := collect.Create(ctx, collect.Options{HostRoot: cfg.HostRoot, ProcRoot: cfg.ProcRoot, Output: *output, Version: version, Now: now, MaxBytes: int64(cfg.CollectMaxMB) << 20, MaxBinaryBytes: int64(cfg.CollectMaxBinaryMB) << 20}, rep.Snapshot, rep.Audit)
			if e != nil {
				return 0, e
			}
			if e = json.NewEncoder(os.Stdout).Encode(res); e != nil {
				return 0, e
			}
			if res.Incomplete {
				return report.ExitIncomplete, nil
			}
			return 0, nil
		}
		rep.Recent = investigate.Recent(ctx, cfg.HostRoot, cutoff, now)
		events, ok := investigate.ReadEvents(cfg.DataDir, cutoff)
		if !ok {
			rep.Incomplete = true
			rep.Warnings = append(rep.Warnings, i18n.T("warn.timeline_history"))
		}
		rep.Timeline = investigate.Timeline(rep.Snapshot, events, rep.Recent, cutoff)
	}
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	rep.Summarize()
	if e = report.Write(*output, func(w io.Writer) error { return rep.Render(w, f, i18n.Default()) }); e != nil {
		return 0, e
	}
	highest := model.RiskInfo
	for _, p := range rep.Priority {
		highest = max(highest, p.Risk)
	}
	return report.ExitCode(highest >= model.RiskLow, highest, fail, rep.Incomplete), nil
}

package tui

import (
	"fmt"
	"strings"
)

const ufwSummaryLimit = 100

func (a *App) ufwSummary(b *lb) {
	b.header(a.tr("tui.ufw.summary"))
	b.para(a.tr("web.ufw.hint"), stDim, 0)
	u := a.data.UFW
	if u == nil {
		b.para(a.tr("web.ufw.unavailable"), stWarn, 0)
	} else {
		switch u.State {
		case "absent":
			b.para(a.tr("web.ufw.absent"), stDim, 0)
		case "enabled":
			b.para(a.tr("tui.ufw.config_enabled"), stNormal, 0)
		case "disabled":
			b.para(a.tr("tui.ufw.config_disabled"), stWarn, 0)
		default:
			b.para(a.tr("web.ufw.unknown"), stWarn, 0)
		}
		for _, s := range u.Settings {
			switch s.Key {
			case "DEFAULT_INPUT_POLICY", "DEFAULT_OUTPUT_POLICY", "DEFAULT_FORWARD_POLICY", "IPV6":
				b.para(a.txt(s.Label)+": "+a.txt(s.Value), stNormal, 0)
			}
		}
		for _, w := range u.Warnings {
			b.para(a.txt(w), stWarn, 0)
		}
	}
	b.header(a.tr("tui.ufw.ports"))
	b.para(a.tr("tui.ufw.ports_hint"), stDim, 0)
	x := a.data.Exposure
	if x == nil {
		b.para(a.tr("tui.ufw.ports_unavailable"), stWarn, 0)
	} else {
		if x.Incomplete {
			b.para(a.tr("tui.ufw.ports_incomplete"), stWarn, 0)
		}
		for _, w := range x.Warnings {
			b.para(a.txt(w), stWarn, 0)
		}
		b.para(a.tr("tui.ufw.port_count", len(x.Entries)), stNormal, 0)
		for _, e := range x.Entries[:min(len(x.Entries), ufwSummaryLimit)] {
			owner := e.ProcName
			if e.PID != 0 {
				owner += fmt.Sprintf(" (PID %d)", e.PID)
			}
			if e.Container != "" {
				owner += " · " + e.Container
			}
			if e.Service != nil {
				owner += " · " + e.Service.Name
			}
			b.para(fmt.Sprintf("%s %s · %s · %s", e.Proto, exposureEndpoint(e), a.scopeName(e.Scope), strings.Trim(owner, " ·")), stNormal, 0)
		}
		if len(x.Entries) > ufwSummaryLimit {
			b.para(a.tr("tui.ufw.ports_limited", ufwSummaryLimit), stWarn, 0)
		}
	}
	b.header(a.tr("tui.ufw.rules"))
	b.para(a.tr("tui.ufw.rules_hint"), stDim, 0)
	if u == nil || u.State == "absent" {
		return
	}
	shown := 0
	for _, path := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		family := "IPv4"
		if strings.HasSuffix(path, "user6.rules") {
			family = "IPv6"
		}
		b.header(family + " · " + path)
		found := false
		for _, f := range u.Files {
			if f.Path != path {
				continue
			}
			found = true
			if f.Status != "ok" {
				b.para(a.tr("tui.ufw.rules_unavailable"), stWarn, 0)
				if !f.Error.IsZero() {
					b.para(a.txt(f.Error), stWarn, 0)
				}
				break
			}
			count := 0
			for line := range strings.SplitSeq(f.Content, "\n") {
				raw, ok := strings.CutPrefix(strings.TrimSpace(line), "### tuple ###")
				if !ok {
					continue
				}
				if shown >= ufwSummaryLimit {
					b.para(a.tr("tui.ufw.rules_limited", ufwSummaryLimit), stWarn, 0)
					return
				}
				count++
				shown++
				// Показываем поля tuple без вычисления итогового решения firewall; хвост сохраняет направление, интерфейсы и профили.
				fields := strings.Fields(raw)
				if len(fields) < 7 {
					b.para(a.tr("tui.ufw.rule_unknown", strings.TrimSpace(raw)), stWarn, 0)
					continue
				}
				b.para(fmt.Sprintf("%d. %s · %s · %s", count, fields[0], fields[1], strings.Join(fields[6:], " ")), stBold, 0)
				b.para(a.tr("tui.ufw.rule_endpoints", fields[5], fields[4], fields[3], fields[2]), stNormal, 2)
			}
			if count == 0 {
				b.para(a.tr("tui.ufw.no_tuples"), stDim, 0)
			}
			break
		}
		if !found {
			b.para(a.tr("tui.ufw.rules_unavailable"), stWarn, 0)
		}
	}
}

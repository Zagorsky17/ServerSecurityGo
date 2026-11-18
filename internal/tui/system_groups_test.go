package tui

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func orphanFinding(p string) model.SystemFinding {
	return model.SystemFinding{Path: p, Risk: model.RiskMedium, Finding: model.Finding{ID: "fs_unowned", Title: i18n.L(p), Evidence: i18n.Ls([]string{"uid=501 gid=50"})}}
}

func TestSystemGroupNavigationCopyAndRefresh(t *testing.T) {
	a, out := newTestApp(t, 160, 55)
	a.data.System = []model.SystemFinding{orphanFinding("/opt/loki/tree/a"), orphanFinding("/opt/loki/tree/b"), {Path: "/etc/critical", Risk: model.RiskCritical}}
	a.rebuild()
	a.focusPanel(pSys)
	if a.count(pSys) != 2 || !strings.Contains(screen(a), "группой: 2") {
		t.Fatal("group not collapsed")
	}
	if _, ok := a.selSystem(); ok {
		t.Fatal("group header treated as an individual finding")
	}
	if items := a.copyItems(); len(items) != 2 || items[0].value != "/opt/loki/tree" {
		t.Fatal(items)
	}
	out.Reset()
	a.copyJSON()
	var copied []model.SystemFinding
	if err := json.Unmarshal([]byte(osc52Text(t, out.String())), &copied); err != nil || len(copied) != 2 || copied[1].Path != "/opt/loki/tree/b" {
		t.Fatal("group JSON lost findings", err)
	}
	press(a, Key{Kind: KeyEnter})
	if a.inMain || a.systemGroup == "" || a.count(pSys) != 2 {
		t.Fatal("group did not open")
	}
	press(a, Key{Kind: KeyDown})
	if f, ok := a.selSystem(); !ok || f.Path != "/opt/loki/tree/b" {
		t.Fatal("member not selectable")
	}
	if items := a.copyItems(); items[0].value != "/opt/loki/tree/b" {
		t.Fatal("member path copy failed")
	}
	a.data.System = append(a.data.System, orphanFinding("/opt/loki/tree/c"))
	a.rebuild()
	if a.systemGroup == "" || a.count(pSys) != 3 {
		t.Fatal("refresh closed group or lost new member")
	}
	press(a, Key{Kind: KeyEnter})
	if !a.inMain {
		t.Fatal("member details unavailable")
	}
	press(a, Key{Kind: KeyEsc})
	press(a, Key{Kind: KeyLeft})
	if a.systemGroup != "" || a.count(pSys) != 2 {
		t.Fatal("cannot return to group list")
	}
	press(a, Key{Kind: KeyDown})
	if f, ok := a.selSystem(); !ok || f.Risk != model.RiskCritical {
		t.Fatal("critical finding hidden")
	}
	a.lists[pSys].filter = "/opt/loki/tree/c"
	a.rebuild()
	if f, ok := a.selSystem(); a.count(pSys) != 1 || !ok || f.Path != "/opt/loki/tree/c" {
		t.Fatal("search did not reach collapsed member")
	}
	a.lists[pSys].filter = "uid=501"
	a.rebuild()
	if a.count(pSys) != 1 {
		t.Fatal("owner search failed")
	}
	press(a, Key{Kind: KeyEnter})
	a.data.System = a.data.System[:1]
	a.rebuild()
	if a.systemGroup != "" || a.count(pSys) != 1 {
		t.Fatal("stale group retained after membership disappeared")
	}
}

func TestSystemGroupSmallTerminalAndEscaping(t *testing.T) {
	a, _ := newTestApp(t, 100, 24)
	a.data.System = []model.SystemFinding{orphanFinding("/opt/\x1b[2J/tree/a"), orphanFinding("/opt/\x1b[2J/tree/b")}
	a.rebuild()
	a.focusPanel(pSys)
	if text := screen(a); strings.Contains(text, "\x1b") || !strings.Contains(text, "uid=501") {
		t.Fatal("group header escaping or details failed")
	}
	a.lang = i18n.EN
	if !strings.Contains(screen(a), "Unknown owner") {
		t.Fatal("translation missing")
	}
	press(a, Key{Kind: KeyRune, Rune: 'l'})
	screen(a)
	press(a, Key{Kind: KeyRune, Rune: 'h'})
	if a.systemGroup != "" {
		t.Fatal("vim navigation failed")
	}
}

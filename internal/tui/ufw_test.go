package tui

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
	"testing"
)

func ufwText(a *App) string {
	a.focus = pUFW
	_, lines := a.mainContent(120)
	var b strings.Builder
	for _, line := range lines {
		for _, s := range line {
			b.WriteString(s.t)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestUFWSummaryFirst(t *testing.T) {
	a, out := newTestApp(t, 160, 55)
	a.focusPanel(pUFW)
	if a.count(pUFW) != len(a.ufwFiles)+1 {
		t.Fatal("summary row missing")
	}
	if _, ok := a.selUFW(); ok {
		t.Fatal("summary selects a file")
	}
	text := ufwText(a)
	for _, want := range []string{"Сводка портов и правил", "Слушающие и опубликованные порты", ":22", "sshd", "DROP", "IPv4", "IPv6", "80,443", "10.0.0.0/8", "limit"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	out.Reset()
	a.copyJSON()
	if copied := osc52Text(t, out.String()); !strings.Contains(copied, `"exposure"`) {
		t.Fatal("summary JSON omits ports")
	}
	// A filter on the Ports panel must not hide ports in the UFW overview.
	a.lists[pPorts].filter = "no-such-port"
	a.rebuild()
	if !strings.Contains(ufwText(a), ":22") {
		t.Fatal("unrelated filter affects summary")
	}
	a.lists[pUFW].filter = "/etc/ufw/user.rules"
	a.rebuild()
	if a.count(pUFW) != 2 {
		t.Fatal(a.count(pUFW))
	}
	a.lists[pUFW].cursor = 1
	if f, ok := a.selUFW(); !ok || f.Path != "/etc/ufw/user.rules" {
		t.Fatal("file navigation shifted incorrectly")
	}
}

func TestUFWSummaryUnavailableAndRules(t *testing.T) {
	a, _ := newTestApp(t, 100, 24)
	a.data.UFW = nil
	a.data.Exposure = nil
	if text := ufwText(a); !strings.Contains(text, "недоступны") {
		t.Fatal(text)
	}
	a.data.UFW = &model.UFWReport{State: "disabled", Files: []model.UFWFile{
		{Path: "/etc/ufw/user.rules", Status: "ok", Content: "### tuple ### deny udp 53 192.0.2.1 123 10.0.0.0/8 in_eth0\n### tuple ### route:allow tcp 443 any any any out_eth1\n### tuple ### malformed\n"},
		{Path: "/etc/ufw/user6.rules", Status: "unavailable", Error: i18n.L("READ_ERROR")},
	}}
	a.data.Exposure = &model.ExposureReport{Incomplete: true, Warnings: []i18n.Msg{i18n.L("PORTS_INCOMPLETE")}}
	text := ufwText(a)
	for _, want := range []string{"deny", "udp", "53", "192.0.2.1", "123", "10.0.0.0/8", "in_eth0", "route:allow", "out_eth1", "malformed", "READ_ERROR", "PORTS_INCOMPLETE"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s", want)
		}
	}
	a.lang = i18n.EN
	if text := ufwText(a); !strings.Contains(text, "Listening and published ports") {
		t.Fatal(text)
	}
	screen(a)
}

func TestUFWSummaryBoundsAndTerminalSafety(t *testing.T) {
	a, _ := newTestApp(t, 100, 24)
	a.data.UFW = &model.UFWReport{State: "enabled", Files: []model.UFWFile{{Path: "/etc/ufw/user.rules", Status: "ok", Content: strings.Repeat("### tuple ### allow tcp 22 any any any in\n", 101) + "### tuple ### forbidden tcp 1 any any any in\n"}}}
	a.data.Exposure = &model.ExposureReport{}
	for i := 0; i < 101; i++ {
		a.data.Exposure.Entries = append(a.data.Exposure.Entries, model.Exposure{Proto: "tcp", Addr: "127.0.0.1", Port: 22, ProcName: "test\x1b[2J"})
	}
	text := ufwText(a)
	for _, want := range []string{"Показаны первые 100 записей", "Показаны первые 100 деклараций"} {
		if !strings.Contains(text, want) {
			t.Fatal(want)
		}
	}
	if strings.Contains(text, "forbidden") || strings.Contains(text, "\x1b") {
		t.Fatal("limit or terminal sanitization failed")
	}
	for _, size := range [][2]int{{100, 24}, {160, 55}} {
		a.w, a.h = size[0], size[1]
		a.focusPanel(pUFW)
		if text := screen(a); !strings.Contains(text, "Сводка портов") {
			t.Fatal("summary not visible")
		}
		press(a, Key{Kind: KeyEnter})
		screen(a)
	}
}

package report

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]Format{"": Text, "table": Text, "TEXT": Text, "json": JSON, "html": HTML, "md": Markdown, "markdown": Markdown} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("sarif"); err == nil {
		t.Error("sarif принят")
	}
	if f, err := ParseFailOn("none"); err != nil || !f.Off {
		t.Errorf("none: %+v %v", f, err)
	}
	if f, err := ParseFailOn("medium"); err != nil || f.Off || f.Level != model.RiskMedium {
		t.Errorf("medium: %+v %v", f, err)
	}
	// INFO означал бы «всегда 1» — не принимается.
	for _, bad := range []string{"bad", "INFO", ""} {
		if _, err := ParseFailOn(bad); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
	if err := AsRunError(os.ErrPermission); err.(*CodeError).Code != ExitError || AsRunError(nil) != nil {
		t.Error("AsRunError")
	}
}

func TestExitCode(t *testing.T) {
	high := FailOn{Level: model.RiskHigh}
	for _, c := range []struct {
		found      bool
		verdict    model.Risk
		f          FailOn
		incomplete bool
		want       int
	}{
		{false, model.RiskInfo, high, false, ExitOK},
		{true, model.RiskMedium, high, false, ExitOK},
		{true, model.RiskHigh, high, false, ExitFindings},
		{true, model.RiskCritical, high, true, ExitFindings}, // находки важнее неполноты
		{true, model.RiskMedium, high, true, ExitIncomplete},
		{true, model.RiskCritical, FailOn{Off: true}, false, ExitOK},
		{true, model.RiskCritical, FailOn{Off: true}, true, ExitIncomplete},
		{true, model.RiskLow, FailOn{Level: model.RiskLow}, false, ExitFindings},
	} {
		if got := ExitCode(c.found, c.verdict, c.f, c.incomplete); got != c.want {
			t.Errorf("%+v: %d, ожидался %d", c, got, c.want)
		}
	}
}

// TestWrite: новый файл и замена существующего — с правами 0600; по
// симлинку запись отказывается; устройство не заменяется файлом.
func TestWrite(t *testing.T) {
	dir := t.TempDir()
	write := func(path string) error {
		return Write(path, func(w io.Writer) error { _, err := w.Write([]byte("report")); return err })
	}
	out := filepath.Join(dir, "report.html")
	if err := os.WriteFile(out, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := write(out); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(out)
	data, _ := os.ReadFile(out)
	if err != nil || fi.Mode().Perm() != 0o600 || string(data) != "report" {
		t.Errorf("файл отчёта: %v %v %q", err, fi, data)
	}
	// Симлинк (на файл в /tmp или /dev/stdout): отказ, цель не тронута,
	// сам симлинк остаётся.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.html")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := write(link); err == nil {
		t.Error("запись по симлинку разрешена")
	}
	if data, _ := os.ReadFile(victim); string(data) != "original" {
		t.Errorf("цель симлинка изменена: %q", data)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("симлинк заменён: %v %v", err, fi)
	}
	// /dev/null остаётся устройством.
	if err := write(os.DevNull); err != nil {
		t.Errorf("/dev/null: %v", err)
	}
	if fi, err := os.Lstat(os.DevNull); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		t.Errorf("/dev/null заменён: %v %v", err, fi)
	}
	// Каталог — отказ.
	if err := write(dir); err == nil {
		t.Error("запись в каталог")
	}
	// Ошибка отрисовки — файла нет, временных тоже.
	bad := filepath.Join(dir, "bad.md")
	if err := Write(bad, func(io.Writer) error { return os.ErrInvalid }); err == nil {
		t.Error("ошибка отрисовки потеряна")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 { // report.html, victim, link.html
		t.Errorf("в каталоге: %v", entries)
	}
}

// evil — строки, которые процесс может задать сам.
const evil = "<script>alert(1)</script>[click](http://evil.example)|`x`\x1b]0;t\x07‮"

func evilSnapshot() *model.Snapshot {
	p := &model.Process{Key: "1-1", PID: 4242, Name: evil, User: "root", Exe: "/tmp/" + evil, Cmdline: evil, Risk: model.RiskCritical, Score: 90,
		Findings:        []model.Finding{{ID: "x", Title: i18n.L(evil), Category: model.CatLocation, Weight: 90}},
		Recommendations: []i18n.Msg{i18n.L("check " + evil)}}
	return &model.Snapshot{Time: time.Now(), Host: model.HostInfo{Hostname: "web-01" + evil, IsRoot: true},
		Processes: []*model.Process{p}, Stats: model.Stats{Total: 1, ByRisk: map[string]int{"CRITICAL": 1}},
		System: []model.SystemFinding{{Finding: model.Finding{ID: "ld_so_preload", Title: i18n.L("preload"), Evidence: []i18n.Msg{i18n.L(evil)}}, Path: "/etc/ld.so.preload", Risk: model.RiskHigh}}}
}

func render(t *testing.T, r interface {
	Render(io.Writer, Format, i18n.Lang) error
}, f Format) string {
	t.Helper()
	var b bytes.Buffer
	if err := r.Render(&b, f, i18n.RU); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestScanFormatsEscape(t *testing.T) {
	s := NewScan(evilSnapshot(), model.RiskLow, "test")
	if v, found := s.Verdict(); v != model.RiskCritical || !found || s.ExitCode(FailOn{Level: model.RiskHigh}) != ExitFindings {
		t.Errorf("итог: %s %v", v, found)
	}
	for _, f := range []Format{Text, JSON, HTML, Markdown} {
		out := render(t, s, f)
		// JSON передаёт данные как есть (управляющие символы экранирует
		// сам encoding/json), остальные форматы — для глаз человека.
		bad := "\x1b\x07‮"
		if f == JSON {
			bad = "\x1b\x07"
		}
		if strings.ContainsAny(out, bad) {
			t.Errorf("%s: управляющие или невидимые символы", f)
		}
		if !strings.Contains(out, "4242") {
			t.Errorf("%s: нет процесса", f)
		}
		switch f {
		case HTML:
			if strings.Contains(out, "<script>alert") || !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
				t.Errorf("HTML не экранирован")
			}
		case Markdown:
			// Ни ссылки, ни сырого HTML, ни разорванной таблицы.
			if strings.Contains(out, "[click](http") || strings.Contains(out, "<script>") {
				t.Errorf("Markdown не экранирован:\n%s", out)
			}
			// В строке процесса 8 столбцов — 9 неэкранированных «|».
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "| **CRITICAL**") {
					if n := strings.Count(line, "|") - strings.Count(line, `\|`); n != 9 {
						t.Errorf("строка таблицы разорвана (%d «|»): %s", n, line)
					}
				}
			}
		case JSON:
			var v map[string]any
			if err := json.Unmarshal([]byte(out), &v); err != nil || v["schema_version"] != float64(SchemaVersion) || v["verdict"] != "CRITICAL" {
				t.Errorf("JSON: %v %v", err, v["verdict"])
			}
		}
	}
}

func TestMarkdownHelpers(t *testing.T) {
	if got := md("a|b*c_[d](e)<f>https://x"); got != `a\|b\*c\_\[d\]\(e\)\<f\>https\://x` {
		t.Errorf("md: %s", got)
	}
	if got := mdCode("echo `x` | y"); got != "`` echo `x` \\| y ``" {
		t.Errorf("mdCode: %s", got)
	}
}

func TestAuditReport(t *testing.T) {
	checks := []model.AuditCheck{
		{ID: "ssh_password_auth", Group: model.AuditGroupSSH, Title: i18n.L("pw"), Status: model.AuditFail, Severity: model.RiskHigh,
			Evidence: []i18n.Msg{i18n.L(evil)}, FixCommand: "a || b"},
		{ID: "ssh_port", Group: model.AuditGroupSSH, Title: i18n.L("port"), Status: model.AuditPass, Severity: model.RiskInfo},
		{ID: "acct_empty_password", Group: model.AuditGroupAccounts, Title: i18n.L("empty"), Status: model.AuditUnknown, Severity: model.RiskCritical},
	}
	a := &Audit{View: view.BuildAudit(true, false, 0, &model.AuditReport{Time: time.Now(), Checks: checks}), Hostname: "h", Version: "t"}
	if v, found := a.Verdict(); v != model.RiskHigh || !found || !a.Incomplete() {
		t.Errorf("итог: %s %v %v", v, found, a.Incomplete())
	}
	if a.ExitCode(FailOn{Level: model.RiskCritical}) != ExitIncomplete || a.ExitCode(FailOn{Level: model.RiskHigh}) != ExitFindings {
		t.Error("коды выхода")
	}
	text := render(t, a, Text)
	if strings.Contains(text, "port") || !strings.Contains(text, "$ a || b") {
		t.Errorf("текст без --all:\n%s", text)
	}
	a.All = true
	if !strings.Contains(render(t, a, Text), "port") {
		t.Error("--all не показывает пройденные")
	}
	html := render(t, a, HTML)
	if !strings.Contains(html, "<pre>a || b</pre>") || strings.Contains(html, "<script>alert") {
		t.Errorf("HTML")
	}
	if mdOut := render(t, a, Markdown); !strings.Contains(mdOut, "`` a \\|\\| b ``") && !strings.Contains(mdOut, "` a \\|\\| b `") {
		t.Errorf("Markdown:\n%s", mdOut)
	}
}

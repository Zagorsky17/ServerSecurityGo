package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Zagorsky17/ServerSecurityGo/internal/config"
	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
)

// TestScanTableEscapes: таблица scan не передаёт в терминал
// ESC-последовательности из имени и пути процесса.
func TestScanTableEscapes(t *testing.T) {
	tree := fakeproc.Demo(time.Now())
	tree.Procs = append(tree.Procs, &fakeproc.Proc{PID: 7777, PPID: 1, Comm: "x\x1b]0;pwned\x07y", UID: 0, State: "S", StartTicks: 100,
		Args: []string{"x\x1b]52;c;QUFB\x07", "‮oops"}, Exe: "/tmp/\x1b[2Jevil", Cwd: "/tmp"})
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSG_PROC_ROOT", procRoot)
	t.Setenv("SSG_HOST_ROOT", hostRoot)
	t.Setenv("SSG_ALLOWLIST_FILE", "")
	out := captureStdout(t, func() {
		if err := cmdScan([]string{"--min-risk", "INFO", "--fail-on", "none"}); !okOrIncomplete(err) {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "7777") {
		t.Fatalf("процесс не выведен:\n%s", out)
	}
	if strings.ContainsAny(out, "\x1b\x07‮") {
		t.Errorf("управляющие символы попали в вывод scan: %q", out)
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}

// TestAuditCommand: serversecuritygo audit в таблице и JSON на демо-дереве;
// ESC-последовательности из конфигов не попадают в терминал, хеши паролей
// не выводятся.
func TestAuditCommand(t *testing.T) {
	tree := fakeproc.Demo(time.Now())
	tree.HostFiles["etc/sudoers.d/evil"] = "Defaults env_keep += \"LD_PRELOAD\" \x1b]0;pwned\x07\n"
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSG_PROC_ROOT", procRoot)
	t.Setenv("SSG_HOST_ROOT", hostRoot)
	t.Setenv("SSG_ALLOWLIST_FILE", "")
	out := captureStdout(t, func() {
		if err := cmdAudit([]string{"--fail-on", "none"}); !okOrIncomplete(err) {
			t.Error(err)
		}
	})
	for _, want := range []string{"[FAIL]", "PasswordAuthentication", "sysadm"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q в выводе:\n%s", want, out)
		}
	}
	if strings.ContainsAny(out, "\x1b\x07") || strings.Contains(out, "demohash") {
		t.Errorf("управляющие символы или хеш в выводе audit: %q", out)
	}
	js := captureStdout(t, func() {
		if err := cmdAudit([]string{"--format", "json", "--fail-on", "none"}); !okOrIncomplete(err) {
			t.Error(err)
		}
	})
	var v struct {
		Passed int `json:"passed"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Title  string `json:"title"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(js), &v); err != nil || len(v.Checks) == 0 || v.Checks[0].Title == "" {
		t.Fatalf("JSON: %v\n%s", err, js)
	}
	if strings.Contains(js, "demohash") {
		t.Error("хеш в JSON")
	}
}

// okOrIncomplete — успех или код 3: тесты идут не от root, поэтому
// проверка может быть неполной.
func okOrIncomplete(err error) bool {
	return err == nil || err == exitStatus(report.ExitIncomplete)
}

// demoEnv пишет демо-дерево и направляет на него сканер.
func demoEnv(t *testing.T) {
	t.Helper()
	procRoot, hostRoot, err := fakeproc.Demo(time.Now()).Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSG_PROC_ROOT", procRoot)
	t.Setenv("SSG_HOST_ROOT", hostRoot)
	t.Setenv("SSG_ALLOWLIST_FILE", "")
}

// TestExitCodes: в демо есть CRITICAL — код 1 при пороге HIGH и
// CRITICAL; при none — 0 или 3 (неполная проверка не от root).
func TestExitCodes(t *testing.T) {
	demoEnv(t)
	for _, c := range []struct {
		cmd  func([]string) error
		args []string
		want int
	}{
		{cmdScan, []string{"--fail-on", "HIGH"}, report.ExitFindings},
		{cmdScan, []string{"--fail-on", "critical"}, report.ExitFindings},
		{cmdAudit, []string{"--fail-on", "HIGH"}, report.ExitFindings},
	} {
		var err error
		captureStdout(t, func() { err = c.cmd(c.args) })
		if err != exitStatus(c.want) {
			t.Errorf("%v: %v, ожидался код %d", c.args, err, c.want)
		}
	}
	// Неверные значения — ошибка с кодом 2, а не итог проверки.
	for _, args := range [][]string{{"--fail-on", "SEVERE"}, {"--fail-on", "INFO"}, {"--format", "pdf"}} {
		for _, cmd := range []func([]string) error{cmdScan, cmdAudit} {
			var ce *report.CodeError
			if err := cmd(args); !errors.As(err, &ce) || ce.Code != report.ExitError {
				t.Errorf("%v: %v", args, err)
			}
		}
	}
}

// TestReportFiles: --output пишет отчёт в файл с правами 0600 во всех
// форматах; HTML без скриптов, Markdown без сырых управляющих символов.
func TestReportFiles(t *testing.T) {
	demoEnv(t)
	dir := t.TempDir()
	for _, f := range []string{"text", "json", "html", "md"} {
		for name, cmd := range map[string]func([]string) error{"scan": cmdScan, "audit": cmdAudit} {
			out := filepath.Join(dir, name+"."+f)
			if err := cmd([]string{"--format", f, "--output", out, "--fail-on", "none"}); !okOrIncomplete(err) {
				t.Fatalf("%s %s: %v", name, f, err)
			}
			fi, err := os.Stat(out)
			if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() == 0 {
				t.Fatalf("%s %s: %v %v", name, f, err, fi)
			}
			data, _ := os.ReadFile(out)
			if strings.ContainsAny(string(data), "\x1b\x07") || strings.Contains(string(data), "demohash") {
				t.Errorf("%s %s: управляющие символы или хеш", name, f)
			}
			if f == "html" && (strings.Contains(string(data), "<script") || !strings.Contains(string(data), "Content-Security-Policy")) {
				t.Errorf("%s html: скрипт или нет CSP", name)
			}
			if f == "json" {
				var v map[string]any
				if err := json.Unmarshal(data, &v); err != nil || v["schema_version"] != float64(report.SchemaVersion) || v["kind"] != name {
					t.Errorf("%s json: %v %v %v", name, err, v["schema_version"], v["kind"])
				}
			}
		}
	}
	// Временных файлов не осталось.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 8 {
		t.Errorf("файлов в каталоге: %d", len(entries))
	}
}

func TestFullScanVerifiesDpkgAndQuickScanRemainsIncomplete(t *testing.T) {
	tree := fakeproc.Demo(time.Now())
	tree.Procs = nil
	tree.Socks = nil
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(root, path, content string) {
		t.Helper()
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(procRoot, "sys/kernel/pid_max", "16")
	write(procRoot, "sys/kernel/tainted", "0")
	write(procRoot, "sys/kernel/osrelease", "test")
	write(procRoot, "sys/kernel/random/boot_id", "12345678-1234-1234-1234-123456789abc")
	write(procRoot, "modules", "")
	os.MkdirAll(filepath.Join(hostRoot, "sys/module"), 0700)
	write(hostRoot, "lib/modules/test/modules.dep", "")
	write(hostRoot, "var/lib/dpkg/status", "Package: tools\nStatus: install ok installed\nVersion: 1\nArchitecture: all\n\n")
	write(hostRoot, "var/lib/dpkg/info/tools.list", "/usr/bin/ssh\n")
	write(hostRoot, "var/lib/dpkg/info/tools.md5sums", "d41d8cd98f00b204e9800998ecf8427e  usr/bin/ssh\n")
	write(hostRoot, "usr/bin/ssh", "modified")
	state := t.TempDir()
	t.Setenv("SSG_PROC_ROOT", procRoot)
	t.Setenv("SSG_HOST_ROOT", hostRoot)
	t.Setenv("SSG_DATA_DIR", state)
	t.Setenv("SSG_ALLOWLIST_FILE", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("SSG_METRICS_ENABLED", "false")
	output := filepath.Join(t.TempDir(), "scan.json")
	code, err := runScan([]string{"--format", "json", "--output", output, "--fail-on", "none"})
	if err != nil || code != report.ExitIncomplete {
		t.Fatalf("quick scan: %d %v", code, err)
	}
	code, err = runScan([]string{"--full", "--format", "json", "--output", output, "--min-risk", "INFO"})
	if err != nil || code != report.ExitFindings {
		t.Fatalf("full scan: %d %v", code, err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bin_modified", "rootkit_sweep_complete", "integrity_complete"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s in %s", want, data)
		}
	}
	if strings.Contains(string(data), "integrity_pending") || strings.Contains(string(data), "rootkit_sweep_pending") {
		t.Fatal("full scan left pending checks")
	}
	entries, _ := os.ReadDir(state)
	if len(entries) != 0 {
		t.Fatal("one-shot scan modified service baselines")
	}
}
func TestUnpackagedAcceptanceRequiresExactExplicitRule(t *testing.T) {
	h := t.TempDir()
	cfg := config.Default()
	cfg.HostRoot = h
	cfg.DataDir = ""
	for _, tc := range []struct {
		rule detect.AllowRule
		want bool
	}{
		{detect.AllowRule{Exe: "/usr/bin/manual", Rules: []string{"bin_unpackaged"}}, true},
		{detect.AllowRule{Exe: "/usr/bin/*", Rules: []string{"bin_unpackaged"}}, false},
		{detect.AllowRule{Exe: "/usr/bin/manual"}, false},
		{detect.AllowRule{Name: "manual", Rules: []string{"bin_unpackaged"}}, false},
	} {
		r := integrityRunner(cfg, detect.Config{Allow: []detect.AllowRule{tc.rule}}, true)
		// Приём проверяется через наблюдаемое поведение, без доступа к внутренностям Runner.
		dir := filepath.Join(h, "var/lib/dpkg/info")
		os.MkdirAll(dir, 0700)
		os.MkdirAll(filepath.Join(h, "usr/bin"), 0700)
		os.WriteFile(filepath.Join(h, "var/lib/dpkg/status"), []byte("Package: empty\nStatus: install ok installed\nVersion: 1\nArchitecture: all\n\n"), 0600)
		os.WriteFile(filepath.Join(dir, "empty.list"), []byte("/.\n"), 0600)
		os.WriteFile(filepath.Join(h, "usr/bin/manual"), []byte("manual"), 0700)
		if err := r.Check(context.Background()); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range r.Findings() {
			if f.ID == "bin_unpackaged" {
				found = true
				if f.Suppressed != tc.want {
					t.Fatalf("%+v: %+v", tc, f)
				}
			}
		}
		if !found {
			t.Fatal("missing unpackaged file")
		}
	}
}

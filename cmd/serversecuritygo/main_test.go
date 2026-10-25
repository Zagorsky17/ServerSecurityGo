package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
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
		if err := cmdScan([]string{"--min-risk", "INFO"}); err != nil {
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
		if err := cmdAudit(nil); err != nil {
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
		if err := cmdAudit([]string{"--format", "json"}); err != nil {
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

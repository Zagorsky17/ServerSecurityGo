package main

import (
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

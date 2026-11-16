package selfcheck

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestWatchdogEnvironment(t *testing.T) {
	for _, tc := range []struct {
		socket, usec, pid string
		want              bool
	}{
		{"/run/notify", "30000000", "42", true}, {"@notify", "30000000", "", true},
		{"/run/notify", "30000000", "43", false}, {"/run/notify", "30000000", "bad", false},
		{"", "30000000", "", false}, {"relative", "30000000", "", false}, {"/run/notify", "0", "", false},
		{"/run/notify", "-1", "", false}, {"/run/notify", "1", "", false}, {"/run/notify", "9223372036854775807", "", false},
	} {
		w := parseWatchdog(tc.socket, tc.usec, tc.pid, 42)
		if (w.socket != "") != tc.want {
			t.Fatalf("%+v -> %+v", tc, w)
		}
	}
}

func TestWatchdogDatagram(t *testing.T) {
	paths := []string{filepath.Join(shortTemp(t), "notify.sock")}
	if runtime.GOOS == "linux" {
		paths = append(paths, "@ssg-"+filepath.Base(filepath.Dir(paths[0])))
	}
	for _, path := range paths {
		conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		w := watchdog{socket: path, interval: time.Second}
		if err := w.ping(); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 128)
		n, _, err := conn.ReadFromUnix(buf)
		conn.Close()
		if err != nil || string(buf[:n]) != "WATCHDOG=1" {
			t.Fatalf("%q %v", buf[:n], err)
		}
	}
	if err := (watchdog{}).ping(); err != nil {
		t.Fatal(err)
	}
	if err := (watchdog{socket: filepath.Join(t.TempDir(), "absent"), interval: time.Second}).ping(); err == nil {
		t.Fatal("missing socket accepted")
	}
}

func TestRunStopsPingingWhenScanStalls(t *testing.T) {
	// Проверяем реальный цикл с малым интервалом уведомлений без ожидания минут.
	f := setup(t)
	f.opt.Record = nil
	m := New(f.opt)
	path := filepath.Join(shortTemp(t), "n.sock")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m.notify = watchdog{socket: path, interval: 10 * time.Millisecond}
	m.started = time.Now().Add(-time.Minute)
	if m.fresh(time.Now()) {
		t.Fatal("stalled scanner considered fresh")
	}
	// Проверка доставки при актуальном скане отдельно от отсутствия доставки.
	if err := m.notify.ping(); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.ReadFromUnix(b); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	c.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	_, _, err = c.ReadFromUnix(b)
	cancel()
	<-done
	if err == nil {
		t.Fatal("watchdog fed while stalled")
	}
	wantID(t, m, "self_scan_stalled", true)
}

func TestWatchdogOwnEnvironment(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "/tmp/test-notify")
	t.Setenv("WATCHDOG_USEC", "2000000")
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	if w := watchdogFromEnv(); w.interval != time.Second {
		t.Fatal(w)
	}
}

func shortTemp(t *testing.T) string {
	t.Helper()
	p, err := os.MkdirTemp("/tmp", "ssg-notify-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(p) })
	return p
}

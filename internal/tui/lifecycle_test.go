package tui

import (
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/metrics"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
)

func TestLocalCloseWaitsForOwnedWorkers(t *testing.T) {
	for _, worker := range []string{"scanner", "metrics"} {
		t.Run(worker, func(t *testing.T) {
			proc, host, err := fakeproc.Demo(time.Now()).Write(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			hook := func() {
				if calls.Add(1) == 2 {
					close(entered)
					<-release
				}
			}
			hist, _ := history.Open(history.Options{})
			quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
			opt := scanner.Options{FS: fakeproc.NewFS(proc, host), Detect: detect.DefaultConfig(), History: hist, Interval: 10 * time.Millisecond, Logger: quiet, Quick: true}
			var mc *metrics.Collector
			if worker == "scanner" {
				opt.BeforeScan = hook
			} else {
				mc = metrics.New(metrics.Options{ProcRoot: proc, HostRoot: host, Interval: 10 * time.Millisecond, BeforeCollect: hook, Logger: quiet})
			}
			src, err := NewLocalSource(scanner.New(opt), nil, mc, false, "test", true, i18n.L("test"))
			if err != nil {
				t.Fatal(err)
			}
			defer src.Close()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("worker did not start")
			}
			done := make(chan struct{})
			go func() { src.Close(); close(done) }()
			select {
			case <-done:
				close(release)
				t.Fatal("Close returned before worker finished")
			case <-time.After(30 * time.Millisecond):
			}
			close(release)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("Close did not join worker")
			}
			count := calls.Load()
			time.Sleep(30 * time.Millisecond)
			if calls.Load() != count {
				t.Fatal("worker ran after Close")
			}
		})
	}
}

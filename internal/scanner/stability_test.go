package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
)

// Длительный прогон включается только явно; данные и история живут в t.TempDir.
func TestDiagnosticStability(t *testing.T) {
	duration := time.Duration(0)
	if raw := os.Getenv("SSG_TEST_SOAK_DURATION"); raw != "" {
		var err error
		duration, err = time.ParseDuration(raw)
		if err != nil || duration < 0 || duration > 24*time.Hour {
			t.Fatal("invalid SSG_TEST_SOAK_DURATION")
		}
	}
	sc, _, _ := newDemoScanner(t)
	dir := t.TempDir()
	opt := history.Options{Dir: dir, MemoryEvents: 128, MaxEventsBytes: 64 << 10}
	hist, err := history.Open(opt)
	if err != nil {
		t.Fatal(err)
	}
	sc.opt.History = hist
	// Первые сканы меняют средние CPU на интервальные значения.
	for i := 0; i < 5; i++ {
		if _, err := sc.ScanOnce(); err != nil {
			t.Fatal(err)
		}
	}
	events := len(hist.Events(0))
	info, err := os.Stat(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	bytes := info.Size()
	start := time.Now()
	iterations := 0
	var mem runtime.MemStats
	for iterations < 30 || time.Since(start) < duration {
		snap, err := sc.ScanOnce()
		if err != nil || snap == nil {
			t.Fatal(err)
		}
		if len(hist.Events(0)) != events {
			t.Fatal("unchanged fixture generated history", len(hist.Events(0)), events)
		}
		if len(snap.Processes) != snap.Stats.Total {
			t.Fatal("inconsistent snapshot")
		}
		iterations++
		if duration > 0 {
			time.Sleep(time.Second)
		}
	}
	if err := hist.Flush(time.Now()); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(dir, "events.jsonl"))
	if err != nil || info.Size() != bytes {
		t.Fatal("stable history grew", info, err)
	}
	restored, err := history.Open(opt)
	if err != nil || len(restored.Events(0)) != events {
		t.Fatal("history reload", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&mem)
	t.Logf("scans=%d duration=%s history_bytes=%d events=%d heap_live_bytes=%d", iterations, time.Since(start), bytes, events, mem.HeapAlloc)
}

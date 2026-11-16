package selfcheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

type fixture struct {
	opt                          Options
	events                       []model.Event
	root, unit, binary, baseline string
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func setup(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{root: root, unit: filepath.Join(root, "etc/systemd/system", unitName), binary: filepath.Join(root, "ssg"), baseline: filepath.Join(root, BaselinePath)}
	write(t, f.binary, "executable")
	write(t, f.unit, "[Service]\nExecStart=/opt/serversecuritygo/bin/serversecuritygo serve\n")
	f.opt = Options{HostRoot: root, DataDir: filepath.Join(root, "state"), Allowlist: filepath.Join(root, "allowlist.json"), Executable: f.binary, Interval: time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := os.Mkdir(f.opt.DataDir, 0700); err != nil {
		t.Fatal(err)
	}
	f.opt.Record = func(e model.Event) error { f.events = append(f.events, e); return nil }
	f.baselineNow(t)
	return f
}
func (f *fixture) baselineNow(t *testing.T) {
	t.Helper()
	paths := []string{f.binary, f.unit}
	var b strings.Builder
	for i, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		key := "binary"
		if i > 0 {
			key = "/etc/systemd/system/" + unitName
		}
		fmt.Fprintf(&b, "%x  %s\n", sha256.Sum256(data), key)
	}
	write(t, f.baseline, b.String())
}
func ids(m *Monitor) []string {
	var out []string
	for _, f := range m.Findings() {
		out = append(out, f.ID)
	}
	return out
}
func wantID(t *testing.T, m *Monitor, id string, yes bool) {
	t.Helper()
	if slices.Contains(ids(m), id) != yes {
		t.Fatalf("findings %v, want %s=%v", ids(m), id, yes)
	}
}

func TestIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		mutate   func(*testing.T, *fixture)
	}{
		{"binary", "self_binary_changed", func(t *testing.T, f *fixture) { write(t, f.binary, "modified") }},
		{"unit", "self_unit_changed", func(t *testing.T, f *fixture) {
			write(t, f.unit, "[Service]\nEnvironment=SSG_ALLOWLIST_FILE=/tmp/rules")
		}},
		{"new drop-in", "self_unit_changed", func(t *testing.T, f *fixture) { write(t, f.unit+".d/new.conf", "[Service]\nUser=nobody") }},
		{"global drop-in", "self_unit_changed", func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.root, "run/systemd/system/service.d/new.conf"), "[Service]\nUser=nobody")
		}},
		{"deleted unit", "self_unit_changed", func(t *testing.T, f *fixture) {
			if err := os.Remove(f.unit); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing baseline", "self_check_unavailable", func(t *testing.T, f *fixture) { os.Remove(f.baseline) }},
		{"corrupt baseline", "self_check_unavailable", func(t *testing.T, f *fixture) { write(t, f.baseline, "not a checksum") }},
		{"missing binary", "self_check_unavailable", func(t *testing.T, f *fixture) { os.Remove(f.binary) }},
		{"symlink baseline", "self_check_unavailable", func(t *testing.T, f *fixture) {
			os.Remove(f.baseline)
			if err := os.Symlink(f.unit, f.baseline); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized unit", "self_check_unavailable", func(t *testing.T, f *fixture) { write(t, f.unit, strings.Repeat("x", (1<<20)+1)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			tc.mutate(t, f)
			m := New(f.opt)
			wantID(t, m, tc.id, true)
			n := len(f.events)
			m.Check(time.Now())
			if len(f.events) != n {
				t.Fatal("duplicate events")
			}
		})
	}
}

func TestNormalInstallUpdateRollbackAndFrozenBaseline(t *testing.T) {
	f := setup(t)
	m := New(f.opt)
	if len(ids(m)) != 0 {
		t.Fatal(ids(m))
	}
	write(t, f.binary, "update")
	write(t, f.unit, "updated unit")
	f.baselineNow(t)
	m.Check(time.Now())
	wantID(t, m, "self_baseline_changed", true)
	wantID(t, m, "self_unit_changed", true)
	m = New(f.opt)
	if len(ids(m)) != 0 {
		t.Fatal("approved update", ids(m))
	}
	write(t, f.binary, "executable")
	write(t, f.unit, "old unit")
	f.baselineNow(t)
	m = New(f.opt)
	if len(ids(m)) != 0 {
		t.Fatal("approved rollback", ids(m))
	}
	write(t, f.unit, "tampered")
	m.Check(time.Now())
	wantID(t, m, "self_unit_changed", true)
	write(t, f.unit, "old unit")
	m.Check(time.Now())
	wantID(t, m, "self_unit_changed", false)
	if f.events[len(f.events)-1].Risk != model.RiskInfo {
		t.Fatal("missing recovery")
	}
}

func TestAllowlistAcrossRestartsAndNoSecrets(t *testing.T) {
	f := setup(t)
	m := New(f.opt)
	if len(f.events) != 0 {
		t.Fatal("missing optional allowlist must be normal")
	}
	secret := "sensitive-token-for-test"
	write(t, f.opt.Allowlist, secret)
	m.Check(time.Now())
	wantID(t, m, "self_allowlist_changed", true)
	if len(f.events) != 1 {
		t.Fatal(f.events)
	}
	m.Check(time.Now())
	if len(f.events) != 1 {
		t.Fatal("repeat notification")
	}
	write(t, f.opt.Allowlist, secret+"2")
	m.Check(time.Now())
	if len(f.events) != 2 {
		t.Fatal("second edit missed")
	}
	os.Remove(f.opt.Allowlist)
	m.Check(time.Now())
	if len(f.events) != 3 {
		t.Fatal("deletion missed")
	}
	write(t, f.opt.Allowlist, secret+"3")
	m = New(f.opt)
	wantID(t, m, "self_allowlist_changed", true)
	state, err := os.ReadFile(filepath.Join(f.opt.DataDir, "self-allowlist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), secret) || strings.Contains(fmt.Sprint(f.events), secret) || strings.Contains(fmt.Sprint(m.Findings()), secret) {
		t.Fatal("secret leaked")
	}
	fi, _ := os.Stat(filepath.Join(f.opt.DataDir, "self-allowlist.json"))
	if fi.Mode().Perm() != 0600 {
		t.Fatal(fi.Mode())
	}
	m = New(f.opt)
	wantID(t, m, "self_allowlist_changed", false)
}

func TestAllowlistFailuresDoNotAcceptState(t *testing.T) {
	f := setup(t)
	m := New(f.opt)
	write(t, f.opt.Allowlist, strings.Repeat("x", (1<<20)+1))
	m.Check(time.Now())
	wantID(t, m, "self_check_unavailable", true)
	if m.allow.Hash != "missing" {
		t.Fatal("failed read replaced baseline")
	}
	write(t, f.opt.Allowlist, "{}")
	m.Check(time.Now())
	wantID(t, m, "self_allowlist_changed", true)
	write(t, filepath.Join(f.opt.DataDir, "self-allowlist.json"), "corrupt")
	m = New(f.opt)
	wantID(t, m, "self_check_unavailable", true)
	data, _ := os.ReadFile(filepath.Join(f.opt.DataDir, "self-allowlist.json"))
	if string(data) != "corrupt" {
		t.Fatal("corruption evidence overwritten")
	}
}

func TestAllowlistSaveFailureAndReadOnlyMode(t *testing.T) {
	f := setup(t)
	os.Mkdir(filepath.Join(f.opt.DataDir, "self-allowlist.json"), 0700)
	m := New(f.opt)
	wantID(t, m, "self_check_unavailable", true)
	f.opt.DataDir = ""
	m = New(f.opt)
	if len(ids(m)) != 0 {
		t.Fatal(ids(m))
	}
	write(t, f.opt.Allowlist, "{}")
	m.Check(time.Now())
	wantID(t, m, "self_allowlist_changed", true)
}

func TestFreshBoundaryAndStallRecovery(t *testing.T) {
	start := time.Now()
	for _, tc := range []struct {
		age  time.Duration
		want bool
	}{{0, true}, {3 * time.Second, true}, {3*time.Second + 1, false}, {10 * time.Second, false}} {
		if got := Fresh(start.Add(tc.age), start, time.Second); got != tc.want {
			t.Fatalf("age %v = %v", tc.age, got)
		}
	}
	if Fresh(start, time.Time{}, time.Second) {
		t.Fatal("zero progress")
	}
	if !Fresh(start.Add(time.Hour), start, time.Duration(1<<63-1)) {
		t.Fatal("overflow")
	}
	f := setup(t)
	last := start
	f.opt.Progress = func() time.Time { return last }
	m := New(f.opt)
	m.Check(start.Add(4 * time.Second))
	wantID(t, m, "self_scan_stalled", true)
	last = start.Add(4 * time.Second)
	m.Check(last)
	wantID(t, m, "self_scan_stalled", false)
}

func TestClockStepVersusNTP(t *testing.T) {
	for _, tc := range []struct {
		shift time.Duration
		want  bool
	}{{500 * time.Millisecond, false}, {time.Second, false}, {2 * time.Second, true}, {-10 * time.Second, false}} {
		t.Run(tc.shift.String(), func(t *testing.T) {
			f := setup(t)
			m := New(f.opt)
			base := time.Now()
			m.previous = base
			m.previousWall = base.Round(0).Add(tc.shift)
			m.Check(base.Add(time.Second))
			wantID(t, m, "self_clock_back", tc.want)
			m.Check(base.Add(2 * time.Second))
			wantID(t, m, "self_clock_back", tc.want)
		})
	}
}

func TestConcurrentSnapshotsAndCancellation(t *testing.T) {
	f := setup(t)
	f.opt.Record = nil
	m := New(f.opt)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 25; n++ {
				m.Findings()
				m.Check(time.Now())
			}
		}()
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("run ignored cancellation")
	}
}

func TestParseBaselineValidation(t *testing.T) {
	f := setup(t)
	data, _ := os.ReadFile(f.baseline)
	if _, err := parseBaseline(data); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(nil))
	for _, s := range []string{"", string(data) + hash + "  binary\n", hash + "  /etc/shadow\n", strings.Replace(string(data), "binary", "../binary", 1), strings.Replace(string(data), "  ", " *", 1), strings.Replace(string(data), hash, "x", 1)[:10]} {
		if _, err := parseBaseline([]byte(s)); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func FuzzParseBaseline(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte(strings.Repeat("a", 64) + "  binary\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 512<<10 {
			return
		}
		_, _ = parseBaseline(data)
	})
}

func TestBaselineRemovalAndHistoryFailure(t *testing.T) {
	f := setup(t)
	var log bytes.Buffer
	f.opt.Logger = slog.New(slog.NewTextHandler(&log, nil))
	f.opt.Record = func(model.Event) error { return os.ErrPermission }
	m := New(f.opt)
	os.Remove(f.baseline)
	m.Check(time.Now())
	wantID(t, m, "self_check_unavailable", true)
	if !strings.Contains(log.String(), "permission denied") {
		t.Fatal("history failure was silent", log.String())
	}
	if len(m.Findings()[0].Evidence) == 0 {
		t.Fatal("missing read error evidence")
	}
}

func TestAllowlistWriteFailureKeepsOldHash(t *testing.T) {
	f := setup(t)
	m := New(f.opt)
	before := m.allow
	os.Remove(filepath.Join(f.opt.DataDir, "self-allowlist.json"))
	os.Remove(f.opt.DataDir)
	write(t, f.opt.Allowlist, "new")
	m.Check(time.Now())
	wantID(t, m, "self_check_unavailable", true)
	if m.allow != before {
		t.Fatal("unsaved state accepted")
	}
	entries, _ := filepath.Glob(filepath.Join(f.opt.DataDir, ".self-allowlist-*"))
	if len(entries) != 0 {
		t.Fatal(entries)
	}
}

func TestInvalidAllowStates(t *testing.T) {
	for _, s := range []allowState{{}, {Path: "x", Hash: "bad"}, {Hash: strings.Repeat("a", 64)}} {
		if validAllowState(s) {
			t.Fatal(s)
		}
	}
	if !validAllowState(allowState{Path: "x", Hash: "missing"}) {
		t.Fatal("missing marker rejected")
	}
}

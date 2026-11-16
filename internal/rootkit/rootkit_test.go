package rootkit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func write(t *testing.T, root, name, data string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func process(t *testing.T, root, dir string, pid, tgid, ppid int, start uint64) {
	t.Helper()
	write(t, root, dir+"/status", fmt.Sprintf("Name:\ttest\nPid:\t%d\nTgid:\t%d\nPPid:\t%d\n", pid, tgid, ppid))
	f := strings.Fields("S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0")
	for len(f) < 50 {
		f = append(f, "0")
	}
	f[1] = strconv.Itoa(ppid)
	f[19] = strconv.FormatUint(start, 10)
	write(t, root, dir+"/stat", fmt.Sprintf("%d (a ) tricky) %s\n", pid, strings.Join(f, " ")))
	if err := os.MkdirAll(filepath.Join(root, dir, "task"), 0700); err != nil {
		t.Fatal(err)
	}
}
func ids(findings []model.SystemFinding) map[string]model.Risk {
	out := map[string]model.Risk{}
	for _, f := range findings {
		out[f.ID] = f.Risk
	}
	return out
}
func TestHiddenProcessRequiresStableLeader(t *testing.T) {
	for _, kind := range []string{"hidden", "thread", "reappeared", "exited", "reused", "reparented", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			process(t, root, "42", 42, 42, 1, 10)
			if kind == "thread" {
				process(t, root, "42", 42, 40, 1, 10)
			}
			list := func(string) (map[int]bool, error) {
				switch kind {
				case "reappeared":
					return map[int]bool{42: true}, nil
				case "exited":
					os.RemoveAll(filepath.Join(root, "42"))
				case "reused":
					process(t, root, "42", 42, 42, 1, 11)
				case "reparented":
					process(t, root, "42", 42, 42, 2, 10)
				}
				return map[int]bool{}, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			f, err := confirmHidden(ctx, root, map[int]bool{}, []int{42, 43}, 0, list)
			if kind == "cancelled" {
				if err == nil {
					t.Fatal("cancel ignored")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "hidden" {
				if len(f) != 1 || f[0].ID != "hidden_process" || f[0].Risk != model.RiskCritical || !f[0].Strong {
					t.Fatalf("%+v", f)
				}
			} else if len(f) != 0 {
				t.Fatalf("false positive: %+v", f)
			}
		})
	}
}
func TestCandidatesAndMalformedIdentity(t *testing.T) {
	root := t.TempDir()
	process(t, root, "10", 10, 10, 42, 100)
	process(t, root, "10/task/11", 11, 99, 42, 100)
	got, err := candidates(root, map[int]bool{10: true})
	if err != nil || fmt.Sprint(got) != "[42 99]" {
		t.Fatalf("%v %v", got, err)
	}
	for _, status := range []string{"Pid: 10\n", "Pid: -1\nTgid: 1\n", "Pid: 10\nTgid: 10\nPid: 10\n"} {
		write(t, root, "10/status", status)
		if _, err := processIdentity(filepath.Join(root, "10")); err == nil {
			t.Fatalf("accepted %q", status)
		}
	}
	process(t, root, "10", 10, 10, 0, 100)
	write(t, root, "10/stat", "truncated")
	if _, err := processIdentity(filepath.Join(root, "10")); err == nil {
		t.Fatal("accepted truncated stat")
	}
}
func hostFixture(t *testing.T) (string, string) {
	t.Helper()
	p, h := t.TempDir(), t.TempDir()
	write(t, p, "modules", "")
	write(t, p, "sys/kernel/tainted", "0\n")
	write(t, p, "sys/kernel/osrelease", "6.test\n")
	write(t, p, "sys/kernel/pid_max", "2049\n")
	write(t, p, "sys/kernel/random/boot_id", "12345678-1234-1234-1234-123456789abc\n")
	if err := os.MkdirAll(filepath.Join(h, "sys/module"), 0700); err != nil {
		t.Fatal(err)
	}
	write(t, h, "lib/modules/6.test/modules.dep", "")
	return p, h
}
func moduleFixture(t *testing.T, h, name, state, taint string) {
	write(t, h, "sys/module/"+name+"/initstate", state)
	write(t, h, "sys/module/"+name+"/taint", taint)
}
func TestModulesStatesTaintAndIndex(t *testing.T) {
	p, h := hostFixture(t)
	write(t, p, "modules", "known 100 0 - Live 0x0\nnvidia 200 0 - Live 0x0\nloading 100 0 - Loading 0x0\n")
	moduleFixture(t, h, "known", "live", "EO")
	moduleFixture(t, h, "nvidia", "live", "OE")
	moduleFixture(t, h, "hidden", "live", "")
	moduleFixture(t, h, "loading", "coming", "")
	moduleFixture(t, h, "unloading", "going", "")
	os.MkdirAll(filepath.Join(h, "sys/module/builtin"), 0700)
	write(t, h, "lib/modules/6.test/modules.dep", "kernel/known.ko.xz:\nkernel/nvidia.ko.zst:\n")
	write(t, p, "sys/kernel/tainted", "8192\n")
	f, live, err := moduleChecks(context.Background(), p, h, map[string]bool{"known": true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]map[string]model.Risk{}
	for _, v := range f {
		if byPath[v.Path] == nil {
			byPath[v.Path] = map[string]model.Risk{}
		}
		byPath[v.Path][v.ID] = v.Risk
	}
	if byPath["/sys/module/hidden"]["kmod_hidden"] != model.RiskCritical {
		t.Fatalf("%+v", f)
	}
	if byPath["/sys/module/known"]["kmod_unsigned"] != model.RiskMedium || byPath["/sys/module/nvidia"]["kmod_unsigned"] != model.RiskLow {
		t.Fatalf("%+v", f)
	}
	if len(live) != 2 || len(byPath["/sys/module/loading"]) != 0 || len(byPath["/sys/module/builtin"]) != 0 {
		t.Fatalf("false positive %+v", f)
	}
	if _, ok := ids(f)["kernel_tainted"]; !ok {
		t.Fatal("missing taint")
	}
	if len(taintReasons(1<<63|1<<18)) != 2 {
		t.Fatal("lost taint bits")
	}
	for _, bad := range []string{"bad", "x -1 0 - Live 0", "x 1 0 - Bad 0", "x 1 0 - Live 0\nx 1 0 - Live 0"} {
		if _, err := parseModules(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	write(t, p, "sys/kernel/osrelease", "../escape")
	f, _, err = moduleChecks(context.Background(), p, h, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids(f)["kmod_origin_unavailable"]; !ok {
		t.Fatal("missing unavailable")
	}
}
func TestBaselineBootPersistenceAndCorruption(t *testing.T) {
	p, h := hostFixture(t)
	state := t.TempDir()
	c := New(Options{ProcRoot: p, HostRoot: h, StateDir: state})
	c.confirmDelay = 0
	c.Check(context.Background())
	fi, err := os.Stat(filepath.Join(state, "rootkit-modules.json"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("%v %v", fi, err)
	}
	write(t, p, "modules", "newmod 1 0 - Live 0\n")
	moduleFixture(t, h, "newmod", "live", "")
	c = New(Options{ProcRoot: p, HostRoot: h, StateDir: state})
	c.confirmDelay = 0
	if _, ok := ids(c.Check(context.Background()))["kmod_new"]; !ok {
		t.Fatal("baseline not loaded")
	}
	write(t, p, "sys/kernel/random/boot_id", "23456789-1234-1234-1234-123456789abc")
	if _, ok := ids(c.Check(context.Background()))["kmod_new"]; ok {
		t.Fatal("previous boot baseline reused")
	}
	write(t, state, "rootkit-modules.json", "broken")
	c = New(Options{ProcRoot: p, HostRoot: h, StateDir: state})
	c.confirmDelay = 0
	if _, ok := ids(c.Check(context.Background()))["rootkit_unavailable"]; !ok {
		t.Fatal("corruption hidden")
	}
	data, _ := os.ReadFile(filepath.Join(state, "rootkit-modules.json"))
	if string(data) != "broken" {
		t.Fatal("corrupt baseline overwritten")
	}
}
func TestSweepBoundariesAndConcurrency(t *testing.T) {
	p, h := hostFixture(t)
	process(t, p, "2048", 2048, 2048, 0, 1)
	c := New(Options{ProcRoot: p, HostRoot: h})
	c.confirmDelay = 0
	c.batchPause = 0
	c.list = func(string) (map[int]bool, error) { return map[int]bool{}, nil }
	if err := c.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.checked != 2048 || !c.complete || len(c.sweep) != 1 {
		t.Fatalf("%+v", c)
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Check(context.Background()) }()
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Sweep(ctx); err == nil || c.complete {
		t.Fatal("cancelled sweep passed")
	}
	for _, bad := range []string{"0", "-1", "4194305", "bad"} {
		write(t, p, "sys/kernel/pid_max", bad)
		if err := c.Sweep(context.Background()); err == nil {
			t.Fatal("bad pid_max passed")
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	c.Run(ctx)
}
func FuzzParseModules(f *testing.F) {
	f.Add("x 100 0 - Live 0x0\n")
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseModules(s) })
}

package fsinspect

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func fixture(t *testing.T) (Options, func(string, string)) {
	t.Helper()
	root := t.TempDir()
	proc := t.TempDir()
	write := func(p, b string) {
		t.Helper()
		p = filepath.Join(root, p)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(b), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("etc/passwd", fmt.Sprintf("root:x:%d:%d::/root:/bin/sh\n", os.Getuid(), os.Getgid()))
	write("etc/group", fmt.Sprintf("root:x:%d:\n", os.Getgid()))
	write("var/lib/dpkg/status", "Package: sample\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n")
	write("var/lib/dpkg/info/sample.list", "/usr/bin/example\n")
	os.MkdirAll(filepath.Join(proc, "self"), 0700)
	os.WriteFile(filepath.Join(proc, "self/mountinfo"), []byte("1 0 1:1 / / rw - ext4 /dev/test rw\n"), 0600)
	return Options{HostRoot: root, ProcRoot: proc, Rate: 1000000, StateDir: t.TempDir(), capRead: func(*os.File) (Capability, error) { return Capability{}, nil }}, write
}
func TestCapabilityFormatsAndMalformed(t *testing.T) {
	for rev, size := range map[uint32]int{1: 12, 2: 20, 3: 24} {
		b := make([]byte, size)
		binary.LittleEndian.PutUint32(b, rev<<24|1)
		binary.LittleEndian.PutUint32(b[4:], 1<<7)
		if rev >= 2 {
			binary.LittleEndian.PutUint32(b[12:], 1)
		}
		if rev == 3 {
			binary.LittleEndian.PutUint32(b[20:], 100000)
		}
		c, e := ParseCapability(b)
		if e != nil || !c.Effective || c.Permitted&128 == 0 || (rev == 3 && c.RootID != 100000) || (rev >= 2 && c.Permitted>>32 != 1) {
			t.Fatal(c, e)
		}
		for _, bad := range [][]byte{b[:size-1], append(append([]byte(nil), b...), 0), {0, 0, 0, 4}} {
			if _, e := ParseCapability(bad); e == nil {
				t.Fatal("malformed accepted")
			}
		}
	}
}
func TestInventoryScopeAndBaseline(t *testing.T) {
	o, write := fixture(t)
	write("usr/bin/example", "test")
	if e := os.Chmod(filepath.Join(o.HostRoot, "usr/bin/example"), os.ModeSetuid|0755); e != nil {
		t.Fatal(e)
	}
	write("tmp/bash", "test")
	os.Chmod(filepath.Join(o.HostRoot, "tmp/bash"), os.ModeSetuid|0755)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "outside"), nil, 0600)
	os.Symlink(outside, filepath.Join(o.HostRoot, "escape"))
	r := New(o)
	first := r.RunOnce(context.Background())
	if first.Incomplete || len(first.Files) != 2 {
		t.Fatalf("%+v", first)
	}
	for _, f := range first.Files {
		if f.Path == "/usr/bin/example" && (f.PackageOwned == nil || !*f.PackageOwned) {
			t.Fatal("package ownership missing")
		}
	}
	found := false
	for _, f := range first.Findings {
		found = found || (f.Path == "/tmp/bash" && f.Risk == model.RiskCritical)
	}
	if !found {
		t.Fatal("dangerous SUID missing")
	}
	baseline, _ := os.ReadFile(statePath(o))
	fi, _ := os.Stat(statePath(o))
	if fi.Mode().Perm() != 0600 {
		t.Fatal(fi.Mode())
	}
	write("usr/bin/new", "test")
	os.Chmod(filepath.Join(o.HostRoot, "usr/bin/new"), os.ModeSetuid|0755)
	restart := New(o)
	second := restart.RunOnce(context.Background())
	found = false
	for _, f := range second.Findings {
		found = found || f.ID == "fs_privilege_new"
	}
	if !found {
		t.Fatal("restart lost original baseline")
	}
	current, _ := os.ReadFile(statePath(o))
	if string(baseline) != string(current) {
		t.Fatal("baseline silently advanced")
	}
	o.Exclude = []string{"/tmp"}
	limited := New(o).RunOnce(context.Background())
	if !limited.Incomplete {
		t.Fatal("changed scope accepted")
	}
}
func TestInventoryIncompleteAndReadOnly(t *testing.T) {
	o, write := fixture(t)
	write("usr/bin/f", "test")
	o.ReadOnly = true
	r := New(o)
	r.RunOnce(context.Background())
	if _, e := os.Stat(statePath(o)); !os.IsNotExist(e) {
		t.Fatal("readonly wrote baseline")
	}
	o.ReadOnly = false
	o.MaxEntries = 2
	r = New(o)
	rep := r.RunOnce(context.Background())
	if !rep.Incomplete {
		t.Fatal("limit hidden")
	}
	if _, e := os.Stat(statePath(o)); !os.IsNotExist(e) {
		t.Fatal("partial baseline saved")
	}
	o.MaxEntries = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !Scan(ctx, o).Incomplete {
		t.Fatal("cancellation hidden")
	}
	os.WriteFile(statePath(o), []byte("broken"), 0600)
	if !New(o).RunOnce(context.Background()).Incomplete {
		t.Fatal("corrupt baseline ignored")
	}
}
func TestCapabilityRiskAndImmutableReport(t *testing.T) {
	o, write := fixture(t)
	write("usr/bin/python3", "test")
	o.capRead = func(f *os.File) (Capability, error) {
		if filepath.Base(f.Name()) == "python3" {
			return Capability{Permitted: 128, Effective: true}, nil
		}
		return Capability{}, nil
	}
	r := New(o)
	first := r.RunOnce(context.Background())
	b, _ := json.Marshal(first)
	found := false
	for _, f := range first.Findings {
		found = found || (f.ID == "fs_capabilities" && f.Risk == model.RiskCritical)
	}
	if !found {
		t.Fatal("setuid capability missed")
	}
	r.RunOnce(context.Background())
	after, _ := json.Marshal(first)
	if string(b) != string(after) {
		t.Fatal("report mutated")
	}
}
func TestMountInfo(t *testing.T) {
	mounts, e := ParseMountInfo("1 0 1:1 / / rw - ext4 /dev/a rw\n2 1 0:1 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n3 1 0:2 / /var/data\\040files ro - nfs server:/data ro\n")
	if e != nil {
		t.Fatal(e)
	}
	m, ok := MountAt(mounts, "/tmp/a")
	if !ok || m.Point != "/tmp" || !m.Options["nosuid"] {
		t.Fatal(m)
	}
	if !NetworkFS(mounts[2].Type) || mounts[2].Point != "/var/data files" {
		t.Fatal(mounts[2])
	}
	for _, bad := range []string{"", "1 2", "1 0 0:1 / /../tmp rw - tmpfs tmpfs rw"} {
		if _, e := ParseMountInfo(bad); e == nil {
			t.Fatal(bad)
		}
	}
}
func TestRateCancellation(t *testing.T) {
	o, write := fixture(t)
	for i := 0; i < 110; i++ {
		write(fmt.Sprintf("files/%03d", i), "x")
	}
	o.Rate = 1
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if !Scan(ctx, o).Incomplete || time.Since(start) > time.Second {
		t.Fatal("rate wait ignored cancellation")
	}
}
func FuzzCapability(f *testing.F) {
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, b []byte) { ParseCapability(b) })
}

func TestNetworkScopeAndChangingMetadata(t *testing.T) {
	o, write := fixture(t)
	write("usr/bin/tool", "test")
	o.capRead = func(f *os.File) (Capability, error) {
		if filepath.Base(f.Name()) == "tool" {
			if e := os.Chmod(f.Name(), 0755|os.ModeSetuid); e != nil {
				t.Fatal(e)
			}
		}
		return Capability{Permitted: 128}, nil
	}
	if !Scan(context.Background(), o).Incomplete {
		t.Fatal("metadata race accepted")
	}
	o.capRead = func(*os.File) (Capability, error) { return Capability{}, nil }
	os.WriteFile(filepath.Join(o.ProcRoot, "self/mountinfo"), []byte("1 0 1:1 / / rw - nfs server:/data rw\n"), 0600)
	if r := Scan(context.Background(), o); !r.Incomplete || r.Scanned != 0 {
		t.Fatal("network root traversed", r)
	}
}

func TestExcludedMountDoesNotInvalidateInventoryScope(t *testing.T) {
	o, _ := fixture(t)
	first := Scan(context.Background(), o)
	os.WriteFile(filepath.Join(o.ProcRoot, "self/mountinfo"), []byte("1 0 1:1 / / rw - ext4 /dev/test rw\n2 1 1:2 / /var/lib/docker/overlay2/new/merged rw - overlay overlay rw\n"), 0600)
	next := Scan(context.Background(), o)
	if first.Scope != next.Scope {
		t.Fatal("excluded Docker mount changed inventory scope")
	}
}

func FuzzMountInfo(f *testing.F) {
	f.Add("1 0 1:1 / / rw - ext4 /dev/test rw\n")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		ParseMountInfo(data)
	})
}

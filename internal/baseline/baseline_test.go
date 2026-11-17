package baseline

import (
	"context"
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sample() *model.BaselineSnapshot {
	return &model.BaselineSnapshot{Version: 1, Time: time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC), Host: "host", Sections: map[string]model.BaselineSection{"users": {Scope: "local", Complete: true, Items: map[string]string{"root": "0"}}, "ports": {Scope: "public-listeners-address-protocol-binary-v1", Complete: true, Items: map[string]string{"tcp 0.0.0.0:22": `["/usr/sbin/sshd"]`}}}}
}
func clone(b *model.BaselineSnapshot) *model.BaselineSnapshot {
	data, _ := json.Marshal(b)
	var c model.BaselineSnapshot
	json.Unmarshal(data, &c)
	return &c
}
func TestStorePrivateImmutableAndRejectsUnsafe(t *testing.T) {
	s := New(t.TempDir())
	b := sample()
	if e := s.Save("before-upgrade", b); e != nil {
		t.Fatal(e)
	}
	if e := s.Save("before-upgrade", b); !os.IsExist(e) {
		t.Fatal("overwrite", e)
	}
	for _, name := range []string{"../escape", "/tmp/escape", "a/b", ".", "a.json", "", strings.Repeat("a", 65)} {
		if e := s.Save(name, b); e == nil {
			t.Fatal(name)
		}
	}
	got, e := s.Load("before-upgrade")
	if e != nil || got.Host != b.Host {
		t.Fatal(got, e)
	}
	for p, mode := range map[string]os.FileMode{s.Dir: 0700, filepath.Join(s.Dir, "before-upgrade.json"): 0600} {
		fi, e := os.Stat(p)
		if e != nil || fi.Mode().Perm() != mode {
			t.Fatal(p, fi, e)
		}
	}
	if e := os.Symlink(filepath.Join(s.Dir, "before-upgrade.json"), filepath.Join(s.Dir, "link.json")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Load("link"); e == nil {
		t.Fatal("link read")
	}
	if e := s.Save("link", b); e == nil {
		t.Fatal("link overwritten")
	}
	os.WriteFile(filepath.Join(s.Dir, "corrupt.json"), []byte("{}"), 0600)
	if _, e := s.Load("corrupt"); e == nil {
		t.Fatal("corrupt accepted")
	}
	os.Chmod(s.Dir, 0755)
	if _, e := s.List(); e == nil {
		t.Fatal("public directory accepted")
	}
	parent := t.TempDir()
	os.Symlink(s.Dir, filepath.Join(parent, "baselines"))
	if _, e := New(parent).List(); e == nil {
		t.Fatal("directory link accepted")
	}
}
func TestDiffCompleteSectionsOnly(t *testing.T) {
	a := sample()
	b := clone(a)
	s := b.Sections["users"]
	s.Items["root"] = "100"
	s.Items["new"] = "1000"
	b.Sections["users"] = s
	d := Diff(a, b)
	if d.Incomplete || len(d.Changes) != 2 {
		t.Fatal(d)
	}
	delete(s.Items, "root")
	d = Diff(a, b)
	if d.Changes[1].Kind != "removed" {
		t.Fatal(d.Changes)
	}
	s.Complete = false
	b.Sections["users"] = s
	d = Diff(a, b)
	if !d.Incomplete || len(d.Changes) != 0 {
		t.Fatal("unknown produced removals", d)
	}
	s.Complete = true
	s.Scope = "different"
	b.Sections["users"] = s
	if d = Diff(a, b); !d.Incomplete || len(d.Changes) != 0 {
		t.Fatal(d)
	}
	b.Host = "other"
	if d = Diff(a, b); !d.Incomplete || len(d.Changes) != 0 {
		t.Fatal(d)
	}
	if !Diff(nil, b).Incomplete {
		t.Fatal("missing baseline clean")
	}
}
func TestMonitorWeeklyPortAcceptanceAndImmutableReports(t *testing.T) {
	s := New(t.TempDir())
	cur := sample()
	m := NewMonitor(s, func(context.Context) *model.BaselineSnapshot { return cur })
	m.Refresh(context.Background())
	first := m.Report()
	data, _ := json.Marshal(first)
	snap := &model.Snapshot{Exposure: &model.ExposureReport{Entries: []model.Exposure{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Scope: model.ScopePublic, Exe: "/usr/sbin/sshd"}}}}
	if f := m.PortFindings(snap); len(f) != 0 {
		t.Fatal(f)
	}
	snap.Exposure.Entries[0].Exe = "/tmp/other"
	if f := m.PortFindings(snap); len(f) != 1 || f[0].Risk != model.RiskHigh {
		t.Fatal(f)
	}
	cur = clone(cur)
	cur.Time = cur.Time.Add(8 * 24 * time.Hour)
	p := cur.Sections["ports"]
	p.Items["tcp 0.0.0.0:22"] = `["/tmp/other"]`
	cur.Sections["ports"] = p
	if e := s.AcceptPorts(cur); e != nil {
		t.Fatal(e)
	}
	m.Refresh(context.Background())
	if f := m.PortFindings(snap); len(f) != 0 {
		t.Fatal(f)
	}
	if m.Report().Week.Incomplete {
		t.Fatal(m.Report().Week)
	}
	after, _ := json.Marshal(first)
	if string(data) != string(after) {
		t.Fatal("published report mutated")
	}
	p.Complete = false
	cur.Sections["ports"] = p
	if e := s.AcceptPorts(cur); e == nil {
		t.Fatal("accepted incomplete ports")
	}
	for i := 0; i < 14; i++ {
		b := clone(cur)
		b.Time = b.Time.Add(time.Duration(i) * 7 * 24 * time.Hour)
		if e := s.Save("weekly-"+b.Time.Format("20060102T150405Z"), b); e != nil && !os.IsExist(e) {
			t.Fatal(e)
		}
	}
	if e := s.Save("manual-preserve", cur); e != nil {
		t.Fatal(e)
	}
	if e := s.PruneWeekly(); e != nil {
		t.Fatal(e)
	}
	names, e := s.List()
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	for _, name := range names {
		if autoRE.MatchString(name) {
			n++
		}
	}
	if n != 12 {
		t.Fatal(names)
	}
	if _, e = s.Load("manual-preserve"); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			m.Refresh(context.Background())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m.Report()
			m.PortFindings(snap)
		}
	}()
	wg.Wait()
}
func TestCaptureRootsSecretsAndCompleteness(t *testing.T) {
	root := t.TempDir()
	proc := t.TempDir()
	write := func(base, p, text string) {
		t.Helper()
		n := filepath.Join(base, p)
		if e := os.MkdirAll(filepath.Dir(n), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(n, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(root, "etc/machine-id", strings.Repeat("a", 32))
	write(root, "etc/passwd", "root:SECRET_HASH:0:0::/root:/bin/sh\n")
	write(root, "etc/group", "root:SECRET_GROUP:0:root\n")
	write(root, "usr/lib/systemd/system/test.service", "[Service]\nExecStart=/bin/true\nEnvironment=SECRET_ENV\n")
	write(root, "usr/bin/bash", "example binary")
	os.Symlink("usr/bin", filepath.Join(root, "bin"))
	write(proc, "modules", "test 10 0 - Live 0x0\n")
	for _, n := range []string{"tcp", "tcp6", "udp", "udp6"} {
		write(proc, "net/"+n, "sl local_address rem_address st\n")
	}
	snap := &model.Snapshot{Auth: &model.AuthReport{Keys: []model.SSHKey{{Path: "/root/.ssh/authorized_keys", User: "root", Fingerprint: "SHA256:test", Comment: "SECRET_COMMENT"}}}, Inventory: &model.FileInventory{Scope: "fixture", Files: []model.FilePrivilege{{Path: "/usr/bin/tool", SUID: true, Permitted: 128}}}, Exposure: &model.ExposureReport{}}
	b := Capture(context.Background(), root, proc, snap, &model.AuditReport{Checks: []model.AuditCheck{{ID: "test", Status: model.AuditPass}}})
	if b.Host == "" || len(b.Sections) != 11 || !b.Sections["ports"].Complete || len(b.Sections["units"].Items) != 1 || b.Sections["binaries"].Items["/bin/bash"] == "" {
		t.Fatalf("%+v", b)
	}
	data, _ := json.Marshal(b)
	if strings.Contains(string(data), "SECRET") {
		t.Fatal("secret retained", string(data))
	}
	snap.Stats.Restricted = 1
	if Ports(proc, snap).Complete {
		t.Fatal("restricted accepted")
	}
	snap.Stats.Restricted = 0
	snap.Exposure.Entries = []model.Exposure{{Scope: model.ScopePublic, Proto: "tcp", Addr: "::", Port: 22}}
	if Ports(proc, snap).Complete {
		t.Fatal("unknown binary accepted")
	}
	os.Remove(filepath.Join(root, "etc/passwd"))
	c := Capture(context.Background(), root, proc, snap, nil)
	if c.Sections["users"].Complete || c.Sections["audit"].Complete {
		t.Fatal("missing data complete")
	}
}

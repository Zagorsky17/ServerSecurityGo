package procfs

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"testing"
)

const bpfFixture = "pos:\t0\nprog_type:\t2\nprog_id:\t17\nprog_tag:\t0123456789abcdef\n"
const packetFixture = "sk RefCnt Type Proto Iface R Rmem User Inode\n000000 3 3 0003 2 1 0 1000 987\n"

func TestBPFAndPacketParsing(t *testing.T) {
	b, e := ParseBPFInfo(bpfFixture, "bpf-prog")
	if e != nil || b.Type != 2 || b.ID != 17 || b.Tag != "0123456789abcdef" {
		t.Fatal(b, e)
	}
	for _, bad := range []string{"", bpfFixture + "prog_id: 18\n", "prog_type: -2\nprog_id: 1\nprog_tag: x\n"} {
		if _, e := ParseBPFInfo(bad, "bpf-prog"); e == nil {
			t.Fatal(bad)
		}
	}
	if _, e := ParseBPFInfo("map_type: 1\nmap_id: 2\n", "bpf-map"); e != nil {
		t.Fatal(e)
	}
	s, e := ParsePacketTable(packetFixture, "net:[1]")
	if e != nil || len(s) != 1 || s[0].Inode != 987 || s[0].PacketInterface != 2 || s[0].UID != 1000 {
		t.Fatal(s, e)
	}
	for _, bad := range []string{"", "header\n", packetFixture + "malformed\n"} {
		if _, e := ParsePacketTable(bad, ""); e == nil {
			t.Fatal(bad)
		}
	}
}
func TestBPFReadDoesNotFollowFDInfoSymlink(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "42/fdinfo"), 0700)
	os.MkdirAll(filepath.Join(root, "42/fd"), 0700)
	os.Symlink("anon_inode:bpf-prog", filepath.Join(root, "42/fd/3"))
	os.WriteFile(filepath.Join(root, "42/fdinfo/3"), []byte(bpfFixture), 0600)
	fs := New(root, root)
	p := &model.Process{}
	fs.readBPF("42", 3, "anon_inode:bpf-prog", p)
	if len(p.BPF) != 1 {
		t.Fatal(p)
	}
	os.Remove(filepath.Join(root, "42/fdinfo/3"))
	os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, "42/fdinfo/3"))
	os.WriteFile(filepath.Join(root, "outside"), []byte(bpfFixture), 0600)
	p = &model.Process{}
	fs.readBPF("42", 3, "anon_inode:bpf-prog", p)
	if len(p.BPF) != 0 || len(p.Access) == 0 {
		t.Fatal(p)
	}
}
func FuzzAdvancedProc(f *testing.F) {
	f.Add(bpfFixture)
	f.Add(packetFixture)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			t.Skip()
		}
		ParseBPFInfo(s, "bpf-prog")
		ParsePacketTable(s, "")
	})
}

func TestBPFDescriptorBudgetAndFDReadErrors(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "42/fd"), 0700)
	os.MkdirAll(filepath.Join(root, "42/fdinfo"), 0700)
	for _, fd := range []string{"3", "4"} {
		os.Symlink("anon_inode:bpf-prog", filepath.Join(root, "42/fd", fd))
		os.WriteFile(filepath.Join(root, "42/fdinfo", fd), []byte(bpfFixture), 0600)
	}
	fs := New(root, root)
	raw := &Raw{Proc: &model.Process{}, SocketInodes: map[uint64][]int{}}
	fs.readFDs("42", raw, 10, 1)
	if raw.BPFReads != 1 || len(raw.Proc.BPF) != 1 || len(raw.Proc.Access) != 1 || raw.Proc.Access[0] != "bpf:limit" {
		t.Fatal(raw)
	}
	os.RemoveAll(filepath.Join(root, "42/fd"))
	os.WriteFile(filepath.Join(root, "42/fd"), []byte("not a directory"), 0600)
	raw = &Raw{Proc: &model.Process{}}
	fs.readFDs("42", raw, 10, 1)
	if len(raw.Proc.Access) == 0 {
		t.Fatal("non-permission FD error hidden")
	}
}

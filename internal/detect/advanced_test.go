package detect

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestAdvancedCalibration(t *testing.T) {
	p := &model.Process{Exe: "/usr/bin/tcpdump", ExeInfo: &model.FileInfo{}, Sockets: []model.Socket{{Proto: "packet", PacketInterface: 2}}}
	c := &Context{Owners: map[string]bool{p.Exe: true}, Cfg: DefaultConfig()}
	f := ruleAdvanced(p, c)
	if len(f) != 1 || f[0].Category != model.CatInfo {
		t.Fatal(f)
	}
	p.ExeInfo.WorldWritable = true
	f = ruleAdvanced(p, c)
	if !f[0].Strong || f[0].Weight == 0 {
		t.Fatal("writable tool trusted", f)
	}
	p.Exe = "/tmp/tcpdump"
	p.BPF = []model.BPFDescriptor{{Kind: "bpf-prog", Type: 2, ID: 1}}
	f = ruleAdvanced(p, c)
	if len(f) != 2 || !f[0].Strong {
		t.Fatal(f)
	}
	p.Executable = &model.ExecutableInspection{ELF: true, Packing: "entropy"}
	f = ruleAdvanced(p, c)
	if f[len(f)-1].Weight != 0 {
		t.Fatal("entropy raised risk")
	}
	p.Executable.Packing = "upx-marker"
	f = ruleAdvanced(p, c)
	if f[len(f)-1].Weight == 0 {
		t.Fatal("UPX signal lost")
	}
	p.Executable.Incomplete = true
	f = ruleAdvanced(p, c)
	if len(f) != 2 {
		t.Fatal("incomplete ELF used")
	}
}
func TestPromiscMatchesInterfaceAndNamespace(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"eth0", "eth1"} {
		os.MkdirAll(filepath.Join(root, "sys/class/net", n), 0700)
		os.WriteFile(filepath.Join(root, "sys/class/net", n, "flags"), []byte("0x1103"), 0600)
	}
	os.WriteFile(filepath.Join(root, "sys/class/net/eth0/ifindex"), []byte("2"), 0600)
	os.WriteFile(filepath.Join(root, "sys/class/net/eth1/ifindex"), []byte("3"), 0600)
	p := &model.Process{Exe: "/usr/bin/tcpdump", ExeInfo: &model.FileInfo{}, Sockets: []model.Socket{{Proto: "packet", PacketInterface: 2}}}
	owners := map[string]bool{p.Exe: true}
	f := PromiscuousInterfaces(root, []*model.Process{p}, owners)
	if len(f) != 2 || f[0].Risk != model.RiskInfo || f[1].Risk != model.RiskMedium {
		t.Fatal(f)
	}
	p.ForeignNS = []string{"net"}
	f = PromiscuousInterfaces(root, []*model.Process{p}, owners)
	if f[0].Risk != model.RiskMedium {
		t.Fatal("container socket waived host interface")
	}
}

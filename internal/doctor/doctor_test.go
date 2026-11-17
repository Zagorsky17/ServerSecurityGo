package doctor

import (
	"context"
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/config"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorOfflineReadOnlyAndMissingData(t *testing.T) {
	tree := &fakeproc.Tree{Procs: []*fakeproc.Proc{{PID: 4242, Comm: "fixture", Exe: "/usr/bin/fixture", StartTicks: 20}}, HostFiles: map[string]string{"/var/log/auth.log": "PRIVATE_CANARY", "/var/lib/dpkg/status": "Package: test\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n", "/var/lib/dpkg/info/test.list": "/usr/bin/fixture\n", "/etc/systemd/system/serversecuritygo.service": "[Service]\nExecStart=/opt/serversecuritygo/bin/serversecuritygo serve\n"}}
	proc, host, e := tree.Write(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	cfg := config.Default()
	cfg.HostRoot = host
	cfg.ProcRoot = proc
	os.MkdirAll(filepath.Join(host, "var/lib/serversecuritygo"), 0777)
	os.Chmod(filepath.Join(host, "var/lib/serversecuritygo"), 0777)
	r := Run(context.Background(), cfg)
	byID := map[string]model.AuditCheck{}
	for _, c := range r.Checks {
		byID[c.ID] = c
	}
	if byID["doctor_data"].Status != model.AuditWarn || byID["doctor_socket"].Status != model.AuditUnknown || byID["doctor_dpkg"].Status != model.AuditPass || byID["doctor_proc"].Status != model.AuditPass {
		t.Fatalf("%+v", byID)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "PRIVATE_CANARY") {
		t.Fatal("log content leaked")
	}
	info, _ := os.Stat(filepath.Join(host, "var/lib/serversecuritygo"))
	if info.Mode().Perm() != 0777 {
		t.Fatal("permissions modified")
	}
	entries, _ := os.ReadDir(filepath.Join(host, "var/lib/serversecuritygo"))
	if len(entries) != 0 {
		t.Fatal("wrote state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range Run(ctx, cfg).Checks {
		if c.ID == "doctor_proc" && c.Status == model.AuditPass {
			t.Fatal("cancelled check passed")
		}
	}
	os.Remove(filepath.Join(host, "var/lib/dpkg/status"))
	for _, c := range Run(context.Background(), cfg).Checks {
		if c.ID == "doctor_dpkg" && c.Status != model.AuditUnknown {
			t.Fatal("missing dpkg accepted")
		}
	}
	cfg.HostRoot = filepath.Join(host, "missing")
	if r = Run(context.Background(), cfg); len(r.Checks) != 1 || r.Checks[0].Status != model.AuditUnknown {
		t.Fatal(r)
	}
}
func TestDoctorSymlinkDoesNotReadOutsideImage(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.MkdirAll(filepath.Join(root, "var/log"), 0700)
	os.WriteFile(filepath.Join(outside, "secret"), []byte("SECRET"), 0600)
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "var/log/auth.log"))
	cfg := config.Default()
	cfg.HostRoot = root
	cfg.ProcRoot = filepath.Join(root, "proc")
	for _, c := range Run(context.Background(), cfg).Checks {
		if c.ID == "doctor_auth" && c.Status != model.AuditUnknown {
			t.Fatal(c)
		}
	}
}

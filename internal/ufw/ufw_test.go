package ufw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func put(t *testing.T, root, name, data string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	put(t, root, "etc/ufw/ufw.conf", "ENABLED=yes\nLOGLEVEL=low\n")
	put(t, root, "etc/default/ufw", "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=ACCEPT\nDEFAULT_FORWARD_POLICY=REJECT\nIPT_SYSCTL=/etc/custom-sysctl.conf\nIPT_MODULES=''\n")
	for _, name := range []string{"before.rules", "user.rules", "after.rules", "before6.rules", "user6.rules", "after6.rules"} {
		put(t, root, "etc/ufw/"+name, "*filter\n-A FORWARD -i eth0 -o eth1 -s 192.0.2.0/24 -j ACCEPT\nCOMMIT\n")
	}
	put(t, root, "etc/ufw/before.rules", "*nat\n-A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080\nCOMMIT\n")
	put(t, root, "etc/ufw/before.init", "#!/bin/sh\necho not-executed\n")
	put(t, root, "etc/custom-sysctl.conf", "net.ipv4.ip_forward=1\n")
	put(t, root, "etc/ufw/applications.d/nginx", "[Nginx Full]\ntitle=Web server\nports=80,443/tcp\n")
	return root
}
func file(r *model.UFWReport, path string) model.UFWFile {
	for _, f := range r.Files {
		if f.Path == path {
			return f
		}
	}
	return model.UFWFile{}
}
func TestCompleteConfiguration(t *testing.T) {
	root := fixture(t)
	r := Read(root)
	if r.State != "enabled" || len(r.Warnings) != 0 || len(r.Settings) != 10 {
		t.Fatalf("%+v", r)
	}
	for _, p := range []string{"/etc/ufw/before.rules", "/etc/ufw/after6.rules", "/etc/custom-sysctl.conf", "/etc/ufw/applications.d/nginx", "/etc/ufw/before.init"} {
		f := file(r, p)
		if f.Status != "ok" || f.Content == "" {
			t.Fatalf("%+v", f)
		}
	}
	if !strings.Contains(file(r, "/etc/ufw/before.rules").Content, "REDIRECT") {
		t.Fatal("lost NAT rule")
	}
	if !strings.Contains(file(r, "/etc/ufw/after6.rules").Content, "-i eth0 -o eth1") {
		t.Fatal("lost interfaces")
	}
	if file(r, "/etc/ufw/after.init").Status != "missing" {
		t.Fatal("missing optional file hidden")
	}
	put(t, root, "etc/ufw/ufw.conf", "ENABLED=no\n")
	if Read(root).State != "disabled" {
		t.Fatal("disabled configuration")
	}
}
func TestUnavailableIsNotDisabled(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "directory", "oversized", "binary"} {
		t.Run(kind, func(t *testing.T) {
			root := fixture(t)
			p := filepath.Join(root, "etc/ufw/ufw.conf")
			os.Remove(p)
			switch kind {
			case "symlink":
				os.Symlink("../../outside", p)
			case "directory":
				os.Mkdir(p, 0700)
			case "oversized":
				put(t, root, "etc/ufw/ufw.conf", strings.Repeat("x", maxFile+1))
			case "binary":
				put(t, root, "etc/ufw/ufw.conf", "ENABLED=yes\x00")
			}
			r := Read(root)
			if r.State != "unknown" || len(r.Warnings) == 0 {
				t.Fatal(r.State, r.Warnings)
			}
		})
	}
	if r := Read(t.TempDir()); r.State != "absent" || len(r.Warnings) > 0 {
		t.Fatal(r)
	}
	if r := Read(filepath.Join(t.TempDir(), "missing")); r.State != "unknown" || len(r.Warnings) == 0 {
		t.Fatal(r)
	}
}
func TestBudgetAndCustomPath(t *testing.T) {
	root := fixture(t)
	for _, name := range []string{"before.rules", "user.rules", "after.rules", "before6.rules", "user6.rules"} {
		put(t, root, "etc/ufw/"+name, strings.Repeat("x", maxFile))
	}
	r := Read(root)
	n := 0
	for _, f := range r.Files {
		n += len(f.Content)
	}
	if n > maxTotal || len(r.Warnings) == 0 {
		t.Fatalf("bytes=%d warnings=%v", n, r.Warnings)
	}
	root = fixture(t)
	put(t, root, "etc/default/ufw", "IPT_SYSCTL=/etc/../outside\n")
	r = Read(root)
	if file(r, "/etc/../outside").Path != "" || len(r.Warnings) == 0 {
		t.Fatal("unsafe custom path accepted")
	}
}
func TestLiteralSettings(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		ok          bool
	}{
		{"X=yes", "yes", true}, {"X = 'a b' # note", "a b", true}, {"X=\"yes\" # note", "yes", true}, {"X=yes # note", "yes", true},
		{"X=$(touch /tmp/never)", "", false}, {"X=\"$OTHER\"", "", false}, {"X=yes; false", "", false}, {"X='broken", "", false},
		{"X=yes\nX=no", "no", true}, {"X=yes\nX=$OTHER", "", false}, {"# X=yes", "", false},
	} {
		v, ok := setting(tc.input, "X")
		if v != tc.want || ok != tc.ok {
			t.Fatalf("%q => %q,%v", tc.input, v, ok)
		}
	}
	r := Read(fixture(t))
	for _, s := range r.Settings {
		if s.Key == "IPT_MODULES" && s.Value.In(i18n.EN) != "Empty" {
			t.Fatal(s)
		}
	}
}
func FuzzSetting(f *testing.F) {
	for _, s := range []string{"ENABLED=yes", "ENABLED='no' # comment", "ENABLED=$(bad)", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { setting(s, "ENABLED") })
}

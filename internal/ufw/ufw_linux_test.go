//go:build linux

package ufw

import (
	"os"
	"strings"
	"testing"
)

func TestRealUFWConfiguration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to read UFW rule files")
	}
	data, err := os.ReadFile("/etc/ufw/ufw.conf")
	if os.IsNotExist(err) {
		t.Skip("UFW configuration not installed")
	}
	if err != nil {
		t.Fatal(err)
	}
	r := Read("/")
	if f := file(r, "/etc/ufw/ufw.conf"); f.Status != "ok" || f.Content != string(data) {
		t.Fatalf("%+v", f)
	}
	for _, name := range []string{"/etc/default/ufw", "/etc/ufw/user.rules", "/etc/ufw/before.rules", "/etc/ufw/after.rules", "/etc/ufw/sysctl.conf"} {
		data, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		f := file(r, name)
		if f.Content != string(data) || f.Status != "ok" {
			t.Fatalf("%s lost content", name)
		}
	}
	if v, ok := setting(string(data), "ENABLED"); ok && strings.EqualFold(v, "yes") && r.State != "enabled" {
		t.Fatal(r.State)
	}
}

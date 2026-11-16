//go:build linux || darwin

package ufw

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestFIFOConfigDoesNotBlock(t *testing.T) {
	root := fixture(t)
	p := filepath.Join(root, "etc/ufw/after.init")
	if err := syscall.Mkfifo(p, 0600); err != nil {
		t.Fatal(err)
	}
	r := Read(root)
	if file(r, "/etc/ufw/after.init").Status != "unavailable" || len(r.Warnings) == 0 {
		t.Fatal("FIFO not rejected")
	}
}

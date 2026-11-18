package fsinspect

import (
	"context"
	"encoding/binary"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

func TestRealFileCapabilitiesAndSUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for a private capability fixture")
	}
	o, write := fixture(t)
	o.capRead = nil
	write("usr/bin/python3", "fixture, never executed")
	p := filepath.Join(o.HostRoot, "usr/bin/python3")
	f, e := os.OpenFile(p, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	name, _ := syscall.BytePtrFromString("security.capability")
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data, 2<<24|1)
	binary.LittleEndian.PutUint32(data[4:], 1<<7)
	_, _, errno := syscall.Syscall6(syscall.SYS_FSETXATTR, f.Fd(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	c, e := capabilities(f)
	if e != nil || c.Permitted != 128 || !c.Effective {
		t.Fatal(c, e)
	}
	write("usr/bin/sample", "fixture, never executed")
	if e = os.Chmod(filepath.Join(o.HostRoot, "usr/bin/sample"), 0755|os.ModeSetuid); e != nil {
		t.Fatal(e)
	}
	rep := Scan(context.Background(), o)
	if rep.Incomplete || len(rep.Files) != 2 {
		t.Fatalf("%+v", rep)
	}
	found := false
	for _, f := range rep.Findings {
		found = found || f.ID == "fs_capabilities" && f.Risk == model.RiskCritical
	}
	if !found {
		t.Fatal(rep.Findings)
	}
}

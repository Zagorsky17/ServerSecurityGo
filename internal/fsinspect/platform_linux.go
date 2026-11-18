package fsinspect

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

func metadata(fi os.FileInfo) (uint64, uint32, uint32) {
	s := fi.Sys().(*syscall.Stat_t)
	return uint64(s.Dev), s.Uid, s.Gid
}
func capabilities(f *os.File) (Capability, error) {
	name, _ := syscall.BytePtrFromString("security.capability")
	b := make([]byte, 24)
	n, _, err := syscall.Syscall6(syscall.SYS_FGETXATTR, f.Fd(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) {
		return Capability{}, nil
	}
	if err != 0 {
		return Capability{}, err
	}
	return ParseCapability(b[:int(n)])
}

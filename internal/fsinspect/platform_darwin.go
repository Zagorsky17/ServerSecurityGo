package fsinspect

import (
	"os"
	"syscall"
)

func metadata(fi os.FileInfo) (uint64, uint32, uint32) {
	s := fi.Sys().(*syscall.Stat_t)
	return uint64(s.Dev), s.Uid, s.Gid
}
func capabilities(f *os.File) (Capability, error) { return Capability{}, os.ErrNotExist }

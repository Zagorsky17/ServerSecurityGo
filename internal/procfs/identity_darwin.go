package procfs

import (
	"fmt"
	"os"
	"syscall"
)

func FileIdentity(fi os.FileInfo) string {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d:%d:%d", s.Dev, s.Ino, s.Ctimespec.Sec, s.Ctimespec.Nsec)
	}
	return ""
}

package procfs

import (
	"fmt"
	"os"
	"syscall"
)

// FileIdentity включает ctime: восстановление mtime не должно сохранять доверие к кешу.
func FileIdentity(fi os.FileInfo) string {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d:%d:%d", s.Dev, s.Ino, s.Ctim.Sec, s.Ctim.Nsec)
	}
	return ""
}

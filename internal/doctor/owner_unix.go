//go:build unix

package doctor

import (
	"os"
	"syscall"
)

func fileUID(fi os.FileInfo) int {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid)
	}
	return -1
}

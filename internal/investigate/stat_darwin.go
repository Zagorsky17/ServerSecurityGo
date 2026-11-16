package investigate

import (
	"os"
	"syscall"
	"time"
)

func changeTime(fi os.FileInfo) time.Time {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return time.Unix(s.Ctimespec.Sec, s.Ctimespec.Nsec)
	}
	return time.Time{}
}

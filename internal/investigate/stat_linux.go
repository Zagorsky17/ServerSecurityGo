package investigate

import (
	"os"
	"syscall"
	"time"
)

func changeTime(fi os.FileInfo) time.Time {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return time.Unix(s.Ctim.Sec, s.Ctim.Nsec)
	}
	return time.Time{}
}

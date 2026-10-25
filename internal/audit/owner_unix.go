//go:build unix

package audit

import (
	"io/fs"
	"syscall"
)

// owner — UID и GID владельца файла.
func owner(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

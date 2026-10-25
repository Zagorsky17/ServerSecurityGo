//go:build unix

package fail2ban

import (
	"io/fs"
	"syscall"
)

// fileID — устройство и inode файла. По ним журнал узнаётся и после
// ротации: logrotate переименовывает fail2ban.log в fail2ban.log.1, inode
// при этом не меняется, и уже разобранное не читается заново.
type fileID struct {
	dev, ino uint64
	path     string // запасной ключ, если inode недоступен
}

func idOf(path string, fi fs.FileInfo) fileID {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)} //nolint:unconvert // тип Dev различается в linux и darwin
	}
	return fileID{path: path}
}

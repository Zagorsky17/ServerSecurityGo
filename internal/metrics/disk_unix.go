//go:build unix

package metrics

import "syscall"

// Usage — место и inode раздела.
type Usage struct {
	Total      uint64
	Free       uint64 // доступно непривилегированному пользователю
	Inodes     uint64
	InodesFree uint64
}

// diskUsage — statfs раздела. Типы полей Statfs_t различаются на
// Linux и macOS, поэтому значения приводятся к uint64.
func diskUsage(path string) (Usage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Usage{}, err
	}
	bs := uint64(st.Bsize)
	return Usage{Total: bs * uint64(st.Blocks), Free: bs * uint64(st.Bavail),
		Inodes: uint64(st.Files), InodesFree: uint64(st.Ffree)}, nil
}

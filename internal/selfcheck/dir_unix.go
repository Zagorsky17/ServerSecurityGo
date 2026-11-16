//go:build unix

package selfcheck

import (
	"os"
	"syscall"
)

// O_DIRECTORY не даёт FIFO вместо каталога заблокировать наблюдателя.
func openDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

//go:build unix

package detect

import (
	"os"
	"syscall"
)

// openForRead открывает файл только на чтение без блокировки: открытие
// FIFO на чтение иначе ждёт писателя бесконечно и вешает сканирование.
// follow = false — не переходить по симлинку в последнем компоненте
// пути (ядро вернёт ELOOP).
func openForRead(path string, follow bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if !follow {
		flags |= syscall.O_NOFOLLOW
	}
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

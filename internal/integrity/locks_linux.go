//go:build linux

package integrity

import (
	"errors"
	"os"
	"syscall"

	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// F_GETLK лишь запрашивает состояние: приложение не блокирует dpkg и не меняет его файлы.
func packageLocks(root *os.Root) error {
	for _, name := range []string{"var/lib/dpkg/lock", "var/lib/dpkg/lock-frontend"} {
		f, _, err := safefile.OpenRooted(root, name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
		err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lock)
		f.Close()
		if err != nil {
			return err
		}
		if lock.Type != syscall.F_UNLCK {
			return errDatabase
		}
	}
	return nil
}

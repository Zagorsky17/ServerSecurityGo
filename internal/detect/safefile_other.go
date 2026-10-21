//go:build !unix

package detect

import (
	"errors"
	"os"
)

// openForRead — запасной вариант для систем без O_NOFOLLOW/O_NONBLOCK:
// тип файла проверяется до открытия. Сканер рассчитан на Linux, здесь
// нужна только сборка.
func openForRead(path string, follow bool) (*os.File, error) {
	stat := os.Stat
	if !follow {
		stat = os.Lstat
	}
	fi, err := stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("не обычный файл")
	}
	return os.Open(path)
}

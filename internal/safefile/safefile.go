// Пакет safefile безопасно читает файлы, которые может контролировать
// злоумышленник: файлы в домашних каталогах, конфигурации контейнеров,
// файлы автозапуска.
//
// Сканер работает от root, поэтому обычное os.ReadFile опасно: FIFO на
// месте файла повесил бы сканирование навсегда, симлинк на /dev/zero или
// огромный файл исчерпал бы память службы, а симлинк на чужой файл
// заставил бы прочитать то, что читать не собирались.
package safefile

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

var (
	// ErrNotRegular — путь не обычный файл (симлинк при follow = false,
	// FIFO, устройство, каталог).
	ErrNotRegular = errors.New("не обычный файл")
	// ErrTooLarge — файл больше допустимого размера.
	ErrTooLarge = errors.New("файл больше допустимого размера")
)

// ReadRegular читает файл, только если это обычный файл не больше max
// байт. follow = false — симлинк в последнем компоненте пути не
// открывается (для файлов, которыми управляет пользователь). Тип и
// размер берутся из уже открытого дескриптора, поэтому подмена файла
// между проверкой и чтением ничего не даёт. FileInfo возвращается и при
// ErrNotRegular/ErrTooLarge — чтобы вызывающий мог объяснить причину.
func ReadRegular(path string, max int64, follow bool) ([]byte, fs.FileInfo, error) {
	f, err := openForRead(path, follow)
	if err != nil {
		// Открыть не удалось из-за типа (симлинк при follow = false):
		// сообщаем об этом отдельно от «файла нет».
		if fi, lerr := os.Lstat(path); lerr == nil && !fi.Mode().IsRegular() {
			return nil, fi, ErrNotRegular
		}
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fi, ErrNotRegular
	}
	if fi.Size() > max {
		return nil, fi, ErrTooLarge
	}
	// Файл мог вырасти после Stat — читаем не больше max+1 байт.
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fi, err
	}
	if int64(len(data)) > max {
		return nil, fi, ErrTooLarge
	}
	return data, fi, nil
}

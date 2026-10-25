//go:build unix

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadRegular(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, fi, err := ReadRegular(file, 100, false)
	if err != nil || string(data) != "hello" || fi.Size() != 5 {
		t.Fatalf("обычный файл: %q %v", data, err)
	}

	// Файл больше лимита — ошибка без чтения, FileInfo доступен.
	if _, fi, err := ReadRegular(file, 4, false); !errors.Is(err, ErrTooLarge) || fi == nil {
		t.Errorf("большой файл: %v", err)
	}

	// Симлинк: без follow — отказ, с follow — чтение цели.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, fi, err := ReadRegular(link, 100, false); !errors.Is(err, ErrNotRegular) || fi == nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("симлинк без follow: %v", err)
	}
	if data, _, err := ReadRegular(link, 100, true); err != nil || string(data) != "hello" {
		t.Errorf("симлинк с follow: %q %v", data, err)
	}

	// Каталог.
	if _, _, err := ReadRegular(dir, 100, false); !errors.Is(err, ErrNotRegular) {
		t.Errorf("каталог: %v", err)
	}

	// Несуществующий файл — обычная ошибка «нет файла».
	if _, _, err := ReadRegular(filepath.Join(dir, "нет"), 100, false); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("нет файла: %v", err)
	}
}

// TestReadRegularFIFO: FIFO без писателя не вешает чтение.
func TestReadRegularFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo недоступен:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := ReadRegular(fifo, 100, false)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("чтение FIFO зависло")
	}
}

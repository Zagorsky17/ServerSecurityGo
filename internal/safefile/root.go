package safefile

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// OpenRooted ограничивает путь root и сверяет обычный файл до и после открытия.
func OpenRooted(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	// Root.OpenFile сам разрешает симлинки даже с O_NOFOLLOW; одного флага недостаточно.
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, before, ErrNotRegular
	}
	f, err := root.OpenFile(name, readFlags(), 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(before, fi) {
		f.Close()
		return nil, fi, ErrNotRegular
	}
	return f, fi, nil
}

func ReadDir(path string, limit int) ([]os.DirEntry, error) {
	f, err := openDir(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > limit {
		return nil, ErrTooLarge
	}
	return entries, nil
}

// WriteJSON сохраняет состояние в существующем доверенном каталоге, атомарно и с правами 600.
func WriteJSON(path string, v any) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".ssg-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(v)
	if err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	return os.Rename(f.Name(), path)
}

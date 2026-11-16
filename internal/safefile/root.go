package safefile

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
func WriteJSON(path string, v any, maxBytes int64) error {
	if maxBytes <= 0 {
		return os.ErrInvalid
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ssg-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(v)
	if err == nil {
		var fi os.FileInfo
		fi, err = f.Stat()
		if err == nil && fi.Size() > maxBytes {
			err = ErrTooLarge
		}
	}
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

// ResolveRooted разрешает доверенный системный путь; абсолютные цели ссылок
// отсчитываются от проверяемого root. Открывать результат нужно снова через root.
func ResolveRooted(root *os.Root, name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", os.ErrPermission
	}
	pending := strings.Split(name, string(os.PathSeparator))
	var parts []string
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(parts) == 0 {
				return "", os.ErrPermission
			}
			parts = parts[:len(parts)-1]
			continue
		}
		current := filepath.Join(append(slices.Clone(parts), part)...)
		fi, err := root.Lstat(current)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if len(pending) > 0 && !fi.IsDir() {
				return "", os.ErrInvalid
			}
			parts = append(parts, part)
			continue
		}
		links++
		if links > 40 {
			return "", os.ErrInvalid
		}
		target, err := os.Readlink(filepath.Join(root.Name(), current))
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			parts = nil
			target = strings.TrimLeft(target, string(os.PathSeparator))
		}
		pending = append(strings.Split(target, string(os.PathSeparator)), pending...)
	}
	if len(parts) == 0 {
		return ".", nil
	}
	return filepath.Join(parts...), nil
}

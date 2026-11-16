// Package selfcheck проверяет целостность установки и работу самого сканера.
package selfcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

const BaselinePath = "/var/lib/serversecuritygo/self.sha256"
const unitName = "serversecuritygo.service"
const maxFiles = 1024

// Эти каталоги совпадают с write_self_baseline в scripts/lib.sh.
var unitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

func digest(path string, limit int64, follow bool) (string, error) {
	f, fi, err := safefile.Open(path, follow)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if fi.Size() > limit {
		return "", safefile.ErrTooLarge
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", safefile.ErrTooLarge
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func unitHashes(root string) (map[string]string, error) {
	out := make(map[string]string)
	total := 0
	add := func(path string) error {
		if len(out) >= maxFiles {
			return safefile.ErrTooLarge
		}
		full := filepath.Join(root, path)
		// systemd разрешает маскировать drop-in ссылкой на /dev/null.
		if target, _ := os.Readlink(full); target == "/dev/null" {
			h := sha256.Sum256(nil)
			out[path] = hex.EncodeToString(h[:])
			return nil
		}
		data, _, err := safefile.ReadRegular(full, 1<<20, true)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		total += len(data)
		if total > 8<<20 {
			return safefile.ErrTooLarge
		}
		h := sha256.Sum256(data)
		out[path] = hex.EncodeToString(h[:])
		return nil
	}
	for _, base := range unitDirs {
		path := base + "/" + unitName
		if _, err := os.Lstat(filepath.Join(root, path)); err == nil {
			if err := add(path); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, dir := range []string{base + "/service.d", base + "/" + unitName + ".d"} {
			f, err := openDirectory(filepath.Join(root, dir))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			entries, err := f.ReadDir(maxFiles + 1)
			f.Close()
			if err != nil && err != io.EOF {
				return nil, err
			}
			if len(entries) > maxFiles {
				return nil, safefile.ErrTooLarge
			}
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".conf") {
					if err := add(dir + "/" + e.Name()); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return out, nil
}

func parseBaseline(data []byte) (map[string]string, error) {
	out := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if len(line) < 67 || line[64:66] != "  " {
			return nil, errors.New("invalid checksum record")
		}
		sum, path := line[:64], line[66:]
		if _, err := hex.DecodeString(sum); err != nil || strings.ToLower(sum) != sum {
			return nil, errors.New("invalid SHA256")
		}
		if _, ok := out[path]; ok || len(out) > maxFiles {
			return nil, errors.New("duplicate or excessive checksum records")
		}
		valid := path == "binary"
		for _, dir := range unitDirs {
			valid = valid || path == dir+"/"+unitName || (filepath.Dir(path) == dir+"/service.d" || filepath.Dir(path) == dir+"/"+unitName+".d") && strings.HasSuffix(path, ".conf")
		}
		if !valid || filepath.Clean(path) != path {
			return nil, errors.New("invalid checksum path")
		}
		out[path] = sum
	}
	if out["binary"] == "" || out["/etc/systemd/system/"+unitName] == "" {
		return nil, errors.New("incomplete checksum baseline")
	}
	return out, nil
}

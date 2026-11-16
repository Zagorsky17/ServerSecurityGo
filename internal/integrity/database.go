package integrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type expected struct{ Package, MD5 string }
type database struct {
	files           map[string]expected
	owned, excluded map[string]bool
	aliases         map[string]string
	digest          string
}

var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?$`)
var errDatabase = i18n.Errorf("err.integrity_database")

func validPath(p string) bool {
	return p != "" && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != "." && p != ".." && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\x00\r\n\\")
}
func (db *database) canonical(p string) string {
	first, rest, ok := strings.Cut(p, "/")
	if replacement := db.aliases[first]; replacement != "" {
		if ok {
			return replacement + "/" + rest
		}
		return replacement
	}
	return p
}
func selected(p string) bool {
	for _, prefix := range []string{"usr/bin/", "usr/sbin/", "bin/", "sbin/", "lib/systemd/", "usr/lib/systemd/", "usr/lib/openssh/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	if !strings.HasPrefix(p, "lib/") && !strings.HasPrefix(p, "usr/lib/") {
		return false
	}
	if strings.Contains(p, "/security/") {
		return true
	}
	b := path.Base(p)
	return strings.HasPrefix(b, "libc.so") || strings.HasPrefix(b, "libc-") || strings.HasPrefix(b, "libpam") || strings.HasPrefix(b, "libkeyutils") || strings.HasPrefix(b, "libaudit")
}
func critical(p string) bool {
	switch path.Base(p) {
	case "sshd", "ssh", "sudo", "su", "login", "passwd", "ps", "ls", "netstat", "ss", "top", "find", "lsof":
		return true
	}
	return strings.Contains(p, "/security/") || strings.HasPrefix(path.Base(p), "libc.so") || strings.HasPrefix(path.Base(p), "libc-") || strings.HasPrefix(path.Base(p), "libpam")
}

// Отпечаток включает и список владельцев, и версии, и исключения, и контрольные суммы.
func loadDatabase(ctx context.Context, root *os.Root) (*database, error) {
	db := &database{files: map[string]expected{}, owned: map[string]bool{}, excluded: map[string]bool{}, aliases: map[string]string{}}
	for _, dir := range []string{"bin", "sbin", "lib", "lib64"} {
		target, err := os.Readlink(filepath.Join(root.Name(), dir))
		if err == nil && (target == "usr/"+dir || target == "/usr/"+dir) {
			db.aliases[dir] = "usr/" + dir
		}
	}
	h := sha256.New()
	for _, dir := range []string{"bin", "sbin", "lib", "lib64"} {
		fmt.Fprintf(h, "alias:%s=%s\x00", dir, db.aliases[dir])
	}
	budget := int64(64 << 20)
	read := func(name string, optional bool) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, fi, err := safefile.OpenRooted(root, name)
		if optional && errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(h, "%s:missing\x00", name)
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		defer f.Close()
		limit := min(budget, int64(16<<20))
		if fi.Size() > limit {
			return nil, safefile.ErrTooLarge
		}
		data, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, safefile.ErrTooLarge
		}
		after, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if fi.Size() != after.Size() || !fi.ModTime().Equal(after.ModTime()) {
			return nil, errDatabase
		}
		budget -= int64(len(data))
		fmt.Fprintf(h, "%s:%d:", name, len(data))
		h.Write(data)
		return data, nil
	}
	status, err := read("var/lib/dpkg/status", false)
	if err != nil {
		return nil, err
	}
	statusText := strings.ReplaceAll(string(status), "\r\n", "\n")
	inConffiles := false
	for _, line := range strings.Split(statusText, "\n") {
		if line == "Conffiles:" {
			inConffiles = true
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inConffiles = false
			continue
		}
		if !inConffiles {
			continue
		}
		// dpkg допускает маркеры вместо хеша и два суффикса у удаляемых conffiles.
		line = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(line), " remove-on-upgrade"), " obsolete")
		p, sum, ok := strings.Cut(line, " ")
		// Пути с пробелами отделяются по последнему пробелу перед MD5.
		if n := strings.LastIndexByte(line, ' '); n >= 0 {
			p, sum, ok = line[:n], line[n+1:], true
		}
		raw, e := hex.DecodeString(sum)
		validHash := (e == nil && len(raw) == 16) || sum == "newconffile" || sum == "nonexistent" || sum == "-"
		if !ok || !validHash || !strings.HasPrefix(p, "/") || !validPath(p[1:]) {
			return nil, i18n.Errorf("err.integrity_metadata", "status: Conffiles", errDatabase)
		}
		db.excluded[db.canonical(p[1:])] = true
	}
	packages, err := installedPackages(statusText)
	if err != nil {
		return nil, i18n.Errorf("err.integrity_metadata", "var/lib/dpkg/status", err)
	}
	div, err := read("var/lib/dpkg/diversions", true)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(div), "\n"), "\n")
	if len(div) > 0 {
		if len(lines)%3 != 0 {
			return nil, errDatabase
		}
		for i := 0; i < len(lines); i += 3 {
			for _, line := range lines[i : i+2] {
				if !strings.HasPrefix(line, "/") || !validPath(line[1:]) {
					return nil, errDatabase
				}
				p := db.canonical(line[1:])
				db.excluded[p] = true
				db.owned[p] = true
			}
			if lines[i+2] != ":" && !packageName.MatchString(lines[i+2]) {
				return nil, errDatabase
			}
		}
	}
	names := make([]string, 0, len(packages))
	for name := range packages {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		prefix := "var/lib/dpkg/info/" + name
		list, err := read(prefix+".list", true)
		if err != nil {
			return nil, err
		}
		// Multi-Arch пакеты используют имя с архитектурой; некоторые старые базы — без неё.
		if list == nil && strings.Contains(name, ":") {
			prefix = "var/lib/dpkg/info/" + strings.SplitN(name, ":", 2)[0]
			list, err = read(prefix+".list", false)
		}
		if err != nil {
			return nil, err
		}
		if list == nil {
			return nil, errDatabase
		}
		for _, line := range strings.Split(string(list), "\n") {
			if line == "" || line == "/." || line == "/" {
				continue
			}
			p := strings.TrimPrefix(line, "/")
			if !validPath(p) {
				return nil, i18n.Errorf("err.integrity_metadata", prefix+" (.list/.conffiles)", errDatabase)
			}
			p = db.canonical(p)
			if selected(p) {
				db.owned[p] = true
			}
		}
		conf, err := read(prefix+".conffiles", true)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(conf), "\n") {
			if line == "" {
				continue
			}
			p := strings.TrimPrefix(strings.TrimPrefix(line, "remove-on-upgrade "), "/")
			if !validPath(p) {
				return nil, i18n.Errorf("err.integrity_metadata", prefix+" (.list/.conffiles)", errDatabase)
			}
			db.excluded[db.canonical(p)] = true
		}
		sums, err := read(prefix+".md5sums", true)
		if err != nil {
			return nil, err
		}
		if err := db.parseSums(string(sums), name+"="+packages[name]); err != nil {
			return nil, i18n.Errorf("err.integrity_metadata", prefix+".md5sums", err)
		}
		if len(db.owned) > 200_000 || len(db.files) > 200_000 {
			return nil, safefile.ErrTooLarge
		}
	}
	for p := range db.files {
		if !db.owned[p] {
			return nil, i18n.Errorf("err.integrity_metadata", "checksum without ownership: "+p, errDatabase)
		}
		if db.excluded[p] {
			delete(db.files, p)
		}
	}
	db.digest = hex.EncodeToString(h.Sum(nil))
	return db, nil
}

func installedPackages(data string) (map[string]string, error) {
	out := map[string]string{}
	for _, paragraph := range strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				return nil, errDatabase
			}
			if _, exists := fields[k]; exists {
				return nil, errDatabase
			}
			fields[k] = strings.TrimSpace(v)
		}
		if len(fields) == 0 {
			continue
		}
		name, version, arch := fields["Package"], fields["Version"], fields["Architecture"]
		state := strings.Fields(fields["Status"])
		if !packageName.MatchString(name) || strings.Contains(name, ":") || len(state) != 3 {
			return nil, errDatabase
		}
		if state[2] == "not-installed" || state[2] == "config-files" {
			continue
		}
		if state[2] != "installed" || state[1] != "ok" || version == "" || strings.ContainsAny(version, "\x00\r\n") {
			return nil, i18n.Errorf("err.integrity_metadata", name+": Status/Version", errDatabase)
		}
		if !packageName.MatchString(arch) || strings.Contains(arch, ":") {
			return nil, i18n.Errorf("err.integrity_metadata", name+": Architecture", errDatabase)
		}
		key := name + ":" + arch
		if _, ok := out[key]; ok {
			return nil, errDatabase
		}
		out[key] = version
	}
	if len(out) == 0 {
		return nil, errDatabase
	}
	return out, nil
}
func (db *database) parseSums(data, pkg string) error {
	for _, line := range strings.Split(data, "\n") {
		if line == "" {
			continue
		}
		if len(line) < 35 || line[32:34] != "  " {
			return errDatabase
		}
		sum, p := line[:32], strings.TrimPrefix(line[34:], "./")
		raw, err := hex.DecodeString(sum)
		if err != nil || len(raw) != 16 || !validPath(p) {
			return errDatabase
		}
		p = db.canonical(p)
		if !selected(p) || db.excluded[p] {
			continue
		}
		next := expected{pkg, strings.ToLower(sum)}
		if old, ok := db.files[p]; ok && old.MD5 != next.MD5 {
			return errDatabase
		}
		db.files[p] = next
	}
	return nil
}

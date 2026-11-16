package procfs

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

var promptNetwork = regexp.MustCompile(`(^|[\s;|&(/])(curl|wget|nc|ncat|netcat)\b|/dev/tcp/|/dev/udp/`)

func appendEnvSignals(flags []string, head []byte) []string {
	name, value, ok := bytes.Cut(head, []byte{'='})
	if !ok {
		return flags
	}
	flag := ""
	switch string(name) {
	case "PYTHON_JIT":
		if bytes.Equal(value, []byte("1")) {
			flag = "PYTHON_JIT"
		}
	case "HISTFILE":
		if len(value) == 0 || bytes.Equal(value, []byte("/dev/null")) {
			flag = "history_disabled"
		}
	case "HISTSIZE", "HISTFILESIZE":
		if n, err := strconv.ParseInt(string(value), 10, 64); err == nil && n == 0 {
			flag = "history_disabled"
		}
	case "PROMPT_COMMAND":
		if promptNetwork.Match(value) {
			flag = "prompt_command_net"
		}
	case "LD_LIBRARY_PATH":
		for _, dir := range strings.Split(string(value), ":") {
			if UnsafeLibraryPath(dir) {
				flag = "ld_library_path_temp"
				break
			}
		}
	}
	if flag != "" && !slices.Contains(flags, flag) {
		flags = append(flags, flag)
	}
	return flags
}

// UnsafeLibraryPath также учитывает относительный путь и пустой элемент (cwd).
func UnsafeLibraryPath(p string) bool {
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		return true
	}
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm", "/run/shm", "/run/user", "/var/run/user"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	for _, part := range strings.Split(p, "/") {
		if strings.HasPrefix(part, ".") && part != "." {
			return true
		}
	}
	return false
}

// ParseMaps сохраняет только исполняемые отображения, без адресов памяти.
func ParseMaps(data []byte) ([]model.MemoryMap, bool) {
	var out []model.MemoryMap
	seen := map[model.MemoryMap]bool{}
	malformed := false
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		fields := strings.Fields(string(line))
		if len(fields) < 5 {
			malformed = true
			continue
		}
		lo, hi, ok := strings.Cut(fields[0], "-")
		a, e1 := strconv.ParseUint(lo, 16, 64)
		b, e2 := strconv.ParseUint(hi, 16, 64)
		perms := fields[1]
		if !ok || e1 != nil || e2 != nil || a >= b || len(perms) != 4 || !strings.ContainsAny(perms[0:1], "r-") || !strings.ContainsAny(perms[1:2], "w-") || !strings.ContainsAny(perms[2:3], "x-") || !strings.ContainsAny(perms[3:4], "ps") {
			malformed = true
			continue
		}
		if perms[2] != 'x' {
			continue
		}
		rest := string(line)
		for i := 0; i < 5; i++ {
			rest = strings.TrimLeft(rest, " \t")
			n := strings.IndexAny(rest, " \t")
			if n < 0 {
				rest = ""
				break
			}
			rest = rest[n:]
		}
		path := strings.TrimSpace(rest)
		path = strings.ReplaceAll(path, `\012`, "\n")
		path, deleted := splitDeleted(path)
		// vDSO/vsyscall — штатные отображения ядра, не анонимный код.
		if strings.HasPrefix(path, "[") && !strings.HasPrefix(path, "[anon:") && !strings.HasPrefix(path, "[anon_shmem:") {
			continue
		}
		if strings.HasPrefix(path, "[anon") {
			path = ""
		}
		if len(path) > 4096 {
			malformed = true
			continue
		}
		m := model.MemoryMap{Path: path, Perms: perms, Deleted: deleted}
		if !seen[m] {
			if len(out) >= 256 {
				return out, true
			}
			out = append(out, m)
			seen[m] = true
		}
	}
	return out, malformed
}

func (f *FS) readMaps(pid string, p *model.Process, limit int) int {
	if limit <= 0 {
		p.Access = append(p.Access, "maps:budget")
		return 0
	}
	data, truncated, err := readLimited(f.path(pid, "maps"), min(limit, 1<<20))
	if err != nil {
		p.Access = append(p.Access, "maps")
		return 0
	}
	defer clear(data)
	consumed := len(data)
	if truncated {
		if n := bytes.LastIndexByte(data, '\n'); n >= 0 {
			data = data[:n+1]
		} else {
			data = nil
		}
	}
	var malformed bool
	p.Maps, malformed = ParseMaps(data)
	if truncated || malformed {
		p.Access = append(p.Access, "maps:incomplete")
	}
	for i := range p.Maps {
		m := &p.Maps[i]
		if m.Deleted && filepath.IsAbs(m.Path) && !f.SkipExeStat {
			// Корень именно этого процесса; путь контейнера не проверяется на хосте.
			fi, err := os.Stat(f.path(pid, "root", m.Path))
			m.Replacement = err == nil && fi.Mode().IsRegular()
		}
	}
	return consumed
}

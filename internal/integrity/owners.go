package integrity

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// Owners — локальная принадлежность файлам dpkg, не доказательство подлинности.
// nil означает неизвестную/неполную базу; отрицательные выводы запрещены.
func Owners(hostRoot string) (map[string]bool, error) {
	root, err := os.OpenRoot(hostRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	budget := int64(64 << 20)
	read := func(p string) ([]byte, error) {
		b, _, err := safefile.ReadRooted(root, p, min(budget, 16<<20))
		budget -= int64(len(b))
		return b, err
	}
	status, err := read("var/lib/dpkg/status")
	if err != nil {
		return nil, err
	}
	packages, err := installedPackages(string(status))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(packages))
	for name := range packages {
		names = append(names, name)
	}
	slices.Sort(names)
	aliases := map[string]bool{}
	for _, dir := range []string{"bin", "sbin", "lib", "lib64"} {
		target, err := os.Readlink(filepath.Join(hostRoot, dir))
		aliases[dir] = err == nil && (target == "usr/"+dir || target == "/usr/"+dir)
	}
	owned := map[string]bool{}
	for _, name := range names {
		data, err := read("var/lib/dpkg/info/" + name + ".list")
		if errors.Is(err, os.ErrNotExist) {
			data, err = read("var/lib/dpkg/info/" + strings.Split(name, ":")[0] + ".list")
		}
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" || line == "/." || line == "/" {
				continue
			}
			if !strings.HasPrefix(line, "/") || !validPath(line[1:]) {
				return nil, errDatabase
			}
			// Храним только пути, нужные новым проверкам.
			if !strings.Contains(line, ".so") && !strings.Contains(line, "/systemd/") && !strings.Contains(line, "/init.d/") && !strings.Contains(line, "/rc") {
				continue
			}
			owned[line] = true
			for dir, alias := range aliases {
				if !alias {
					continue
				}
				if strings.HasPrefix(line, "/"+dir+"/") {
					owned["/usr"+line] = true
				}
				if strings.HasPrefix(line, "/usr/"+dir+"/") {
					owned[strings.TrimPrefix(line, "/usr")] = true
				}
			}
			if len(owned) > 200_000 {
				return nil, safefile.ErrTooLarge
			}
		}
	}
	return owned, nil
}

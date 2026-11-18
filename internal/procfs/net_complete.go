package procfs

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
	"path/filepath"
	"strings"
)

// NetTablesComplete prevents unreadable or malformed tables from appearing empty.
func NetTablesComplete(root string) bool {
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, _, e := safefile.ReadRegular(filepath.Join(root, "net", name), 32<<20, true)
		if e != nil {
			return false
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) == 0 || !strings.Contains(lines[0], "local_address") {
			return false
		}
		rows := 0
		for _, line := range lines[1:] {
			if strings.TrimSpace(line) != "" {
				rows++
			}
		}
		parsed := ParseNetTable(string(b), name, "")
		if len(parsed) != rows {
			return false
		}
		for _, s := range parsed {
			if s.State == "" {
				return false
			}
		}
	}
	return true
}

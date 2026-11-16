package investigate

import (
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
)

func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func Commands(id string, pid int, path string) []string {
	if pid > 0 {
		p := fmt.Sprintf("/proc/%d", pid)
		switch id {
		case "exe_deleted", "exe_memfd", "bin_modified":
			return []string{"ls -l -- " + p + "/exe", "sha256sum -- " + p + "/exe"}
		case "stdio_socket":
			return []string{"ls -l -- " + p + "/fd", "ss -tpn"}
		case "ld_preload":
			return []string{"cat -- " + p + "/maps"}
		}
		return []string{"cat -- " + p + "/status", "ls -l -- " + p + "/exe", "ps -p " + fmt.Sprint(pid) + " -o pid,ppid,user,lstart,args"}
	}
	if strings.HasPrefix(id, "kmod_") {
		return []string{"cat /proc/modules", "ls -l /sys/module", "dmesg"}
	}
	if path != "" && strings.HasPrefix(path, "/") {
		return []string{"stat -- " + Quote(path), "ls -ld -- " + Quote(path)}
	}
	return []string{"serversecuritygo scan --full --format json"}
}
func Attach(snap *model.Snapshot) {
	for _, p := range snap.Processes {
		for i := range p.Findings {
			f := &p.Findings[i]
			f.VerifyCommands = Commands(f.ID, p.PID, p.Exe)
		}
	}
	for i := range snap.System {
		f := &snap.System[i]
		f.VerifyCommands = Commands(f.ID, 0, f.Path)
	}
}

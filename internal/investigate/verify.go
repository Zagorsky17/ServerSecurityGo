package investigate

import (
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strconv"
	"strings"
)

func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func Commands(id string, pid int, path string) []string {
	if pid == 0 && id == "hidden_process" && strings.HasPrefix(path, "/proc/") {
		part := strings.Split(strings.TrimPrefix(path, "/proc/"), "/")[0]
		if n, e := strconv.Atoi(part); e == nil && n > 0 {
			pid = n
		}
	}
	if pid > 0 {
		p := fmt.Sprintf("/proc/%d", pid)
		switch id {
		case "exe_deleted", "exe_memfd", "bin_modified":
			return []string{"ls -l -- " + p + "/exe", "sha256sum -- " + p + "/exe"}
		case "bpf_unexpected":
			return []string{"cat -- " + p + "/fdinfo/*", "bpftool prog show", "bpftool map show"}
		case "raw_packet_socket":
			return []string{"cat -- " + p + "/net/packet", "ls -l -- " + p + "/fd"}
		case "exe_packed", "exe_static_in_temp":
			return []string{"file -- " + p + "/exe", "readelf -lS -- " + p + "/exe", "sha256sum -- " + p + "/exe"}
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
		q := Quote(path)
		switch id {
		case "bin_modified", "bin_unpackaged":
			return []string{"sha256sum -- " + q, "md5sum -- " + q, "dpkg-query -S -- " + q, "dpkg -V"}
		case "log_utmp_missing":
			return []string{"who -a", "ps -eo pid,ppid,user,args", "stat -- " + q}
		case "log_wtmp_truncated", "log_wtmp_gap":
			return []string{"last -Fai", "ls -li -- " + q + " " + Quote(path+".1")}
		case "log_authlog_truncated":
			return []string{"stat -- " + q, "ls -li -- " + q + " " + Quote(path+".1")}
		case "log_journal_vacuum":
			return []string{"journalctl --disk-usage", "ls -la -- " + q}
		case "ssh_key_command":
			return []string{"cat -A -- " + q}
		}
		if strings.HasPrefix(id, "login_") {
			if strings.HasSuffix(path, ".gz") {
				return []string{"gzip -cd -- " + q, "last -Fai"}
			}
			return []string{"grep -nE -- 'Accepted|Failed' " + q, "last -Fai"}
		}

		return []string{"stat -- " + Quote(path), "ls -ld -- " + Quote(path)}
	}
	return []string{"serversecuritygo scan --full --format json"}
}
func Attach(snap *model.Snapshot, events ...model.Event) {
	idx := indexEvents(events)
	parents := map[int]*model.Process{}
	for _, p := range snap.Processes {
		parents[p.PID] = p
	}
	for _, p := range snap.Processes {
		for i := range p.Findings {
			f := &p.Findings[i]
			f.AllowlistProposal = detect.AllowlistProposal(p, *f)
			f.VerifyCommands = Commands(f.ID, p.PID, p.Exe)
			f.FindingContext = contextFor(f.ID, f.Category, p.Exe)
			if f.ID == "scheduler_suspicious" {
				if par := parents[p.PPID]; par != nil && (par.Name == "cron" || par.Name == "crond") {
					f.Attack = []string{"T1053.003"}
				}
			}
			f.RelatedEvents = idx["key:"+p.Key]
		}
	}
	for i := range snap.System {
		f := &snap.System[i]
		f.VerifyCommands = Commands(f.ID, 0, f.Path)
		f.FindingContext = contextFor(f.ID, f.Category, f.Path)
		if f.Path != "" {
			f.RelatedEvents = idx["path:"+f.Path]
		}
	}
}

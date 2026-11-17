// Package doctor проверяет установку без запуска команд и изменения файлов.
package doctor

import (
	"context"
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/config"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/integrity"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func Run(ctx context.Context, cfg config.Config) *model.AuditReport {
	report := &model.AuditReport{Time: time.Now()}
	if filepath.Clean(cfg.HostRoot) != "/" && filepath.Clean(cfg.ProcRoot) == "/proc" {
		cfg.ProcRoot = filepath.Join(cfg.HostRoot, "proc")
	}
	add := func(id, status string, ev string) {
		report.Checks = append(report.Checks, model.AuditCheck{ID: "doctor_" + id, Group: "doctor", Status: status, Severity: model.RiskLow, Title: i18n.T("cli.doctor." + id), Evidence: []i18n.Msg{i18n.L(ev)}, Recommendation: i18n.T("cli.doctor." + id + "_rec")})
	}
	root, err := os.OpenRoot(cfg.HostRoot)
	if err != nil {
		add("root", model.AuditUnknown, err.Error())
		return report
	}
	defer root.Close()
	for _, p := range []struct {
		id, path string
		socket   bool
	}{{"data", cfg.DataDir, false}, {"socket", cfg.SocketPath, true}} {
		if p.path == "" {
			add(p.id, model.AuditNA, "")
			continue
		}
		n := strings.TrimPrefix(filepath.Clean(p.path), "/")
		fi, e := root.Lstat(n)
		status := model.AuditPass
		ev := p.path
		if e != nil {
			status = model.AuditUnknown
			ev += " : " + e.Error()
		} else {
			valid := fi.IsDir()
			if p.socket {
				valid = fi.Mode()&os.ModeSocket != 0
			}
			if !valid || fi.Mode().Perm()&0077 != 0 || fileUID(fi) != 0 {
				status = model.AuditWarn
			}
			ev += fmt.Sprintf(" mode=%s uid=%d", fi.Mode(), fileUID(fi))
			if p.socket {
				parent, pe := root.Lstat(filepath.Dir(n))
				if pe != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 || fileUID(parent) != 0 {
					status = model.AuditWarn
				}
			}
		}
		add(p.id, status, ev)
	}
	unitStatus, unitEvidence := model.AuditUnknown, "serversecuritygo.service"
	for _, dir := range []string{"etc/systemd/system", "run/systemd/system", "usr/local/lib/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"} {
		p := dir + "/serversecuritygo.service"
		if _, e := root.Lstat(p); os.IsNotExist(e) {
			continue
		}
		resolved, e := safefile.ResolveRooted(root, p)
		if e != nil {
			unitEvidence = e.Error()
			break
		}
		b, fi, e := safefile.ReadRooted(root, resolved, 1<<20)
		if e != nil {
			unitEvidence = e.Error()
			break
		}
		unitStatus = model.AuditPass
		unitEvidence = "/" + p
		if fi.Mode().Perm()&0022 != 0 || fileUID(fi) != 0 || !strings.Contains(string(b), "[Service]") || !strings.Contains(string(b), "ExecStart=") {
			unitStatus = model.AuditWarn
		}
		clear(b)
		break
	}
	add("unit", unitStatus, unitEvidence)
	data, _, e := safefile.ReadRooted(root, "var/log/auth.log", 8<<20)
	clear(data)
	status := model.AuditPass
	if e != nil {
		status = model.AuditUnknown
	}
	add("auth", status, "/var/log/auth.log")
	_, e = integrity.OwnersFor(cfg.HostRoot, map[string]bool{})
	status = model.AuditPass
	ev := "/var/lib/dpkg"
	if e != nil {
		status = model.AuditUnknown
		ev += " : " + e.Error()
	}
	add("dpkg", status, ev)
	procRoot, e := os.OpenRoot(cfg.ProcRoot)
	if e != nil {
		add("proc", model.AuditUnknown, e.Error())
		add("kernel", model.AuditUnknown, "")
		return report
	}
	defer procRoot.Close()
	data, _, e = safefile.ReadRooted(procRoot, "sys/kernel/osrelease", 4096)
	status = model.AuditInfo
	if e != nil || strings.TrimSpace(string(data)) == "" {
		status = model.AuditUnknown
	}
	add("kernel", status, strings.TrimSpace(string(data)))
	entries, e := safefile.ReadDirRooted(procRoot, ".", 100000)
	status = model.AuditPass
	checked, failed := 0, 0
	if e != nil {
		status = model.AuditUnknown
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		if ctx.Err() != nil {
			status = model.AuditUnknown
			break
		}
		if checked >= 32 {
			break
		}
		p := entry.Name()
		st, _, err := safefile.ReadRooted(procRoot, p+"/stat", 8192)
		if os.IsNotExist(err) {
			continue
		}
		parsed, pe := procfs.ParseStat(string(st))
		if pe == nil && parsed.Flags&0x00200000 != 0 {
			continue
		}
		checked++
		if err != nil || pe != nil {
			failed++
			continue
		}
		// Содержимое maps/status не выводим; проверяем возможность ограниченного чтения.
		for _, file := range []string{"status", "maps"} {
			b, _, err := safefile.ReadRooted(procRoot, p+"/"+file, 4<<20)
			clear(b)
			if err != nil {
				failed++
				break
			}
		}
		if _, err := safefile.ReadDirRooted(procRoot, p+"/fd", 65536); err != nil {
			failed++
		}
	}
	if checked == 0 || failed > 0 {
		status = model.AuditUnknown
	}
	add("proc", status, fmt.Sprintf("sample=%d inaccessible=%d (maximum 32)", checked, failed))
	return report
}

package detect

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/redact"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

var persistenceMessages = map[string][2]string{
	"persistence_unavailable": {"rule.persistence_unavailable.title", "rule.persistence_unavailable.rec"},
	"systemd_unit_no_package": {"rule.systemd_unit_no_package.title", "rule.systemd_unit_no_package.rec"},
	"pam_exec":                {"rule.pam_exec.title", "rule.pam_exec.rec"},
	"pam_module_unusual":      {"rule.pam_module_unusual.title", "rule.pam_module_unusual.rec"},
	"library_search_path":     {"rule.library_search_path.title", "rule.library_search_path.rec"},
	"sysv_no_package":         {"rule.sysv_no_package.title", "rule.sysv_no_package.rec"},
	"shell_history_disabled":  {"rule.shell_history_disabled.title", "rule.shell_history_disabled.rec"},
	"hosts_override":          {"rule.hosts_override.title", "rule.hosts_override.rec"},
	"dns_configuration":       {"rule.dns_configuration.title", "rule.dns_configuration.rec"},
}

func persistenceFinding(id, path string, risk model.Risk, facts ...i18n.Msg) model.SystemFinding {
	keys := persistenceMessages[id]
	return sys(model.Finding{ID: id, Title: i18n.T(keys[0]), Category: model.CatPersistence, Evidence: facts, Recommendation: i18n.T(keys[1])}, path, risk, time.Time{})
}

type userHome struct {
	path string
	uid  int
}

func persistenceChecks(hostRoot string, now time.Time, cfg Config, owners map[string]bool, procs []*model.Process) []model.SystemFinding {
	root, err := os.OpenRoot(hostRoot)
	if err != nil {
		return []model.SystemFinding{persistenceFinding("persistence_unavailable", "/", model.RiskInfo)}
	}
	defer root.Close()
	var out []model.SystemFinding
	issues := []i18n.Msg{}
	issue := func(p string) {
		if len(issues) < 12 {
			issues = append(issues, i18n.L("/"+p))
		}
	}
	budget := int64(32 << 20)
	read := func(p string) ([]byte, os.FileInfo, error) {
		b, fi, err := safefile.ReadRooted(root, p, min(budget, maxSystemFile))
		budget -= int64(len(b))
		return b, fi, err
	}
	// Раскрытие шаблонов ограничено на каждом уровне и общим числом кандидатов.
	paths := map[string]bool{}
	visited := 0
	var expand func(string)
	expand = func(pattern string) {
		if visited >= 20000 {
			issue(pattern)
			return
		}
		visited++
		i := strings.IndexAny(pattern, "*?[")
		if i < 0 {
			paths[pattern] = true
			return
		}
		slash := strings.LastIndex(pattern[:i], "/")
		dir, tail := ".", pattern
		if slash >= 0 {
			dir, tail = pattern[:slash], pattern[slash+1:]
		}
		part, rest, _ := strings.Cut(tail, "/")
		entries, err := safefile.ReadDirRooted(root, dir, 4096)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				issue(dir)
			}
			return
		}
		slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		for _, e := range entries {
			match, _ := filepath.Match(part, e.Name())
			if strings.HasSuffix(e.Name(), ".sample") {
				continue
			}
			if !match {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if rest != "" {
				if e.IsDir() {
					expand(p + "/" + rest)
				} else if e.Type()&os.ModeSymlink != 0 {
					issue(p)
				}
			} else if !e.IsDir() {
				expand(p)
			}
		}
	}
	patterns := []string{"etc/crontab", "etc/anacrontab", "etc/rc.local", "etc/bash.bashrc", "etc/profile", "etc/environment", "root/.bashrc", "root/.profile",
		"etc/cron.d/*", "etc/cron.hourly/*", "etc/cron.daily/*", "etc/cron.weekly/*", "etc/cron.monthly/*", "var/spool/cron/*", "var/spool/cron/crontabs/*", "var/spool/cron/atjobs/*", "var/spool/at/*",
		"etc/profile.d/*", "etc/zsh/*", "etc/systemd/system/*", "etc/systemd/system/*.service.d/*.conf", "etc/systemd/system/*.timer.d/*.conf", "etc/systemd/user/*", "etc/systemd/user/*.service.d/*.conf", "usr/lib/systemd/user/*", "usr/lib/systemd/system/*.service", "usr/lib/systemd/system/*.timer", "usr/lib/systemd/system/*.target", "lib/systemd/system/*.service", "lib/systemd/system/*.timer", "lib/systemd/system/*.target",
		"etc/systemd/system-generators/*", "usr/local/lib/systemd/system-generators/*", "etc/pam.d/*", "etc/update-motd.d/*", "etc/ld.so.conf", "etc/ld.so.conf.d/*", "etc/udev/rules.d/*", "etc/X11/Xsession.d/*", "etc/init.d/*", "etc/rc*.d/*",
		"etc/NetworkManager/dispatcher.d/*", "etc/network/if-up.d/*", "etc/apt/apt.conf.d/*", "etc/ssh/sshrc", "opt/*/.git/hooks/*", "var/www/*/.git/hooks/*", "etc/logrotate.d/*", "var/spool/incron/*", "etc/incron.d/*", "etc/hosts", "etc/resolv.conf"}
	var homes []userHome
	if data, _, err := read("etc/passwd"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Split(line, ":")
			if len(f) != 7 {
				continue
			}
			shell := filepath.Base(f[6])
			if shell == "nologin" || shell == "false" || f[6] == "" {
				continue
			}
			home := filepath.Clean(f[5])
			uid, err := strconv.Atoi(f[2])
			if err != nil || uid < 0 || !filepath.IsAbs(home) || home == "/" {
				continue
			}
			home = strings.TrimPrefix(home, "/")
			homes = append(homes, userHome{home, uid})
			for _, name := range []string{".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout", ".zshrc", ".zshenv", ".config/fish/config.fish", ".config/systemd/user/*", ".config/systemd/user/*.service.d/*.conf", ".config/autostart/*.desktop", ".ssh/rc", ".ssh/config"} {
				patterns = append(patterns, home+"/"+name)
			}
			if len(homes) >= 4096 {
				issue("etc/passwd")
				break
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		issue("etc/passwd")
	}
	for _, pattern := range patterns {
		expand(pattern)
	}
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	slices.Sort(names)
	for _, p := range names {
		data, fi, err := read(p)
		if errors.Is(err, safefile.ErrNotRegular) && fi != nil && fi.Mode()&os.ModeSymlink != 0 {
			// Системные ссылки (например rc?.d) читаются только внутри корня хоста.
			if strings.HasPrefix(p, "etc/") || strings.HasPrefix(p, "lib/") || strings.HasPrefix(p, "usr/lib/") {
				target, readErr := os.Readlink(filepath.Join(hostRoot, p))
				if readErr == nil && target == "/dev/null" {
					continue
				}
				f, e := root.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
				if e == nil {
					fi, e = f.Stat()
					if e == nil && fi.Mode().IsRegular() {
						data, e = io.ReadAll(io.LimitReader(f, min(budget, maxSystemFile)+1))
						if int64(len(data)) > min(budget, maxSystemFile) {
							e = safefile.ErrTooLarge
						}
						budget -= int64(len(data))
					} else if e == nil {
						e = safefile.ErrNotRegular
					}
					f.Close()
				}
				err = e
			}
		}
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				issue(p)
			}
			continue
		}
		rel := "/" + p
		out = append(out, persistenceContent(rel, data, fi, now, cfg, owners, root)...)
	}
	for _, home := range homes {
		p := home.path + "/.bash_history"
		fi, err := root.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			issue(p)
			continue
		}
		disabled := false
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(filepath.Join(hostRoot, p))
			disabled = err == nil && target == "/dev/null"
		}
		active := false
		for _, p := range procs {
			if p.UID == home.uid && isShell(p) && !skipUserRules(p) {
				active = true
				break
			}
		}
		if disabled || (fi.Mode().IsRegular() && fi.Size() == 0 && active) {
			out = append(out, persistenceFinding("shell_history_disabled", "/"+p, model.RiskInfo))
		}
	}
	if len(issues) > 0 {
		out = append(out, persistenceFinding("persistence_unavailable", "/", model.RiskInfo, issues...))
	}
	return out
}

func persistenceContent(path string, data []byte, fi os.FileInfo, now time.Time, cfg Config, owners map[string]bool, root *os.Root) []model.SystemFinding {
	var out []model.SystemFinding
	add := func(id string, risk model.Risk, facts ...i18n.Msg) {
		out = append(out, persistenceFinding(id, path, risk, facts...))
	}
	lines := strings.Split(string(data), "\n")
	hits, tempHits := []i18n.Msg{}, []i18n.Msg{}
	for i, line := range lines {
		t := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if t == "" || strings.HasPrefix(t, ";") {
			continue
		}
		// Сохраняем факт и номер строки; содержимое профиля может включать произвольные секреты.
		ref := i18n.T("ev.persistence_line", i+1)
		if persistPattern.MatchString(t) && len(hits) < 5 {
			hits = append(hits, ref)
		} else if tempPattern.MatchString(t) && len(tempHits) < 5 {
			tempHits = append(tempHits, ref)
		}
		if strings.HasPrefix(path, "/etc/pam.d/") {
			fields := strings.Fields(t)
			for j, module := range fields {
				if !strings.HasSuffix(module, ".so") {
					continue
				}
				if filepath.Base(module) == "pam_exec.so" {
					risk := model.RiskMedium
					for _, arg := range fields[j+1:] {
						arg = strings.Trim(arg, "\"' ")
						if filepath.IsAbs(arg) && procfs.UnsafeLibraryPath(arg) {
							risk = model.RiskCritical
						}
					}
					add("pam_exec", risk, ref)
				}
				if filepath.IsAbs(module) {
					clean := filepath.Clean(module)
					standard := (strings.HasPrefix(clean, "/lib/") || strings.HasPrefix(clean, "/usr/lib/") || strings.HasPrefix(clean, "/lib64/") || strings.HasPrefix(clean, "/usr/lib64/")) && strings.Contains(clean, "/security/")
					if !standard || (owners != nil && !owners[clean]) {
						add("pam_module_unusual", model.RiskHigh, ref, i18n.L(clean))
					}
				}
				if !strings.Contains(module, "/") && owners != nil {
					found := false
					for file := range owners {
						if filepath.Base(file) == module && strings.Contains(file, "/security/") {
							found = true
							break
						}
					}
					if !found {
						add("pam_module_unusual", model.RiskHigh, ref, i18n.L(module))
					}
				}
				break
			}
		}
		if path == "/etc/ld.so.conf" || strings.HasPrefix(path, "/etc/ld.so.conf.d/") {
			dir := strings.TrimSpace(t)
			if strings.HasPrefix(dir, "include ") {
				continue
			}
			writable := false
			if filepath.IsAbs(dir) {
				info, err := root.Stat(strings.TrimPrefix(filepath.Clean(dir), "/"))
				writable = err == nil && info.IsDir() && info.Mode().Perm()&0002 != 0
			}
			if procfs.UnsafeLibraryPath(dir) || writable {
				add("library_search_path", model.RiskHigh, ref, i18n.L(redact.String(dir)))
			}
		}
		if path == "/etc/hosts" {
			f := strings.Fields(t)
			for _, domain := range f[1:] {
				domain = strings.TrimSuffix(strings.ToLower(domain), ".")
				for _, repo := range []string{"github.com", "archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org", "security.debian.org"} {
					if domain == repo || strings.HasSuffix(domain, "."+repo) {
						add("hosts_override", model.RiskLow, i18n.L(strings.Join(f, " ")))
						break
					}
				}
			}
		}
		if path == "/etc/resolv.conf" {
			f := strings.Fields(t)
			if len(f) == 2 && f[0] == "nameserver" {
				add("dns_configuration", model.RiskInfo, i18n.L(f[1]))
			}
		}
	}
	if len(hits) > 0 {
		out = append(out, sys(model.Finding{ID: "autostart_suspicious", Title: i18n.T("rule.autostart_suspicious.title"), Category: model.CatPersistence, Weight: 30, Evidence: hits, Recommendation: i18n.T("rule.autostart_suspicious.rec", path)}, path, model.RiskMedium, fi.ModTime()))
	} else if len(tempHits) > 0 {
		out = append(out, sys(model.Finding{ID: "autostart_temp", Title: i18n.T("rule.autostart_temp.title"), Category: model.CatPersistence, Weight: 8, Evidence: tempHits, Recommendation: i18n.T("rule.autostart_temp.rec", path)}, path, model.RiskLow, fi.ModTime()))
	} else if path != "/etc/hosts" && path != "/etc/resolv.conf" && fi.ModTime().After(now.Add(-time.Duration(cfg.RecentDays)*24*time.Hour)) {
		out = append(out, sys(model.Finding{ID: "autostart_recent", Title: i18n.T("rule.autostart_recent.title"), Category: model.CatPersistence, Weight: 3, Evidence: []i18n.Msg{i18n.T("ev.modified", fi.ModTime().Format("2006-01-02 15:04"))}, Recommendation: i18n.T("rule.autostart_recent.rec")}, path, model.RiskInfo, fi.ModTime()))
	}
	if owners != nil && !owners[path] {
		if strings.HasPrefix(path, "/etc/systemd/system/") && (strings.HasSuffix(path, ".service") || strings.HasSuffix(path, ".timer")) {
			f := persistenceFinding("systemd_unit_no_package", path, model.RiskInfo)
			f.Suppressed = cfg.Allowed(&model.Process{Exe: path}, f.ID)
			out = append(out, f)
		}
		if strings.HasPrefix(path, "/etc/init.d/") {
			add("sysv_no_package", model.RiskInfo)
		}
	}
	// Объединение повторяющихся строк одного правила сохраняет стабильный ключ истории.
	result := []model.SystemFinding{}
	seen := map[string]int{}
	for _, f := range out {
		if idx, ok := seen[f.ID]; ok {
			old := &result[idx]
			old.Risk = max(old.Risk, f.Risk)
			if len(old.Evidence) < 8 {
				old.Evidence = append(old.Evidence, f.Evidence...)
			}
		} else {
			seen[f.ID] = len(result)
			result = append(result, f)
		}
	}
	return result
}

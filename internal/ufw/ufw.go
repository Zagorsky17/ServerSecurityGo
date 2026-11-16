// Package ufw читает сохранённые настройки firewall без запуска команд или shell.
package ufw

import (
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

const maxFile = 1 << 20
const maxTotal = 4 << 20

func Read(hostRoot string) *model.UFWReport {
	r := &model.UFWReport{Time: time.Now(), State: "unknown", Settings: []model.UFWSetting{}, Files: []model.UFWFile{}, Warnings: []i18n.Msg{}}
	root, err := os.OpenRoot(hostRoot)
	if err != nil {
		r.Warnings = append(r.Warnings, i18n.T("warn.ufw_read", hostRoot, err))
		return r
	}
	defer root.Close()
	settings := map[string]string{}
	budget := int64(maxTotal)
	seen := map[string]bool{}
	read := func(name string, required bool) model.UFWFile {
		f := model.UFWFile{Path: "/" + name, Status: "ok"}
		data, err := readFile(root, name, &budget)
		if errors.Is(err, os.ErrNotExist) {
			f.Status = "missing"
		} else if err != nil {
			f.Status = "unavailable"
		}
		if err != nil {
			f.Error = i18n.T("warn.ufw_read", f.Path, err)
			if required || f.Status == "unavailable" {
				r.Warnings = append(r.Warnings, f.Error)
			}
		} else {
			f.Content = string(data)
		}
		seen[name] = true
		r.Files = append(r.Files, f)
		return f
	}
	conf := read("etc/ufw/ufw.conf", true)
	defaults := read("etc/default/ufw", true)
	for _, f := range []model.UFWFile{conf, defaults} {
		if f.Status != "ok" {
			continue
		}
		for _, key := range []string{"ENABLED", "LOGLEVEL", "IPV6", "DEFAULT_INPUT_POLICY", "DEFAULT_OUTPUT_POLICY", "DEFAULT_FORWARD_POLICY", "DEFAULT_APPLICATION_POLICY", "MANAGE_BUILTINS", "IPT_SYSCTL", "IPT_MODULES"} {
			value, found := setting(f.Content, key)
			if found {
				settings[key] = value
			}
		}
	}
	for _, field := range []struct{ key, label string }{
		{"ENABLED", "web.ufw.enabled"}, {"DEFAULT_INPUT_POLICY", "web.ufw.input"}, {"DEFAULT_OUTPUT_POLICY", "web.ufw.output"}, {"DEFAULT_FORWARD_POLICY", "web.ufw.forward"}, {"IPV6", "web.ufw.ipv6"}, {"LOGLEVEL", "web.ufw.logging"}, {"DEFAULT_APPLICATION_POLICY", "web.ufw.application"}, {"MANAGE_BUILTINS", "web.ufw.builtins"}, {"IPT_MODULES", "web.ufw.modules"}, {"IPT_SYSCTL", "web.ufw.sysctl"},
	} {
		value := i18n.T("web.ufw.unknown")
		if v, ok := settings[field.key]; ok {
			value = i18n.L(v)
			if v == "" {
				value = i18n.T("web.ufw.empty")
			}
		}
		r.Settings = append(r.Settings, model.UFWSetting{Key: field.key, Label: i18n.T(field.label), Value: value})
	}

	switch strings.ToLower(settings["ENABLED"]) {
	case "yes":
		r.State = "enabled"
	case "no":
		r.State = "disabled"
	}
	if conf.Status == "missing" && defaults.Status == "missing" {
		if _, err := root.Lstat("etc/ufw"); errors.Is(err, os.ErrNotExist) {
			r.State = "absent"
			r.Warnings = nil
			return r
		}
	}
	for _, name := range []string{"before.rules", "user.rules", "after.rules", "before6.rules", "user6.rules", "after6.rules", "sysctl.conf", "before.init", "after.init"} {
		required := strings.HasSuffix(name, ".rules") && (!strings.Contains(name, "6.") || strings.ToLower(settings["IPV6"]) != "no")
		read("etc/ufw/"+name, required)
	}
	if custom := settings["IPT_SYSCTL"]; custom != "" && !seen[strings.TrimPrefix(custom, "/")] {
		// Путь из настройки не интерпретируется shell и не может уйти за корень хоста.
		if !strings.HasPrefix(custom, "/") || path.Clean(custom) != custom || strings.ContainsAny(custom, "$`\\\x00\r\n") {
			r.Warnings = append(r.Warnings, i18n.T("warn.ufw_sysctl_path", custom))
		} else {
			read(custom[1:], true)
		}
	}
	dir, err := root.OpenRoot("etc/ufw/applications.d")
	if err == nil {
		defer dir.Close()
		f, e := dir.Open(".")
		if e == nil {
			entries, re := f.ReadDir(1001)
			f.Close()
			if re != nil && re != io.EOF {
				err = re
			} else if len(entries) > 1000 {
				err = safefile.ErrTooLarge
			} else {
				slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
				for _, entry := range entries {
					read("etc/ufw/applications.d/"+entry.Name(), true)
				}
			}
		} else {
			err = e
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		r.Warnings = append(r.Warnings, i18n.T("warn.ufw_read", "/etc/ufw/applications.d", err))
	}
	return r
}

func readFile(root *os.Root, name string, budget *int64) ([]byte, error) {
	f, before, err := safefile.OpenRooted(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limit := min(int64(maxFile), *budget)
	if before.Size() > limit {
		return nil, safefile.ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	*budget -= int64(len(data))
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
	current, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, current) {
		return nil, i18n.Errorf("err.ufw_changed")
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return nil, i18n.Errorf("err.ufw_text")
	}
	return data, nil
}

// Только буквальные присваивания: динамические shell-выражения остаются в исходном файле.
func setting(data, key string) (string, bool) {
	value, found := "", false
	for _, line := range strings.Split(data, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		found = false
		value = ""
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "'") || strings.HasPrefix(v, "\"") {
			quote := v[:1]
			end := strings.Index(v[1:], quote)
			if end < 0 {
				continue
			}
			end++
			tail := strings.TrimSpace(v[end+1:])
			if tail != "" && !strings.HasPrefix(tail, "#") {
				continue
			}
			v = v[1:end]
			if quote == "\"" && strings.ContainsAny(v, "$`\\") {
				continue
			}
		} else {
			if i := strings.Index(v, " #"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
			if strings.ContainsAny(v, " \t;$`\\\"'") {
				continue
			}
		}
		value, found = v, true
	}
	return value, found
}

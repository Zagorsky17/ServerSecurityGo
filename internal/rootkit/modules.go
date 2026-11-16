package rootkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

var bootIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

var moduleName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

type module struct {
	state, taint string
	info         os.FileInfo
}

func parseModules(data string) (map[string]string, error) {
	out := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 || !moduleName.MatchString(f[0]) {
			return nil, i18n.Errorf("err.rootkit_field", "/proc/modules")
		}
		if _, err := strconv.ParseUint(f[1], 10, 64); err != nil {
			return nil, err
		}
		if _, err := strconv.ParseInt(f[2], 10, 64); err != nil {
			return nil, err
		}
		if f[4] != "Live" && f[4] != "Loading" && f[4] != "Unloading" {
			return nil, i18n.Errorf("err.rootkit_field", "/proc/modules: state")
		}
		if _, ok := out[f[0]]; ok {
			return nil, i18n.Errorf("err.rootkit_field", "/proc/modules: name")
		}
		out[f[0]] = f[4]
	}
	return out, nil
}

func moduleSample(procRoot, hostRoot string) (map[string]string, map[string]module, error) {
	data, _, err := safefile.ReadRegular(filepath.Join(procRoot, "modules"), 4<<20, false)
	if err != nil {
		return nil, nil, err
	}
	listed, err := parseModules(string(data))
	if err != nil {
		return nil, nil, err
	}
	entries, err := safefile.ReadDir(filepath.Join(hostRoot, "sys/module"), 16384)
	if err != nil {
		return nil, nil, err
	}
	sys := make(map[string]module)
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !moduleName.MatchString(name) {
			continue
		}
		dir := filepath.Join(hostRoot, "sys/module", name)
		state, fi, err := safefile.ReadRegular(filepath.Join(dir, "initstate"), 4096, false)
		// Встроенные модули не имеют initstate; исчезновение при выгрузке тоже штатно.
		if errors.Is(err, os.ErrNotExist) {
			for _, marker := range []string{"refcnt", "sections"} {
				if _, markerErr := os.Lstat(filepath.Join(dir, marker)); markerErr == nil {
					return nil, nil, err
				} else if !errors.Is(markerErr, os.ErrNotExist) {
					return nil, nil, markerErr
				}
			}
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		stateText := strings.TrimSpace(string(state))
		if stateText != "live" && stateText != "coming" && stateText != "going" {
			return nil, nil, i18n.Errorf("err.rootkit_field", dir+"/initstate")
		}
		taint, _, err := safefile.ReadRegular(filepath.Join(dir, "taint"), 4096, false)
		if errors.Is(err, os.ErrNotExist) {
			if _, stateErr := os.Lstat(filepath.Join(dir, "initstate")); errors.Is(stateErr, os.ErrNotExist) {
				continue
			}
		}
		if err != nil {
			return nil, nil, err
		}
		sys[name] = module{state: stateText, taint: strings.TrimSpace(string(taint)), info: fi}
	}
	return listed, sys, nil
}

func knownExternal(name string) bool {
	return name == "zfs" || name == "spl" || name == "vboxdrv" || name == "vboxnetflt" || name == "vboxnetadp" || name == "wireguard" || name == "nvidia" || strings.HasPrefix(name, "nvidia_")
}

func moduleChecks(ctx context.Context, procRoot, hostRoot string, baseline map[string]bool, delay time.Duration) ([]model.SystemFinding, map[string]bool, error) {
	first, sys1, err := moduleSample(procRoot, hostRoot)
	if err != nil {
		return nil, nil, err
	}
	if err := pause(ctx, delay); err != nil {
		return nil, nil, err
	}
	second, sys2, err := moduleSample(procRoot, hostRoot)
	if err != nil {
		return nil, nil, err
	}
	var out []model.SystemFinding
	live := make(map[string]bool)
	for name, m := range sys2 {
		old, ok := sys1[name]
		if !ok || old.state != "live" || m.state != "live" || !os.SameFile(old.info, m.info) {
			continue
		}
		path := "/sys/module/" + name
		if first[name] == "" && second[name] == "" {
			out = append(out, finding("kmod_hidden", path, model.RiskCritical, i18n.T("rule.kmod_hidden.title", name), i18n.T("rule.kmod_hidden.rec"), i18n.T("ev.kmod_hidden", path)))
			continue
		}
		if first[name] != "Live" || second[name] != "Live" {
			continue
		}
		live[name] = true
		if baseline != nil && !baseline[name] {
			out = append(out, finding("kmod_new", path, model.RiskMedium, i18n.T("rule.kmod_new.title", name), i18n.T("rule.kmod_new.rec"), i18n.T("ev.kmod_new", name)))
		}
		if strings.ContainsAny(m.taint, "EO") {
			risk := model.RiskMedium
			if knownExternal(name) {
				risk = model.RiskLow
			}
			out = append(out, finding("kmod_unsigned", path, risk, i18n.T("rule.kmod_unsigned.title", name), i18n.T("rule.kmod_unsigned.rec"), i18n.T("ev.kmod_taint", m.taint)))
		}
	}
	// Это сведения для диагностики ядра, а не утверждение о компрометации.
	data, _, err := safefile.ReadRegular(filepath.Join(procRoot, "sys/kernel/tainted"), 4096, false)
	if err != nil {
		return out, nil, err
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return out, nil, err
	}
	if mask != 0 {
		out = append(out, finding("kernel_tainted", "/proc/sys/kernel/tainted", model.RiskInfo, i18n.T("rule.kernel_tainted.title", mask), i18n.T("rule.kernel_tainted.rec"), taintReasons(mask)...))
	}
	if err := indexedModules(hostRoot, procRoot, live, &out); err != nil {
		out = append(out, finding("kmod_origin_unavailable", "/lib/modules", model.RiskInfo, i18n.T("rule.kmod_origin_unavailable.title"), i18n.T("rule.kmod_origin_unavailable.rec"), i18n.T("ev.verification_error", err)))
	}
	slices.SortFunc(out, func(a, b model.SystemFinding) int { return strings.Compare(a.ID+a.Path, b.ID+b.Path) })
	return out, live, nil
}

// modules.dep доказывает лишь наличие установленного файла, но не путь загрузки в ядро.
func indexedModules(hostRoot, procRoot string, live map[string]bool, out *[]model.SystemFinding) error {
	data, _, err := safefile.ReadRegular(filepath.Join(procRoot, "sys/kernel/osrelease"), 4096, false)
	if err != nil {
		return err
	}
	release := strings.TrimSpace(string(data))
	if !filepath.IsLocal(release) || strings.ContainsAny(release, "/\\\x00\r\n") || len(release) > 128 {
		return i18n.Errorf("err.rootkit_field", "/proc/sys/kernel/osrelease")
	}
	data, _, err = safefile.ReadRegular(filepath.Join(hostRoot, "lib/modules", release, "modules.dep"), 16<<20, true)
	if err != nil {
		return err
	}
	names := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		path, _, ok := strings.Cut(line, ":")
		if !ok || !filepath.IsLocal(path) {
			return i18n.Errorf("err.rootkit_field", "modules.dep")
		}
		name := filepath.Base(path)
		for _, suffix := range []string{".zst", ".xz", ".gz"} {
			name = strings.TrimSuffix(name, suffix)
		}
		name = strings.TrimSuffix(name, ".ko")
		names[strings.ReplaceAll(name, "-", "_")] = true
	}
	for name := range live {
		if !names[name] {
			*out = append(*out, finding("kmod_unindexed", "/sys/module/"+name, model.RiskInfo, i18n.T("rule.kmod_unindexed.title", name), i18n.T("rule.kmod_unindexed.rec"), i18n.L("/lib/modules/"+release+"/modules.dep")))
		}
	}
	return nil
}

func taintReasons(mask uint64) []i18n.Msg {
	// Биты документации ядра; неизвестные будущие биты не теряются.
	keys := []string{"ev.taint_p", "ev.taint_f", "ev.taint_s", "ev.taint_r", "ev.taint_m", "ev.taint_b", "ev.taint_u", "ev.taint_d", "ev.taint_a", "ev.taint_w", "ev.taint_c", "ev.taint_i", "ev.taint_o", "ev.taint_e", "ev.taint_l", "ev.taint_k", "ev.taint_x", "ev.taint_t", "ev.taint_n", "ev.taint_j"}
	var out []i18n.Msg
	for bit := 0; bit < 64; bit++ {
		if mask&(uint64(1)<<bit) != 0 {
			if bit < len(keys) {
				out = append(out, i18n.T(keys[bit]))
			} else {
				out = append(out, i18n.T("ev.taint_unknown", fmt.Sprint(bit)))
			}
		}
	}
	return out
}

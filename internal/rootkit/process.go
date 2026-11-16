package rootkit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

var errIdentityChanged = i18n.Errorf("err.rootkit_identity_changed")

type identity struct {
	pid, tgid, ppid int
	start           uint64
}

func processIdentity(path string) (identity, error) {
	var p identity
	status, _, err := safefile.ReadRegular(filepath.Join(path, "status"), 64<<10, false)
	if err != nil {
		return p, err
	}
	values := make(map[string]int)
	for _, line := range strings.Split(string(status), "\n") {
		key, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if key == "Pid" || key == "Tgid" || key == "PPid" {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 0 {
				return p, i18n.Errorf("err.rootkit_field", key)
			}
			if _, ok := values[key]; ok {
				return p, i18n.Errorf("err.rootkit_field", key)
			}
			values[key] = n
		}
	}
	p.pid, p.tgid, p.ppid = values["Pid"], values["Tgid"], values["PPid"]
	_, hasParent := values["PPid"]
	if p.pid <= 0 || p.tgid <= 0 || !hasParent {
		return p, i18n.Errorf("err.rootkit_field", "PID/TGID/PPID")
	}
	data, _, err := safefile.ReadRegular(filepath.Join(path, "stat"), 64<<10, false)
	if err != nil {
		return p, err
	}
	_, err = procfs.ParseStat(string(data))
	if err != nil {
		return p, err
	}
	// ParseStat допускает отсутствующие числовые значения; здесь идентичность должна быть строгой.
	end := strings.LastIndexByte(string(data), ')')
	fields := strings.Fields(string(data[end+1:]))
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return p, err
	}
	statParent, parentErr := strconv.Atoi(fields[1])
	if parentErr != nil || statParent < 0 {
		return p, os.ErrInvalid
	}
	statPID, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(string(data), "(", 2)[0]))
	if err != nil || statPID != p.pid || statParent != p.ppid {
		return p, errIdentityChanged
	}
	p.start = start
	return p, nil
}

func pidList(root string) (map[int]bool, error) {
	entries, err := safefile.ReadDir(root, 100_000)
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool)
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err == nil && n > 0 && strconv.Itoa(n) == e.Name() {
			out[n] = true
		}
	}
	return out, nil
}

// PPID и TGID дают только кандидатов: исчезнувший родитель и обычный TID не являются руткитом.
func candidates(root string, visible map[int]bool) ([]int, error) {
	set := make(map[int]bool)
	for pid := range visible {
		path := filepath.Join(root, strconv.Itoa(pid))
		p, err := processIdentity(path)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errIdentityChanged) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if p.ppid > 0 && !visible[p.ppid] {
			set[p.ppid] = true
		}
		tasks, err := safefile.ReadDir(filepath.Join(path, "task"), 100_000)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errIdentityChanged) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, t := range tasks {
			if _, err := strconv.Atoi(t.Name()); err != nil {
				continue
			}
			p, err := processIdentity(filepath.Join(path, "task", t.Name()))
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, errIdentityChanged) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !visible[p.tgid] {
				set[p.tgid] = true
			}
		}
	}
	out := make([]int, 0, len(set))
	for pid := range set {
		out = append(out, pid)
	}
	slices.Sort(out)
	return out, nil
}

func pause(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func confirmHidden(ctx context.Context, root string, visible map[int]bool, ids []int, delay time.Duration, list func(string) (map[int]bool, error)) ([]model.SystemFinding, error) {
	first := make(map[int]identity)
	for _, pid := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if visible[pid] {
			continue
		}
		p, err := processIdentity(filepath.Join(root, strconv.Itoa(pid)))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errIdentityChanged) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if p.pid == pid && p.tgid == pid {
			first[pid] = p
		}
	}
	if len(first) == 0 {
		return nil, nil
	}
	if err := pause(ctx, delay); err != nil {
		return nil, err
	}
	// Список перечитывается ДО проверки идентичности: исключаем завершение и повторное использование PID.
	second, err := list(root)
	if err != nil {
		return nil, err
	}
	var out []model.SystemFinding
	for pid, old := range first {
		if second[pid] {
			continue
		}
		p, err := processIdentity(filepath.Join(root, strconv.Itoa(pid)))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errIdentityChanged) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if p != old {
			continue
		}
		out = append(out, finding("hidden_process", "/proc/"+strconv.Itoa(pid), model.RiskCritical,
			i18n.T("rule.hidden_process.title", pid), i18n.T("rule.hidden_process.rec"), i18n.T("ev.hidden_process", pid, p.start)))
	}
	slices.SortFunc(out, func(a, b model.SystemFinding) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

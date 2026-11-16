package selfcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type Options struct {
	HostRoot, DataDir, Allowlist, Executable string
	Interval                                 time.Duration
	Progress                                 func() time.Time
	Record                                   func(model.Event) error
	Logger                                   *slog.Logger
	Watchdog                                 bool
}

type allowState struct{ Path, Hash string }

type Monitor struct {
	opt                      Options
	checkMu                  sync.Mutex
	mu                       sync.RWMutex
	findings                 []model.SystemFinding
	active                   map[string]string
	started, previous        time.Time
	previousWall             time.Time
	baseline                 map[string]string
	baselineHash, binaryHash string
	baselineErr, binaryErr   error
	allow                    allowState
	allowKnown               bool
	stateErr                 error
	clockBack, allowChanged  bool
	notify                   watchdog
}

func New(opt Options) *Monitor {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Interval <= 0 {
		opt.Interval = 30 * time.Second
	}
	if opt.Executable == "" {
		opt.Executable, _ = os.Executable()
		// /proc/self/exe указывает на запущенный inode даже после замены пути.
		if runtime.GOOS == "linux" {
			opt.Executable = "/proc/self/exe"
		}
	}
	m := &Monitor{opt: opt, active: make(map[string]string), started: time.Now()}
	path := filepath.Join(opt.HostRoot, BaselinePath)
	data, _, err := safefile.ReadRegular(path, 512<<10, false)
	m.baselineErr = err
	if err == nil {
		m.baseline, m.baselineErr = parseBaseline(data)
	}
	h := sha256.Sum256(data)
	m.baselineHash = hex.EncodeToString(h[:])
	m.binaryHash, m.binaryErr = digest(opt.Executable, 256<<20, true)
	if opt.DataDir != "" {
		data, _, err := safefile.ReadRegular(filepath.Join(opt.DataDir, "self-allowlist.json"), 16<<10, false)
		if err == nil {
			if err = json.Unmarshal(data, &m.allow); err == nil && validAllowState(m.allow) {
				m.allowKnown = true
			} else {
				m.stateErr = errors.New("invalid allowlist baseline")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			m.stateErr = err
		}
	}
	if opt.Watchdog {
		m.notify = watchdogFromEnv()
	}
	m.Check(time.Now())
	return m
}

func (m *Monitor) Findings() []model.SystemFinding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.findings)
}

// Fresh использует монотонную часть time.Time: перевод часов не скрывает зависание.
func Fresh(now, last time.Time, interval time.Duration) bool {
	if last.IsZero() || interval <= 0 {
		return false
	}
	if interval > time.Duration(1<<63-1)/3 {
		return true
	}
	return now.Sub(last) <= 3*interval
}

func (m *Monitor) fresh(now time.Time) bool {
	last := m.started
	if m.opt.Progress != nil {
		if t := m.opt.Progress(); !t.IsZero() {
			last = t
		}
	}
	return Fresh(now, last, m.opt.Interval)
}

// Check не берёт блокировку сканирования и остаётся доступен при его зависании.
func (m *Monitor) Check(now time.Time) {
	m.checkMu.Lock()
	defer m.checkMu.Unlock()
	var findings []model.SystemFinding
	next := make(map[string]string)
	add := func(id, path string, risk model.Risk, title, rec i18n.Msg, token string) {
		key := id + "|" + path
		f := model.SystemFinding{Finding: model.Finding{ID: id, Title: title, Recommendation: rec}, Path: path, Risk: risk}
		findings = append(findings, f)
		next[key] = token
		if old, ok := m.active[key]; !ok || old != token {
			m.event(model.Event{Time: now, Type: model.EvSystem, Name: id, Exe: path, Risk: risk, Details: title})
		}
	}
	unknown := func(path string, err error) {
		add("self_check_unavailable", path, model.RiskMedium, i18n.T("rule.self_check_unavailable.title", path), i18n.T("rule.self_check_unavailable.rec"), path+err.Error())
		findings[len(findings)-1].Evidence = []i18n.Msg{i18n.L(err.Error())}
	}
	basePath := filepath.Join(m.opt.HostRoot, BaselinePath)
	if m.baselineErr != nil {
		unknown(basePath, m.baselineErr)
	} else {
		current, err := digest(basePath, 512<<10, false)
		if err != nil {
			unknown(basePath, err)
		} else if current != m.baselineHash {
			add("self_baseline_changed", basePath, model.RiskHigh, i18n.T("rule.self_baseline_changed.title"), i18n.T("rule.self_baseline_changed.rec"), current)
		}
		if m.binaryErr != nil {
			unknown(m.opt.Executable, m.binaryErr)
		} else if m.binaryHash != m.baseline["binary"] {
			add("self_binary_changed", m.opt.Executable, model.RiskCritical, i18n.T("rule.self_binary_changed.title"), i18n.T("rule.self_binary_changed.rec"), m.binaryHash)
		}
		units, err := unitHashes(m.opt.HostRoot)
		if err != nil {
			unknown("systemd", err)
		} else {
			expected := maps.Clone(m.baseline)
			delete(expected, "binary")
			if !maps.Equal(units, expected) {
				add("self_unit_changed", "/etc/systemd/system/"+unitName, model.RiskHigh, i18n.T("rule.self_unit_changed.title"), i18n.T("rule.self_unit_changed.rec"), "changed")
				var paths []string
				for path, sum := range units {
					if expected[path] != sum {
						paths = append(paths, path)
					}
				}
				for path := range expected {
					if _, ok := units[path]; !ok {
						paths = append(paths, path)
					}
				}
				slices.Sort(paths)
				for _, path := range paths {
					findings[len(findings)-1].Evidence = append(findings[len(findings)-1].Evidence, i18n.T("ev.self_unit_path", path))
				}
			}
		}
	}
	if m.opt.Allowlist != "" {
		sum, err := digest(m.opt.Allowlist, 1<<20, false)
		if errors.Is(err, os.ErrNotExist) {
			sum, err = "missing", nil
		}
		if err != nil {
			unknown(m.opt.Allowlist, err)
		} else if m.stateErr != nil {
			unknown(filepath.Join(m.opt.DataDir, "self-allowlist.json"), m.stateErr)
		} else {
			state := allowState{Path: m.opt.Allowlist, Hash: sum}
			changed := m.allowKnown && state != m.allow
			m.allowChanged = m.allowChanged || changed
			if m.allowChanged {
				add("self_allowlist_changed", m.opt.Allowlist, model.RiskMedium, i18n.T("rule.self_allowlist_changed.title"), i18n.T("rule.self_allowlist_changed.rec"), sum)
			}
			if !m.allowKnown || state != m.allow {
				if err := m.saveAllow(state); err != nil {
					unknown(filepath.Join(m.opt.DataDir, "self-allowlist.json"), err)
				} else {
					m.allow, m.allowKnown = state, true
				}
			}
		}
	}
	if !m.previous.IsZero() {
		// Небольшие поправки NTP не считаем скачком времени.
		wall := now.Round(0).Sub(m.previousWall)
		if now.Sub(m.previous)-wall > time.Second {
			m.clockBack = true
		}
	}
	m.previous = now
	m.previousWall = now.Round(0)
	if m.clockBack {
		add("self_clock_back", "", model.RiskMedium, i18n.T("rule.self_clock_back.title"), i18n.T("rule.self_clock_back.rec"), "back")
	}
	if !m.fresh(now) {
		add("self_scan_stalled", "", model.RiskHigh, i18n.T("rule.self_scan_stalled.title"), i18n.T("rule.self_scan_stalled.rec"), "stalled")
	}
	for key := range m.active {
		if _, ok := next[key]; !ok {
			id, path, _ := strings.Cut(key, "|")
			m.event(model.Event{Time: now, Type: model.EvSystem, Name: id, Exe: path, Risk: model.RiskInfo, Details: i18n.T("hist.self_recovered", id)})
		}
	}
	m.active = next
	m.mu.Lock()
	m.findings = findings
	m.mu.Unlock()
}

func (m *Monitor) event(e model.Event) {
	m.opt.Logger.Warn(i18n.S("log.self_check"), "check", e.Name, "risk", e.Risk.String())
	if m.opt.Record != nil {
		if err := m.opt.Record(e); err != nil {
			m.opt.Logger.Error(i18n.S("log.self_history_failed"), "err", err)
		}
	}
}

func validAllowState(s allowState) bool {
	if s.Path == "" {
		return false
	}
	if s.Hash == "missing" {
		return true
	}
	b, err := hex.DecodeString(s.Hash)
	return err == nil && len(b) == sha256.Size
}

func (m *Monitor) saveAllow(state allowState) error {
	if m.opt.DataDir == "" {
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.opt.DataDir, ".self-allowlist-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), filepath.Join(m.opt.DataDir, "self-allowlist.json"))
}

func (m *Monitor) Run(ctx context.Context) {
	interval := 5 * time.Second
	if m.notify.interval > 0 {
		interval = min(interval, m.notify.interval)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			m.Check(now)
			if m.fresh(time.Now()) {
				if err := m.notify.ping(); err != nil {
					m.opt.Logger.Warn(i18n.S("log.self_notify_failed"), "err", err)
				}
			}
		}
	}
}

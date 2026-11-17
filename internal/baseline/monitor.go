package baseline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

func (s *Store) AcceptPorts(b *model.BaselineSnapshot) error {
	if b == nil {
		return i18n.Errorf("err.baseline_ports")
	}
	p, ok := b.Sections["ports"]
	if !valid(b) || !ok || !p.Complete {
		return i18n.Errorf("err.baseline_ports")
	}
	r, e := s.root(true)
	if e != nil {
		return e
	}
	defer r.Close()
	target := "expected-ports.json"
	if fi, e := r.Lstat(target); e == nil && (!fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0) {
		return i18n.Errorf("err.baseline_private")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	accepted := &model.BaselineSnapshot{Version: 1, Host: b.Host, Time: b.Time, Sections: map[string]model.BaselineSection{"ports": p}}
	return safefile.WriteJSON(filepath.Join(s.Dir, target), accepted, maxBytes)
}

type Monitor struct {
	store       *Store
	capture     func(context.Context) *model.BaselineSnapshot
	mu          sync.RWMutex
	report      *model.ChangesReport
	expected    *model.BaselineSnapshot
	expectedErr error
	host        string
}

func NewMonitor(store *Store, capture func(context.Context) *model.BaselineSnapshot) *Monitor {
	return &Monitor{store: store, capture: capture}
}
func (m *Monitor) Report() *model.ChangesReport { m.mu.RLock(); defer m.mu.RUnlock(); return m.report }
func (m *Monitor) Refresh(ctx context.Context) {
	cur := m.capture(ctx)
	if cur == nil || ctx.Err() != nil {
		return
	}
	out := &model.ChangesReport{}
	warn := func(e error) { out.Warnings = append(out.Warnings, i18n.T("warn.baseline_storage", e.Error())) }
	initial, e := m.store.Load("installation")
	if os.IsNotExist(e) {
		if e = m.store.Save("installation", cur); e == nil {
			initial = cur
		} else {
			warn(e)
		}
	} else if e != nil {
		warn(e)
	}
	out.Installation = Diff(initial, cur)
	names, e := m.store.List()
	if e != nil {
		warn(e)
	}
	var week, latest *model.BaselineSnapshot
	cutoff := cur.Time.Add(-7 * 24 * time.Hour)
	for _, name := range names {
		if !autoRE.MatchString(name) {
			continue
		}
		b, e := m.store.Load(name)
		if e != nil {
			warn(e)
			continue
		}
		if latest == nil || b.Time.After(latest.Time) {
			latest = b
		}
		if !b.Time.After(cutoff) && (week == nil || b.Time.After(week.Time)) {
			week = b
		}
	}
	if initial != nil && !initial.Time.After(cutoff) && (week == nil || initial.Time.After(week.Time)) {
		week = initial
	}
	out.Week = Diff(week, cur)
	if week != nil && cutoff.Sub(week.Time) > time.Hour {
		out.Week.Warnings = append(out.Week.Warnings, i18n.T("warn.baseline_week"))
	}
	if ctx.Err() == nil && (latest == nil || cur.Time.Sub(latest.Time) >= 7*24*time.Hour) {
		if e = m.store.Save("weekly-"+cur.Time.UTC().Format("20060102T150405Z"), cur); e != nil {
			warn(e)
		} else if e = m.store.PruneWeekly(); e != nil {
			warn(e)
		}
	}
	expected, e := m.store.Load("expected-ports")
	if os.IsNotExist(e) && initial != nil && initial.Sections["ports"].Complete {
		e = m.store.AcceptPorts(initial)
		if e == nil {
			expected, e = m.store.Load("expected-ports")
		}
	}
	if e == nil && expected.Host != cur.Host {
		expected = nil
		e = i18n.Errorf("err.baseline_invalid")
	}
	if e != nil {
		warn(e)
	}
	m.mu.Lock()
	m.host = cur.Host
	m.report = out
	m.expected = expected
	m.expectedErr = e
	m.mu.Unlock()
}
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var next time.Time
	for {
		if time.Now().After(next) {
			m.Refresh(ctx)
			if m.Report() != nil {
				next = time.Now().Add(time.Hour)
			}
		} else {
			b, e := m.store.Load("expected-ports")
			m.mu.Lock()
			if e == nil && b.Host != m.host {
				b = nil
				e = i18n.Errorf("err.baseline_invalid")
			}
			m.expected = b
			m.expectedErr = e
			m.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
func (m *Monitor) PortFindings(snap *model.Snapshot) []model.SystemFinding {
	m.mu.RLock()
	b, e := m.expected, m.expectedErr
	m.mu.RUnlock()
	if b == nil || e != nil {
		return []model.SystemFinding{{Risk: model.RiskInfo, Finding: model.Finding{ID: "ports_baseline_unavailable", Category: model.CatInfo, Title: i18n.T("warn.baseline_ports")}}}
	}
	p, ok := b.Sections["ports"]
	if !ok || !p.Complete || snap.Exposure == nil {
		return nil
	}
	var out []model.SystemFinding
	seen := map[string]bool{}
	for _, entry := range snap.Exposure.Entries {
		if entry.Scope != model.ScopePublic || entry.Exe == "" {
			continue
		}
		key := PortKey(entry)
		var binaries []string
		err := json.Unmarshal([]byte(p.Items[key]), &binaries)
		if err == nil && slices.Contains(binaries, entry.Exe) {
			continue
		}
		identity := key + " " + entry.Exe
		if seen[identity] {
			continue
		}
		seen[identity] = true
		out = append(out, model.SystemFinding{Path: identity, Risk: model.RiskHigh, Finding: model.Finding{ID: "new_public_listener", Title: i18n.T("rule.new_public_listener.title"), Category: model.CatNetwork, Evidence: []i18n.Msg{i18n.L(identity)}, Recommendation: i18n.T("rule.new_public_listener.rec")}})
	}
	return out
}

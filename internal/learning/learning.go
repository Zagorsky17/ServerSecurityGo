// Package learning records review candidates without changing detection or allowlists.
package learning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type ruleUse struct{ First, Last time.Time }
type state struct {
	Started    time.Time
	Until      time.Time
	Candidates map[string]model.LearningCandidate
	Rules      map[string]ruleUse
}
type Tracker struct {
	dir                string
	hours              int
	rules              []detect.AllowRule
	state              state
	loadErr            error
	lastSave, lastScan time.Time
}

func New(dir string, hours int, rules []detect.AllowRule) *Tracker {
	if hours == 0 && len(rules) == 0 {
		return nil
	}
	t := &Tracker{dir: dir, hours: hours, rules: rules, state: state{Candidates: map[string]model.LearningCandidate{}, Rules: map[string]ruleUse{}}}
	if dir != "" {
		b, _, e := safefile.ReadRegular(filepath.Join(dir, "learning.json"), 4<<20, false)
		if e == nil {
			var loaded state
			e = json.Unmarshal(b, &loaded)
			t.state = loaded
			if e == nil && (len(t.state.Candidates) > 1000 || len(t.state.Rules) > 1000 || t.state.Candidates == nil || t.state.Rules == nil) {
				e = os.ErrInvalid
			}
			if e == nil {
				for key, c := range t.state.Candidates {
					if key != digest([]string{c.Exe, c.User, c.Rule}) || c.Count < 0 || c.Count > 100000000 || c.First.IsZero() || c.Last.Before(c.First) {
						e = os.ErrInvalid
						break
					}
				}
			}
		}
		if e != nil && !os.IsNotExist(e) {
			t.loadErr = e
		}
	}
	return t
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (t *Tracker) Observe(now time.Time, procs []*model.Process) *model.LearningReport {
	if t == nil {
		return nil
	}
	r := &model.LearningReport{Candidates: []model.LearningCandidate{}}
	r.Warnings = detect.WeakAllowMessages(t.rules)
	if t.loadErr != nil {
		r.Warnings = append(r.Warnings, i18n.T("warn.learning_state", t.loadErr.Error()))
		return r
	}
	if now.Before(t.lastScan) || (!t.state.Started.IsZero() && now.Before(t.state.Started)) {
		r.Warnings = append(r.Warnings, i18n.T("warn.learning_clock"))
		return r
	}
	if t.hours > 0 && t.state.Started.IsZero() {
		t.state.Started = now
		t.state.Until = now.Add(time.Duration(t.hours) * time.Hour)
	}
	r.Until = t.state.Until
	r.Enabled = t.hours > 0 && now.Before(t.state.Until)
	seen := map[string]bool{}
	eligible := map[string]string{}
	for _, p := range procs {
		for _, f := range p.Findings {
			if p.Risk <= model.RiskLow && f.Weight <= 10 && !f.Strong && !f.Suppressed && f.Category != model.CatInfo {
				if proposal := detect.AllowlistProposal(p, f); proposal != "" {
					eligible[digest([]string{p.Exe, p.User, f.ID})] = proposal
				}
			}
		}
	}
	if now.After(t.lastScan) {
		for _, p := range procs {
			for _, f := range p.Findings {
				key := digest([]string{p.Exe, p.User, f.ID})
				if p.Risk >= model.RiskHigh || f.Strong {
					delete(t.state.Candidates, key)
					continue
				}
				if !r.Enabled || p.Risk > model.RiskLow || f.Weight > 10 || f.Suppressed || f.Category == model.CatInfo || seen[key] {
					continue
				}
				proposal := detect.AllowlistProposal(p, f)
				if proposal == "" {
					continue
				}
				seen[key] = true
				c, ok := t.state.Candidates[key]
				if !ok {
					if len(t.state.Candidates) >= 1000 {
						r.Warnings = append(r.Warnings, i18n.T("warn.learning_limit"))
						continue
					}
					c = model.LearningCandidate{Exe: p.Exe, User: p.User, Rule: f.ID, First: now, Proposal: proposal}
				}
				c.Count++
				c.Last = now
				t.state.Candidates[key] = c
			}
		}
		active := map[string]bool{}
		comparisons := 100000
		for i, a := range t.rules {
			if i >= 1000 {
				r.Warnings = append(r.Warnings, i18n.T("warn.learning_limit"))
				break
			}
			key := digest(a)
			active[key] = true
			u := t.state.Rules[key]
			if u.First.IsZero() {
				u.First = now
			}
			cfg := detect.Config{Allow: []detect.AllowRule{a}}
			complete := true
		search:
			for _, p := range procs {
				for _, f := range p.Findings {
					if comparisons <= 0 {
						complete = false
						break search
					}
					comparisons--
					if cfg.Allowed(p, f.ID) {
						u.Last = now
						break search
					}
				}
			}
			// Пропуск наблюдения не должен создавать вывод об устаревании правила.
			if !complete {
				u.First = now
				u.Last = time.Time{}
			}

			t.state.Rules[key] = u
			last := u.Last
			if last.IsZero() {
				last = u.First
			}
			if now.Sub(last) >= 30*24*time.Hour {
				r.Warnings = append(r.Warnings, i18n.T("warn.allow_unused", i+1, last.UTC().Format(time.RFC3339)))
			}
		}
		if comparisons <= 0 {
			r.Warnings = append(r.Warnings, i18n.T("warn.learning_limit"))
		}
		for key := range t.state.Rules {
			if !active[key] {
				delete(t.state.Rules, key)
			}
		}
		t.lastScan = now
	}
	if t.hours > 0 {
		for key, c := range t.state.Candidates {
			c.Proposal = eligible[key]
			if c.Proposal != "" && c.Count >= 3 && c.Last.Sub(c.First) >= 5*time.Minute {
				r.Candidates = append(r.Candidates, c)
			}
		}
	}
	sort.Slice(r.Candidates, func(i, j int) bool {
		x, y := r.Candidates[i], r.Candidates[j]
		if x.Exe != y.Exe {
			return x.Exe < y.Exe
		}
		if x.User != y.User {
			return x.User < y.User
		}
		return x.Rule < y.Rule
	})
	if t.dir != "" && (t.lastSave.IsZero() || now.Sub(t.lastSave) >= time.Minute) {
		if e := safefile.WriteJSON(filepath.Join(t.dir, "learning.json"), t.state, 4<<20); e != nil {
			r.Warnings = append(r.Warnings, i18n.T("warn.learning_state", e.Error()))
		} else {
			t.lastSave = now
		}
	}
	return r
}

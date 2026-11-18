package view

import (
	"sort"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// SystemDetailOnly оставляет неполноту и находки со связанной историей в сводке.
func SystemDetailOnly(f model.SystemFinding) bool {
	return f.Risk == model.RiskInfo && !f.Incomplete() && len(f.RelatedEvents) == 0
}

type SystemOverview struct {
	Attention  int   `json:"attention"`
	Incomplete int   `json:"incomplete"`
	Details    []int `json:"details"`
}

func OverviewSystem(findings []model.SystemFinding) SystemOverview {
	o := SystemOverview{Details: []int{}}
	for i, f := range findings {
		if SystemDetailOnly(f) {
			o.Details = append(o.Details, i)
		} else {
			o.Attention++
		}
		if f.Incomplete() {
			o.Incomplete++
		}
	}
	return o
}

func AuditAttention(c model.AuditCheck) bool {
	return c.Change || (c.Status != model.AuditPass && c.Status != model.AuditInfo && c.Status != model.AuditNA)
}

// LoginGroup ссылается на исходные события; записи разных журналов не дедуплицируются.
type LoginGroup struct {
	Indices []int      `json:"indices"`
	First   time.Time  `json:"first"`
	Last    time.Time  `json:"last"`
	Risk    model.Risk `json:"risk"`
}

func GroupLogins(events []model.LoginEvent) []LoginGroup {
	type key struct {
		ip, source, method string
		bucket             int64
	}
	groups := []LoginGroup{}
	byKey := map[key]int{}
	for i, e := range events {
		k := key{e.IP, e.Source, e.Method, e.Time.UTC().Truncate(15 * time.Minute).Unix()}
		groupable := e.Kind == "failed" && e.IP != "" && e.Source != "" && !e.Time.IsZero()
		pos, found := byKey[k]
		if !groupable || !found {
			pos = len(groups)
			groups = append(groups, LoginGroup{First: e.Time, Last: e.Time, Risk: e.Risk})
			if groupable {
				byKey[k] = pos
			}
		}
		g := &groups[pos]
		g.Indices = append(g.Indices, i)
		if e.Time.Before(g.First) {
			g.First = e.Time
		}
		if e.Time.After(g.Last) {
			g.Last = e.Time
		}
		if e.Risk > g.Risk {
			g.Risk = e.Risk
		}
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Last.After(groups[j].Last) })
	return groups
}

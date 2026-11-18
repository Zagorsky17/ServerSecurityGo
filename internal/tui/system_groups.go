package tui

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func (a *App) buildSystemRows() {
	a.systemRows = a.systemRows[:0]
	a.systemGroups = map[int]view.SystemGroup{}
	skip := make([]bool, len(a.system))
	for _, g := range view.GroupSystem(a.system) {
		a.systemGroups[g.Indices[0]] = g
		if g.Key == a.systemGroup {
			a.systemRows = append(a.systemRows, g.Indices...)
		}
		for _, i := range g.Indices[1:] {
			skip[i] = true
		}
	}
	if len(a.systemRows) > 0 {
		return
	}
	a.systemGroup = ""
	for i := range a.system {
		if !skip[i] {
			a.systemRows = append(a.systemRows, i)
		}
	}
}

func (a *App) selSystemGroup() (view.SystemGroup, bool) {
	c := a.lists[pSys].cursor
	if a.systemGroup == "" && c >= 0 && c < len(a.systemRows) {
		g, ok := a.systemGroups[a.systemRows[c]]
		return g, ok
	}
	return view.SystemGroup{}, false
}

func (a *App) openSystemGroup() bool {
	if a.focus != pSys || a.inMain {
		return false
	}
	g, ok := a.selSystemGroup()
	if !ok {
		return false
	}
	a.systemGroup = g.Key
	a.buildSystemRows()
	a.lists[pSys].cursor, a.lists[pSys].offset, a.mainOffset = 0, 0, 0
	return true
}

func (a *App) backSystemGroup() bool {
	if a.focus != pSys || a.inMain || a.systemGroup == "" {
		return false
	}
	key := a.systemGroup
	a.systemGroup = ""
	a.buildSystemRows()
	for row, i := range a.systemRows {
		if g, ok := a.systemGroups[i]; ok && g.Key == key {
			a.lists[pSys].cursor = row
			break
		}
	}
	a.mainOffset = 0
	a.clamp(pSys)
	return true
}

func (a *App) systemGroupFindings(g view.SystemGroup) []model.SystemFinding {
	out := make([]model.SystemFinding, 0, len(g.Indices))
	for _, i := range g.Indices {
		out = append(out, a.system[i])
	}
	return out
}

func (a *App) systemGroupDetail(b *lb, g view.SystemGroup) {
	f := a.system[g.Indices[0]]
	b.header(a.tr("web.system.group", len(g.Indices)))
	b.para(f.Risk.String(), riskStyle(f.Risk.String()), 0)
	b.kv(a.tr("tui.k.path"), g.Directory)
	b.para(g.Owner, stNormal, 0)
	b.para(a.tr("tui.system.open"), stDim, 0)
	if f.Suppressed {
		b.para(a.tr("tui.suppressed"), stWarn, 0)
	}
	b.header(a.tr("tui.system.examples", min(5, len(g.Indices))))
	for _, i := range g.Indices[:min(5, len(g.Indices))] {
		b.para(a.system[i].Path, stNormal, 2)
	}
	b.header(a.tr("tui.h.recommendation"))
	b.para(a.txt(f.Recommendation), stNormal, 0)
}

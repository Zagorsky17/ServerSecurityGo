// Пакет view строит представления данных сканирования, общие для
// веб-панели (JSON API) и терминального интерфейса: облегчённую сводку
// процесса для списков, подробную карточку и дерево процессов.
//
// Благодаря общему пакету терминальный интерфейс одинаково работает и с
// локальным сканером, и с API запущенной службы: в обоих случаях он
// получает одни и те же структуры.
package view

import (
	"sort"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// Summary — облегчённое представление процесса для таблиц.
type Summary struct {
	Key             string         `json:"key"`
	PID             int            `json:"pid"`
	PPID            int            `json:"ppid"`
	Name            string         `json:"name"`
	User            string         `json:"user"`
	UID             int            `json:"uid"`
	Exe             string         `json:"exe"`
	ExeDeleted      bool           `json:"exeDeleted"`
	Cmdline         string         `json:"cmdline"`
	StartTime       time.Time      `json:"startTime"`
	CPUPercent      float64        `json:"cpuPercent"`
	CPUAverage      bool           `json:"cpuAverage"`
	MemPercent      float64        `json:"memPercent"`
	RSSBytes        uint64         `json:"rssBytes"`
	Threads         int            `json:"threads"`
	Kernel          bool           `json:"kernel"`
	Container       string         `json:"container,omitempty"`
	Risk            model.Risk     `json:"risk"`
	Score           int            `json:"score"`
	Findings        []FindingBrief `json:"findings"`
	Explanation     i18n.Msg       `json:"explanation,omitzero"`
	Recommendations []i18n.Msg     `json:"recommendations,omitempty"`
	FirstSeen       time.Time      `json:"firstSeen"`
	LastSeen        time.Time      `json:"lastSeen"`
	Sockets         int            `json:"sockets"`
	Restricted      bool           `json:"restricted"`
}

// FindingBrief — признак без доказательств (для списков).
type FindingBrief struct {
	ID         string   `json:"id"`
	Title      i18n.Msg `json:"title"`
	Category   string   `json:"category"`
	Weight     int      `json:"weight"`
	Strong     bool     `json:"strong"`
	Suppressed bool     `json:"suppressed,omitempty"`
}

// Summarize строит сводку процесса. Справочные признаки (info) в
// сводку не попадают; объяснение и рекомендации — только для
// процессов с риском от LOW, чтобы не раздувать ответ.
func Summarize(p *model.Process) Summary {
	s := Summary{Key: p.Key, PID: p.PID, PPID: p.PPID, Name: p.Name, User: p.User, UID: p.UID, Exe: p.Exe, ExeDeleted: p.ExeDeleted,
		Cmdline: p.Cmdline, StartTime: p.StartTime, CPUPercent: p.CPUPercent, CPUAverage: p.CPUAverage, MemPercent: p.MemPercent, RSSBytes: p.RSSBytes,
		Threads: p.Threads, Kernel: p.Kernel, Container: p.Container, Risk: p.Risk, Score: p.Score, FirstSeen: p.FirstSeen, LastSeen: p.LastSeen,
		Restricted: len(p.Access) > 0, Findings: []FindingBrief{}}
	if p.ContainerRuntime != "" && s.Container == "" {
		s.Container = p.ContainerRuntime
	}
	for _, sk := range p.Sockets {
		if sk.Proto != "unix" {
			s.Sockets++
		}
	}
	for _, f := range p.Findings {
		if f.Category == model.CatInfo {
			continue
		}
		s.Findings = append(s.Findings, FindingBrief{ID: f.ID, Title: f.Title, Category: f.Category, Weight: f.Weight, Strong: f.Strong, Suppressed: f.Suppressed})
	}
	if p.Risk >= model.RiskLow {
		s.Explanation = p.Explanation
		s.Recommendations = p.Recommendations
	}
	return s
}

// SummarizeAll строит сводки для всех процессов снимка.
func SummarizeAll(snap *model.Snapshot) []Summary {
	out := make([]Summary, 0, len(snap.Processes))
	for _, p := range snap.Processes {
		out = append(out, Summarize(p))
	}
	return out
}

// Link — краткая ссылка на процесс (предок или потомок).
type Link struct {
	Key  string     `json:"key"`
	PID  int        `json:"pid"`
	Name string     `json:"name"`
	User string     `json:"user"`
	Exe  string     `json:"exe"`
	Risk model.Risk `json:"risk"`
}

// Detail — полная карточка процесса. Если процесс уже завершился,
// Process пуст, Exited = true и заполнен Track из истории.
type Detail struct {
	Process   *model.Process `json:"process,omitempty"`
	Ancestors []Link         `json:"ancestors"`
	Children  []Link         `json:"children"`
	Events    []model.Event  `json:"events"`
	Exited    bool           `json:"exited,omitempty"`
	Track     *history.Track `json:"track,omitempty"`
}

// BuildDetail собирает карточку процесса по ключу. ok = false, если
// процесса нет ни в снимке, ни в истории.
func BuildDetail(snap *model.Snapshot, hist *history.Store, key string) (Detail, bool) {
	p := snap.ByKey[key]
	if p == nil {
		if t, ok := hist.Track(key); ok {
			return Detail{Exited: true, Track: &t, Events: hist.EventsFor(key)}, true
		}
		return Detail{}, false
	}
	byPID := make(map[int]*model.Process, len(snap.Processes))
	for _, q := range snap.Processes {
		byPID[q.PID] = q
	}
	link := func(q *model.Process) Link { return Link{q.Key, q.PID, q.Name, q.User, q.Exe, q.Risk} }
	d := Detail{Process: p, Events: hist.EventsFor(key)}
	// Цепочка предков от родителя к корню; seen защищает от циклов при
	// гонке PID между чтениями.
	seen := map[int]bool{p.PID: true}
	for cur := byPID[p.PPID]; cur != nil && !seen[cur.PID]; cur = byPID[cur.PPID] {
		seen[cur.PID] = true
		d.Ancestors = append(d.Ancestors, link(cur))
	}
	for _, c := range p.Children {
		if q := byPID[c]; q != nil {
			d.Children = append(d.Children, link(q))
		}
	}
	return d, true
}

// TreeNode — узел дерева процессов.
type TreeNode struct {
	Key      string      `json:"key"`
	PID      int         `json:"pid"`
	Name     string      `json:"name"`
	User     string      `json:"user"`
	Exe      string      `json:"exe"`
	Cmdline  string      `json:"cmdline"`
	Risk     model.Risk  `json:"risk"`
	Kernel   bool        `json:"kernel"`
	Children []*TreeNode `json:"children"`
}

// BuildTree строит лес процессов: корни — процессы, чей родитель не
// найден в снимке (PID 1, kthreadd, процессы вне видимого PID-пространства).
func BuildTree(snap *model.Snapshot) []*TreeNode {
	nodes := make(map[int]*TreeNode, len(snap.Processes))
	for _, p := range snap.Processes {
		nodes[p.PID] = &TreeNode{Key: p.Key, PID: p.PID, Name: p.Name, User: p.User, Exe: p.Exe, Cmdline: p.Cmdline, Risk: p.Risk, Kernel: p.Kernel, Children: []*TreeNode{}}
	}
	var roots []*TreeNode
	for _, p := range snap.Processes {
		n := nodes[p.PID]
		if par, ok := nodes[p.PPID]; ok && p.PPID != p.PID {
			par.Children = append(par.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].PID < roots[j].PID })
	return roots
}

// Status — сводное состояние для заголовка интерфейса.
type Status struct {
	Version        string         `json:"version"`
	Auth           bool           `json:"auth"`
	CSRF           string         `json:"csrf"`
	Demo           bool           `json:"demo"`
	Interval       float64        `json:"interval"`
	Ready          bool           `json:"ready"`
	Time           time.Time      `json:"time"`
	Seq            uint64         `json:"seq"`
	DurationMs     int64          `json:"durationMs"`
	Host           model.HostInfo `json:"host"`
	Stats          model.Stats    `json:"stats"`
	Warnings       []i18n.Msg     `json:"warnings"`
	SystemFindings int            `json:"systemFindings"`
}

// BuildStatus заполняет данные снимка в Status (snap может быть nil).
func BuildStatus(st Status, snap *model.Snapshot) Status {
	if snap == nil {
		return st
	}
	st.Ready = true
	st.Time = snap.Time
	st.Seq = snap.Seq
	st.DurationMs = snap.Duration.Milliseconds()
	st.Host = snap.Host
	st.Stats = snap.Stats
	st.Warnings = snap.Warnings
	for _, f := range snap.System {
		if f.Risk >= model.RiskLow {
			st.SystemFindings++
		}
	}
	return st
}

// SortedSystem возвращает системные находки по убыванию риска.
func SortedSystem(snap *model.Snapshot) []model.SystemFinding {
	sys := append([]model.SystemFinding(nil), snap.System...)
	sort.SliceStable(sys, func(i, j int) bool { return sys[i].Risk > sys[j].Risk })
	return sys
}

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
	Audit          AuditBrief     `json:"audit"`
	// Fail2ban — есть, только если fail2ban установлен: по этому полю
	// интерфейсы показывают или скрывают раздел.
	Fail2ban *Fail2banBrief `json:"fail2ban,omitempty"`
}

// Fail2banBrief — счётчики fail2ban для заголовка интерфейса.
type Fail2banBrief struct {
	Installed    bool `json:"installed"`
	Running      bool `json:"running"`
	LogAvailable bool `json:"logAvailable"`
	Banned       int  `json:"banned"`
	Found24h     int  `json:"found24h"`
	Bans24h      int  `json:"bans24h"`
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
	if f := snap.Fail2ban; f != nil && f.Installed {
		st.Fail2ban = &Fail2banBrief{Installed: true, Running: f.Running, LogAvailable: f.LogAvailable, Banned: len(f.Bans), Found24h: f.Found24h, Bans24h: f.Bans24h}
	}
	return st
}

// Fail2ban возвращает отчёт fail2ban снимка: при установленном fail2ban
// — с пустыми списками вместо nil, иначе только {installed: false}.
func Fail2ban(snap *model.Snapshot) *model.Fail2banReport {
	if snap == nil || snap.Fail2ban == nil || !snap.Fail2ban.Installed {
		return &model.Fail2banReport{}
	}
	r := *snap.Fail2ban
	for _, s := range []*[]model.Fail2banBucket{&r.Hourly, &r.Daily} {
		if *s == nil {
			*s = []model.Fail2banBucket{}
		}
	}
	for _, s := range []*[]model.Fail2banSource{&r.Top, &r.TopNets} {
		if *s == nil {
			*s = []model.Fail2banSource{}
		}
	}
	if r.Jails == nil {
		r.Jails = []model.Fail2banJail{}
	}
	if r.Bans == nil {
		r.Bans = []model.Fail2banBan{}
	}
	if r.Recent == nil {
		r.Recent = []model.Fail2banEvent{}
	}
	return &r
}

// SortedSystem возвращает системные находки по убыванию риска.
func SortedSystem(snap *model.Snapshot) []model.SystemFinding {
	sys := append([]model.SystemFinding(nil), snap.System...)
	sort.SliceStable(sys, func(i, j int) bool { return sys[i].Risk > sys[j].Risk })
	return sys
}

// Exposure возвращает отчёт о поверхности атаки снимка. Пустой отчёт
// вместо nil — чтобы в JSON были пустые списки, а не null.
func Exposure(snap *model.Snapshot) *model.ExposureReport {
	if snap == nil || snap.Exposure == nil {
		return &model.ExposureReport{Entries: []model.Exposure{}, Addrs: []model.IfaceAddr{}, Bindings: []model.PortBinding{}, Firewall: model.FirewallInfo{UFW: "absent"}}
	}
	r := *snap.Exposure
	if r.Entries == nil {
		r.Entries = []model.Exposure{}
	}
	if r.Addrs == nil {
		r.Addrs = []model.IfaceAddr{}
	}
	if r.Bindings == nil {
		r.Bindings = []model.PortBinding{}
	}
	return &r
}

// AuditCounts — число проверок по статусам.
type AuditCounts struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Warn    int `json:"warn"`
	Info    int `json:"info"`
	NA      int `json:"na"`
	Unknown int `json:"unknown"`
}

func (c *AuditCounts) add(status string) {
	switch status {
	case model.AuditPass:
		c.Pass++
	case model.AuditFail:
		c.Fail++
	case model.AuditWarn:
		c.Warn++
	case model.AuditInfo:
		c.Info++
	case model.AuditNA:
		c.NA++
	default:
		c.Unknown++
	}
}

// AuditView — вкладка «Результаты аудита»: результат последнего
// аудита и сводка «пройдено N из M» (советы, n/a и unknown не считаются).
type AuditView struct {
	Enabled    bool                   `json:"enabled"`
	Running    bool                   `json:"running"`
	Interval   float64                `json:"interval"` // секунды
	Ready      bool                   `json:"ready"`    // есть результат
	Time       time.Time              `json:"time"`
	DurationMs int64                  `json:"durationMs"`
	Passed     int                    `json:"passed"`
	Total      int                    `json:"total"`
	Summary    AuditCounts            `json:"summary"`
	Groups     map[string]AuditCounts `json:"groups"`
	Checks     []model.AuditCheck     `json:"checks"`
}

// AuditBrief — счётчики аудита для заголовка интерфейса.
type AuditBrief struct {
	Enabled bool      `json:"enabled"`
	Running bool      `json:"running"`
	Ready   bool      `json:"ready"`
	Fail    int       `json:"fail"`
	Warn    int       `json:"warn"`
	Time    time.Time `json:"time"`
}

// auditOrder — порядок статусов в списке: сначала то, что нужно исправить.
var auditOrder = map[string]int{model.AuditFail: 0, model.AuditWarn: 1, model.AuditUnknown: 2, model.AuditInfo: 3, model.AuditPass: 4, model.AuditNA: 5}

// BuildAudit собирает представление аудита. rep может быть nil (аудит
// ещё не выполнялся или выключен).
func BuildAudit(enabled, running bool, interval time.Duration, rep *model.AuditReport) AuditView {
	v := AuditView{Enabled: enabled, Running: running, Interval: interval.Seconds(), Groups: map[string]AuditCounts{}, Checks: []model.AuditCheck{}}
	if rep == nil {
		return v
	}
	v.Ready, v.Time, v.DurationMs = true, rep.Time, rep.Duration.Milliseconds()
	v.Checks = append(v.Checks, rep.Checks...)
	sort.SliceStable(v.Checks, func(i, j int) bool {
		a, b := v.Checks[i], v.Checks[j]
		if auditOrder[a.Status] != auditOrder[b.Status] {
			return auditOrder[a.Status] < auditOrder[b.Status]
		}
		return a.Severity > b.Severity
	})
	for _, c := range v.Checks {
		v.Summary.add(c.Status)
		g := v.Groups[c.Group]
		g.add(c.Status)
		v.Groups[c.Group] = g
	}
	v.Passed, v.Total = v.Summary.Pass, v.Summary.Pass+v.Summary.Fail+v.Summary.Warn
	return v
}

// Brief — краткая сводка аудита для Status.
func (v AuditView) Brief() AuditBrief {
	return AuditBrief{Enabled: v.Enabled, Running: v.Running, Ready: v.Ready, Fail: v.Summary.Fail, Warn: v.Summary.Warn, Time: v.Time}
}

// BuildAuditBrief — то же, что BuildAudit(...).Brief(), но без копирования
// и сортировки проверок: /api/status опрашивается каждые несколько секунд.
func BuildAuditBrief(enabled, running bool, rep *model.AuditReport) AuditBrief {
	b := AuditBrief{Enabled: enabled, Running: running}
	if rep == nil {
		return b
	}
	b.Ready, b.Time = true, rep.Time
	for _, c := range rep.Checks {
		switch c.Status {
		case model.AuditFail:
			b.Fail++
		case model.AuditWarn:
			b.Warn++
		}
	}
	return b
}

// AuditStatusText — подпись статуса проверки аудита (для TUI и отчётов).
func AuditStatusText(s string) i18n.Msg {
	switch s {
	case model.AuditPass:
		return i18n.T("audit.status.pass")
	case model.AuditFail:
		return i18n.T("audit.status.fail")
	case model.AuditWarn:
		return i18n.T("audit.status.warn")
	case model.AuditInfo:
		return i18n.T("audit.status.info")
	case model.AuditNA:
		return i18n.T("audit.status.na")
	}
	return i18n.T("audit.status.unknown")
}

// AuditGroupText — подпись группы проверок аудита.
func AuditGroupText(g string) i18n.Msg {
	switch g {
	case model.AuditGroupSSH:
		return i18n.T("audit.group.ssh")
	case model.AuditGroupAccounts:
		return i18n.T("audit.group.accounts")
	case model.AuditGroupSudo:
		return i18n.T("audit.group.sudo")
	}
	return i18n.L(g)
}

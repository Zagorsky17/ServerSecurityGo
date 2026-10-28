// Пакет tui — терминальный интерфейс в стиле lazygit: слева
// пронумерованные панели-списки, справа подробности выбранного
// элемента, внизу подсказки по клавишам.
//
// Написан без внешних библиотек: сырой режим терминала (term.go),
// буфер кадра с ANSI-цветами (screen.go), разбор клавиш и мыши
// (input.go). Данные приходят из службы через Unix-сокет или из
// собственного сканера (source.go).
//
// Безопасность: имена процессов и командные строки контролирует
// потенциальный злоумышленник. Screen.Text отбрасывает управляющие
// символы, поэтому ESC-последовательности из имени процесса не попадут
// в терминал; дополнительно строки проходят через sanitize.
package tui

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/metrics"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

// rangeName — подпись окна графиков метрик.
func (a *App) rangeName(rng string) string {
	switch rng {
	case metrics.RangeDay:
		return a.tr("tui.range.24h")
	case metrics.RangeMonth:
		return a.tr("tui.range.30d")
	}
	return a.tr("tui.range.1h")
}

// nextRange — следующее окно графиков метрик.
func nextRange(cur string) string {
	switch cur {
	case metrics.RangeHour:
		return metrics.RangeDay
	case metrics.RangeDay:
		return metrics.RangeMonth
	}
	return metrics.RangeHour
}

type panelID int

const (
	pStatus panelID = iota
	pSusp
	pProcs
	pNet
	pPorts
	pAudit
	pF2B // только при установленном fail2ban
	pHist
	pSys
	pMetrics // только при включённом сборе метрик
	nPanels
)

// panelKeys — ключи каталога для названий панелей.
var panelKeys = [nPanels]string{"tui.panel.status", "tui.panel.susp", "tui.panel.procs", "tui.panel.net", "tui.panel.ports",
	"tui.panel.audit", "tui.panel.f2b", "tui.panel.hist", "tui.panel.sys", "tui.panel.metrics"}

// sortKeys — режимы сортировки списка процессов (ключи каталога).
var sortKeys = []string{"tui.sort.risk", "tui.sort.cpu", "tui.sort.mem", "tui.sort.pid", "tui.sort.name"}

// listState — положение курсора и фильтр одной панели-списка.
type listState struct {
	cursor, offset int
	filter         string
}

type rect struct{ x, y, w, h int }

func (r rect) has(x, y int) bool { return x >= r.x && x < r.x+r.w && y >= r.y && y < r.y+r.h }

// Options — параметры запуска интерфейса.
type Options struct {
	Source  Source
	Refresh time.Duration // как часто перечитывать данные
	Out     io.Writer     // по умолчанию os.Stdout
	Lang    i18n.Lang     // язык интерфейса; пусто — язык процесса (i18n.Default)
}

// App — состояние интерфейса.
type App struct {
	src     Source
	out     io.Writer
	scr     *Screen
	w, h    int
	refresh time.Duration
	lang    i18n.Lang // язык интерфейса, переключается клавишей L

	data    *Data
	err     error
	fetched time.Time

	focus    panelID // активная панель слева
	inMain   bool    // фокус на панели подробностей
	expanded panelID // какая из панелей-списков развёрнута
	lists    [nPanels]listState

	// Отфильтрованные и отсортированные элементы панелей.
	susp       []view.Summary
	procs      []view.Summary
	procPrefix []string // префиксы дерева («├─ ») в режиме дерева
	socks      []model.Socket
	ports      []model.Exposure
	checks     []model.AuditCheck
	bans       []model.Fail2banBan
	events     []model.Event
	system     []model.SystemFinding
	mrows      []metricRow
	mrange     string // окно графиков метрик (metrics.Range*)
	byKey      map[string]view.Summary

	sortMode   int
	treeMode   bool
	showKernel bool

	detailKey string
	detailSeq uint64
	detail    *view.Detail
	detailErr error

	mainLines  []line
	mainOffset int
	mainH      int

	editing bool
	help    bool
	// menu — открытое меню копирования (c); plain — показан текстовый
	// режим (v), интерфейс не рисуется до нажатия клавиши; mouseOff —
	// мышь выключена (m), работает выделение терминала.
	menu     *copyMenu
	plain    bool
	mouseOff bool
	paused   bool
	zoom     bool
	msg      string
	msgErr   bool
	msgTime  time.Time

	rects   [nPanels + 1]rect // области панелей для мыши; [nPanels] — подробности
	headers [nPanels]int      // сколько строк заголовка у списка
}

// New создаёт интерфейс.
func New(opt Options) *App {
	if opt.Out == nil {
		opt.Out = os.Stdout
	}
	if opt.Refresh <= 0 {
		opt.Refresh = 5 * time.Second
	}
	if _, ok := i18n.Parse(string(opt.Lang)); !ok {
		opt.Lang = i18n.Default()
	}
	return &App{src: opt.Source, out: opt.Out, refresh: opt.Refresh, lang: opt.Lang, focus: pSusp, expanded: pSusp,
		mrange: metrics.RangeHour, byKey: map[string]view.Summary{}}
}

// tr — строка каталога на языке интерфейса.
func (a *App) tr(key string, args ...any) string { return i18n.T(key, args...).In(a.lang) }

// txt — серверное сообщение на языке интерфейса.
func (a *App) txt(m i18n.Msg) string { return m.In(a.lang) }

func (a *App) panelTitle(p panelID) string { return a.tr(panelKeys[p]) }
func (a *App) sortName(i int) string       { return a.tr(sortKeys[i]) }

// toggleLang переключает язык на следующий из i18n.Langs.
func (a *App) toggleLang() {
	for i, l := range i18n.Langs {
		if l == a.lang {
			a.lang = i18n.Langs[(i+1)%len(i18n.Langs)]
			break
		}
	}
	a.rebuild() // фильтры ищут по переведённому тексту
	a.flash(a.tr("tui.lang_switched"), false)
}

// Run запускает интерфейс в текущем терминале и возвращается после выхода.
func (a *App) Run() error {
	fd := int(os.Stdin.Fd())
	st, err := makeRaw(fd)
	if err != nil {
		return err
	}
	// Альтернативный экран, скрытый курсор, мышь (SGR 1006).
	io.WriteString(a.out, "\x1b[?1049h\x1b[?25l"+mouseOnSeq)
	defer func() {
		io.WriteString(a.out, mouseOffSeq+"\x1b[?25h\x1b[?1049l")
		st.restore()
	}()

	a.w, a.h, _ = termSize(fd)
	a.load()

	keys := make(chan []Key, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(keys)
				return
			}
			keys <- parseKeys(append([]byte(nil), buf[:n]...))
		}
	}()
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGWINCH, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	tick := time.NewTicker(a.refresh)
	defer tick.Stop()

	for {
		// В текстовом режиме (v) на экране обычный текст для выделения:
		// кадр не рисуется, пока не нажата клавиша.
		if !a.plain {
			a.draw()
		}
		select {
		case ks, ok := <-keys:
			if !ok {
				return nil
			}
			for _, k := range ks {
				if a.handleKey(k) {
					return nil
				}
			}
		case s := <-sigs:
			if s != syscall.SIGWINCH {
				return nil
			}
			a.w, a.h, _ = termSize(fd)
		case <-tick.C:
			if !a.paused {
				a.load()
			}
		}
	}
}

// load перечитывает данные из источника.
func (a *App) load() {
	d, err := a.src.Fetch()
	a.err = err
	if err == nil {
		a.data = d
		a.fetched = time.Now()
		a.rebuild()
	}
}

func (a *App) flash(msg string, isErr bool) {
	a.msg, a.msgErr, a.msgTime = msg, isErr, time.Now()
}

// ---------------------------------------------------------------------
// Подготовка списков
// ---------------------------------------------------------------------

func matches(filter string, fields ...string) bool {
	if filter == "" {
		return true
	}
	f := strings.ToLower(filter)
	for _, s := range fields {
		if strings.Contains(strings.ToLower(s), f) {
			return true
		}
	}
	return false
}

func procMatches(l i18n.Lang, f string, p view.Summary) bool {
	fields := []string{strconv.Itoa(p.PID), p.Name, p.User, p.Exe, p.Cmdline, p.Risk.String(), p.Container}
	for _, fb := range p.Findings {
		fields = append(fields, fb.Title.In(l), fb.ID)
	}
	return matches(f, fields...)
}

// visible — панели, которые сейчас есть на экране, по порядку. Панель
// fail2ban есть, только если fail2ban установлен; без неё номера
// остальных панелей сдвигаются, и клавиши 1…N всегда идут подряд.
func (a *App) visible() []panelID {
	out := make([]panelID, 0, nPanels)
	for p := pStatus; p < nPanels; p++ {
		if p == pF2B && !a.hasF2B() {
			continue
		}
		if p == pMetrics && !a.hasMetrics() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// hasMetrics — служба собирает метрики (данные о них пришли).
func (a *App) hasMetrics() bool {
	return a.data != nil && a.data.Metrics != nil && a.data.Metrics.Enabled
}

// metricRow — строка панели «Метрики»: ряд, его текущее значение,
// среднее и максимум за окно.
type metricRow struct {
	Key   string  `json:"key"`
	Name  string  `json:"name"`
	Now   float64 `json:"now"`
	Avg   float64 `json:"avg"`
	Max   float64 `json:"max"`
	Count int     `json:"points"`
	// Vals — значения точек окна для графика.
	Vals []float64 `json:"-"`
}

// hasF2B — fail2ban установлен (данные о нём пришли).
func (a *App) hasF2B() bool {
	return a.data != nil && a.data.Fail2ban != nil && a.data.Fail2ban.Installed
}

// panelNum — номер панели на экране (и клавиша для перехода к ней).
func (a *App) panelNum(p panelID) int {
	for i, v := range a.visible() {
		if v == p {
			return i + 1
		}
	}
	return 0
}

// cyclePanel переходит к следующей (d = 1) или предыдущей (d = -1)
// видимой панели.
func (a *App) cyclePanel(d int) {
	vis := a.visible()
	i := max(a.panelNum(a.focus)-1, 0)
	a.focusPanel(vis[(i+d+len(vis))%len(vis)])
}

// rebuild пересобирает списки панелей после загрузки данных или смены
// фильтра/сортировки.
func (a *App) rebuild() {
	if a.data == nil {
		return
	}
	a.byKey = make(map[string]view.Summary, len(a.data.Procs))
	for _, p := range a.data.Procs {
		a.byKey[p.Key] = p
	}

	a.susp = a.susp[:0]
	for _, p := range a.data.Procs {
		if p.Risk >= model.RiskLow && procMatches(a.lang, a.lists[pSusp].filter, p) {
			a.susp = append(a.susp, p)
		}
	}
	sort.SliceStable(a.susp, func(i, j int) bool {
		if a.susp[i].Risk != a.susp[j].Risk {
			return a.susp[i].Risk > a.susp[j].Risk
		}
		return a.susp[i].Score > a.susp[j].Score
	})

	if a.treeMode {
		a.buildTree()
	} else {
		a.procs, a.procPrefix = a.procs[:0], nil
		for _, p := range a.data.Procs {
			if (a.showKernel || !p.Kernel) && procMatches(a.lang, a.lists[pProcs].filter, p) {
				a.procs = append(a.procs, p)
			}
		}
		less := map[int]func(x, y view.Summary) bool{
			0: func(x, y view.Summary) bool {
				if x.Risk != y.Risk {
					return x.Risk > y.Risk
				}
				return x.CPUPercent > y.CPUPercent
			},
			1: func(x, y view.Summary) bool { return x.CPUPercent > y.CPUPercent },
			2: func(x, y view.Summary) bool { return x.RSSBytes > y.RSSBytes },
			3: func(x, y view.Summary) bool { return x.PID < y.PID },
			4: func(x, y view.Summary) bool { return strings.ToLower(x.Name) < strings.ToLower(y.Name) },
		}[a.sortMode]
		sort.SliceStable(a.procs, func(i, j int) bool { return less(a.procs[i], a.procs[j]) })
	}

	a.socks = a.socks[:0]
	for _, s := range a.data.Sockets {
		if matches(a.lists[pNet].filter, s.Proto, s.LocalAddr, strconv.Itoa(s.LocalPort), s.RemoteAddr, strconv.Itoa(s.RemotePort), s.State, s.ProcName, strconv.Itoa(s.PID), s.User) {
			a.socks = append(a.socks, s)
		}
	}
	a.ports = a.ports[:0]
	if x := a.data.Exposure; x != nil {
		for _, e := range x.Entries {
			if a.portMatches(e) {
				a.ports = append(a.ports, e)
			}
		}
	}
	a.checks = a.checks[:0]
	if av := a.data.Audit; av != nil {
		for _, c := range av.Checks {
			if matches(a.lists[pAudit].filter, c.ID, c.Group, c.Status, a.txt(c.Title), c.Severity.String(), i18n.Join(" ", c.Evidence...).In(a.lang)) {
				a.checks = append(a.checks, c)
			}
		}
	}
	a.bans = a.bans[:0]
	if f := a.data.Fail2ban; f != nil {
		for _, b := range f.Bans {
			if matches(a.lists[pF2B].filter, b.IP, b.Jail) {
				a.bans = append(a.bans, b)
			}
		}
	}
	// fail2ban удалили, пока была открыта его панель.
	if !a.hasF2B() {
		if a.focus == pF2B {
			a.focus, a.inMain = pSusp, false
		}
		if a.expanded == pF2B {
			a.expanded = pSusp
		}
	}
	a.events = a.events[:0]
	for _, e := range a.data.Events {
		if matches(a.lists[pHist].filter, e.Type, eventName(a.lang, e.Type), strconv.Itoa(e.PID), e.Name, e.User, a.txt(e.Details), e.Risk.String()) {
			a.events = append(a.events, e)
		}
	}
	a.system = a.system[:0]
	for _, f := range a.data.System {
		if matches(a.lists[pSys].filter, a.txt(f.Title), f.Path, f.ID, f.Risk.String()) {
			a.system = append(a.system, f)
		}
	}
	a.buildMetrics()
	for p := pSusp; p < nPanels; p++ {
		a.clamp(p)
	}
}

// buildTree раскладывает процессы деревом. При фильтре показываются
// совпадения и их предки, чтобы было видно, откуда процесс запущен.
func (a *App) buildTree() {
	procs := a.data.Procs
	byPID := make(map[int]view.Summary, len(procs))
	children := map[int][]int{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	var roots []int
	for _, p := range procs {
		if _, ok := byPID[p.PPID]; ok && p.PPID != p.PID {
			children[p.PPID] = append(children[p.PPID], p.PID)
		} else {
			roots = append(roots, p.PID)
		}
	}
	include := map[int]bool{}
	f := a.lists[pProcs].filter
	for _, p := range procs {
		if (!a.showKernel && p.Kernel) || !procMatches(a.lang, f, p) {
			continue
		}
		for cur, ok := p, true; ok && !include[cur.PID]; cur, ok = byPID[cur.PPID] {
			include[cur.PID] = true
			if cur.PPID == cur.PID {
				break
			}
		}
	}
	sort.Ints(roots)
	a.procs, a.procPrefix = a.procs[:0], a.procPrefix[:0]
	var walk func(pid int, prefix string, last, root bool)
	walk = func(pid int, prefix string, last, root bool) {
		p := byPID[pid]
		if !include[pid] {
			return
		}
		branch, next := "", prefix
		if !root {
			if last {
				branch, next = prefix+"└─ ", prefix+"   "
			} else {
				branch, next = prefix+"├─ ", prefix+"│  "
			}
		}
		a.procs = append(a.procs, p)
		a.procPrefix = append(a.procPrefix, branch)
		var kids []int
		for _, c := range children[pid] {
			if include[c] {
				kids = append(kids, c)
			}
		}
		sort.Ints(kids)
		for i, c := range kids {
			walk(c, next, i == len(kids)-1, false)
		}
	}
	for _, r := range roots {
		walk(r, "", true, true)
	}
}

// metricOrder — порядок рядов на панели: сначала процессор и нагрузка,
// потом память, диски и сеть. Ряды, которых в ответе нет (PSI выключен,
// нет swap), пропускаются.
var metricOrder = []string{metrics.KeyCPU, metrics.KeyCPUUser, metrics.KeyCPUSystem, metrics.KeyCPUIOWait, metrics.KeySteal,
	metrics.KeyLoad1, metrics.KeyPSICPU, metrics.KeyMem, metrics.KeySwap, metrics.KeyPSIMem,
	metrics.KeyDiskRead, metrics.KeyDiskWrite, metrics.KeyDiskBusy, metrics.KeyDiskFull, metrics.KeyPSIIO,
	metrics.KeyNetRx, metrics.KeyNetTx, metrics.KeyPPSIn, metrics.KeyPPSOut}

// metricNames — ключи каталога с названиями рядов. Литералы, а не
// склейка «tui.m.» + имя ряда: keys_test сверяет ключи из кода с
// каталогом и склейку не увидит.
var metricNames = map[string]string{
	metrics.KeyCPU: "tui.m.cpu", metrics.KeyCPUUser: "tui.m.cpu_user", metrics.KeyCPUSystem: "tui.m.cpu_system",
	metrics.KeyCPUIOWait: "tui.m.cpu_iowait", metrics.KeySteal: "tui.m.steal", metrics.KeyLoad1: "tui.m.load1",
	metrics.KeyMem: "tui.m.mem", metrics.KeySwap: "tui.m.swap", metrics.KeySwapUsed: "tui.m.swap_used",
	metrics.KeyDiskRead: "tui.m.disk_read", metrics.KeyDiskWrite: "tui.m.disk_write", metrics.KeyDiskBusy: "tui.m.disk_busy",
	metrics.KeyDiskFull: "tui.m.disk_full", metrics.KeyNetRx: "tui.m.net_rx", metrics.KeyNetTx: "tui.m.net_tx",
	metrics.KeyPPSIn: "tui.m.pps_in", metrics.KeyPPSOut: "tui.m.pps_out",
	metrics.KeyPSICPU: "tui.m.psi_cpu", metrics.KeyPSIMem: "tui.m.psi_mem", metrics.KeyPSIIO: "tui.m.psi_io",
}

// buildMetrics собирает строки панели «Метрики» с учётом фильтра.
func (a *App) buildMetrics() {
	a.mrows = a.mrows[:0]
	mv := a.data.Metrics
	if mv == nil {
		return
	}
	for _, k := range metricOrder {
		pts, ok := mv.Series[k]
		if !ok {
			continue
		}
		name := a.tr(metricNames[k])
		if !matches(a.lists[pMetrics].filter, name, k) {
			continue
		}
		r := metricRow{Key: k, Name: name, Count: len(pts)}
		sum := 0.0
		for i, p := range pts {
			sum += p.Avg
			r.Max = max(r.Max, p.Max)
			r.Vals = append(r.Vals, p.Avg)
			if i == len(pts)-1 {
				r.Now = p.Avg
			}
		}
		if len(pts) > 0 {
			r.Avg = sum / float64(len(pts))
		}
		a.mrows = append(a.mrows, r)
	}
}

func (a *App) count(p panelID) int {
	switch p {
	case pSusp:
		return len(a.susp)
	case pProcs:
		return len(a.procs)
	case pNet:
		return len(a.socks)
	case pPorts:
		return len(a.ports)
	case pAudit:
		return len(a.checks)
	case pF2B:
		return len(a.bans)
	case pHist:
		return len(a.events)
	case pSys:
		return len(a.system)
	case pMetrics:
		return len(a.mrows)
	}
	return 0
}

func (a *App) clamp(p panelID) {
	l := &a.lists[p]
	n := a.count(p)
	if l.cursor >= n {
		l.cursor = n - 1
	}
	if l.cursor < 0 {
		l.cursor = 0
	}
}

// ---------------------------------------------------------------------
// Клавиши
// ---------------------------------------------------------------------

// handleKey обрабатывает нажатие; true — выйти из интерфейса.
func (a *App) handleKey(k Key) bool {
	if k.Kind == KeyCtrlC {
		return true
	}
	if a.plain {
		// Любая клавиша (кроме событий мыши — она выключена) — назад.
		if k.Kind != KeyMouse {
			a.leavePlain()
		}
		return false
	}
	if a.menu != nil {
		if k.Kind != KeyMouse {
			a.menuKey(k)
		}
		return false
	}
	if a.editing {
		a.editKey(k)
		return false
	}
	if a.help {
		if k.Kind == KeyEsc || k.Kind == KeyEnter || (k.Kind == KeyRune && (k.Rune == '?' || k.Rune == 'q')) {
			a.help = false
		}
		return false
	}
	if k.Kind == KeyMouse {
		a.mouse(k)
		return false
	}
	list := a.focus
	if a.inMain {
		list = -1
	}
	switch k.Kind {
	case KeyUp:
		a.move(-1)
	case KeyDown:
		a.move(1)
	case KeyPgUp, KeyCtrlU:
		a.move(-a.page())
	case KeyPgDn, KeyCtrlD:
		a.move(a.page())
	case KeyHome:
		a.move(-1 << 30)
	case KeyEnd:
		a.move(1 << 30)
	case KeyTab:
		a.cyclePanel(1)
	case KeyBackTab:
		a.cyclePanel(-1)
	case KeyRight, KeyEnter:
		if !a.inMain {
			a.inMain, a.mainOffset = true, 0
		}
	case KeyLeft:
		a.inMain = false
	case KeyEsc:
		switch {
		case a.inMain:
			a.inMain = false
		case list >= pSusp && a.lists[list].filter != "":
			a.lists[list].filter = ""
			a.rebuild()
		}
	case KeyRune:
		return a.runeKey(k.Rune, list)
	}
	return false
}

func (a *App) runeKey(r rune, list panelID) bool {
	switch r {
	case 'q':
		return true
	case 'j':
		a.move(1)
	case 'k':
		a.move(-1)
	case 'g':
		a.move(-1 << 30)
	case 'G':
		a.move(1 << 30)
	case 'l':
		a.inMain, a.mainOffset = true, 0
	case 'h':
		a.inMain = false
	case ']':
		a.cyclePanel(1)
	case '[':
		a.cyclePanel(-1)
	case '1', '2', '3', '4', '5', '6', '7', '8', '9':
		if vis := a.visible(); int(r-'1') < len(vis) {
			a.focusPanel(vis[r-'1'])
		}
	case '0':
		// Десятая панель: цифры кончились, 0 — её номер.
		if vis := a.visible(); len(vis) >= 10 {
			a.focusPanel(vis[9])
		}
	case '/':
		if a.focus >= pSusp {
			a.inMain = false
			a.editing = true
		}
	case 's':
		if a.focus == pProcs {
			a.sortMode = (a.sortMode + 1) % len(sortKeys)
			a.treeMode = false
			a.rebuild()
			a.flash(a.tr("tui.flash.sort", a.sortName(a.sortMode)), false)
		}
	case 't':
		a.treeMode = !a.treeMode
		a.focusPanel(pProcs)
		a.rebuild()
		if a.treeMode {
			a.flash(a.tr("tui.flash.tree"), false)
		} else {
			a.flash(a.tr("tui.flash.list"), false)
		}
	case 'K':
		a.showKernel = !a.showKernel
		a.rebuild()
		if a.showKernel {
			a.flash(a.tr("tui.flash.kernel_shown"), false)
		} else {
			a.flash(a.tr("tui.flash.kernel_hidden"), false)
		}
	case 'r':
		if a.focus == pAudit {
			// На панели результатов аудита r — «Проверить сейчас».
			if err := a.src.RunAudit(); err != nil {
				a.flash(a.tr("tui.error", err.Error()), true)
			} else {
				a.flash(a.tr("tui.flash.audit_started"), false)
				time.Sleep(300 * time.Millisecond)
				a.load()
			}
			return false
		}
		if err := a.src.Rescan(); err != nil {
			a.flash(a.tr("tui.error", err.Error()), true)
		} else {
			a.flash(a.tr("tui.flash.scan_started"), false)
			time.Sleep(300 * time.Millisecond)
			a.load()
		}
	case 'p':
		a.paused = !a.paused
		if a.paused {
			a.flash(a.tr("tui.flash.paused"), false)
		} else {
			a.flash(a.tr("tui.flash.resumed"), false)
			a.load()
		}
	case 'w':
		// Окно графиков метрик: час → сутки → 30 дней.
		if a.hasMetrics() {
			a.mrange = nextRange(a.mrange)
			a.src.SetRange(a.mrange)
			a.flash(a.tr("tui.flash.range", a.rangeName(a.mrange)), false)
			a.load()
		}
	case 'L':
		a.toggleLang()
	case '+', 'z':
		a.zoom = !a.zoom
	case 'y':
		a.copyMain()
	case 'c':
		a.openCopyMenu()
	case 'v':
		a.showPlain()
	case 'm':
		a.toggleMouse()
	case 'Y':
		a.copyJSON()
	case '?':
		a.help = true
	}
	return false
}

// editKey — ввод строки фильтра. Фильтр применяется сразу при вводе.
func (a *App) editKey(k Key) {
	l := &a.lists[a.focus]
	switch k.Kind {
	case KeyEnter:
		a.editing = false
	case KeyEsc:
		a.editing = false
		l.filter = ""
	case KeyBackspace:
		if r := []rune(l.filter); len(r) > 0 {
			l.filter = string(r[:len(r)-1])
		}
	case KeyCtrlU:
		l.filter = ""
	case KeyRune:
		if len(l.filter) < 100 {
			l.filter += string(k.Rune)
		}
	default:
		return
	}
	l.cursor, l.offset = 0, 0
	a.rebuild()
}

func (a *App) focusPanel(p panelID) {
	a.focus, a.inMain = p, false
	if p >= pSusp {
		a.expanded = p
	}
}

func (a *App) page() int {
	if a.inMain {
		return max(1, a.mainH-1)
	}
	return max(1, a.rects[a.focus].h-2-a.headers[a.focus]-1)
}

// move сдвигает курсор активного списка или прокручивает подробности.
func (a *App) move(d int) {
	if a.inMain || a.focus == pStatus {
		a.mainOffset += d
		maxOff := max(0, len(a.mainLines)-a.mainH)
		a.mainOffset = min(max(a.mainOffset, 0), maxOff)
		return
	}
	l := &a.lists[a.focus]
	l.cursor += d
	a.clamp(a.focus)
	a.mainOffset = 0
}

func (a *App) mouse(k Key) {
	if !k.Press {
		return
	}
	target := panelID(-1)
	for p := pStatus; p < nPanels; p++ {
		if a.rects[p].has(k.X, k.Y) {
			target = p
		}
	}
	inMain := a.rects[nPanels].has(k.X, k.Y)
	switch k.Button {
	case 64, 65: // колесо
		d := 3
		if k.Button == 64 {
			d = -3
		}
		if inMain {
			a.inMain = true
			a.move(d)
		} else if target >= pStatus {
			if target != a.focus {
				a.focusPanel(target)
			}
			a.move(d)
		}
	case 0: // левая кнопка
		if inMain {
			a.inMain = true
			return
		}
		if target < pStatus {
			return
		}
		a.focusPanel(target)
		if target >= pSusp {
			r := a.rects[target]
			row := k.Y - r.y - 1 - a.headers[target]
			if row >= 0 {
				l := &a.lists[target]
				l.cursor = l.offset + row
				a.clamp(target)
				a.mainOffset = 0
			}
		}
	}
}

func (a *App) copyJSON() {
	var v any
	switch a.focus {
	case pNet:
		if s, ok := a.selSocket(); ok {
			v = s
		}
	case pPorts:
		if e, ok := a.selPort(); ok {
			v = e
		}
	case pAudit:
		if c, ok := a.selCheck(); ok {
			v = c
		}
	case pF2B:
		if b, ok := a.selBan(); ok {
			v = b
		} else if a.data.Fail2ban != nil {
			v = a.data.Fail2ban
		}
	case pHist:
		if e, ok := a.selEvent(); ok {
			v = e
		}
	case pSys:
		if f, ok := a.selSystem(); ok {
			v = f
		}
	case pMetrics:
		if m, ok := a.selMetric(); ok {
			v = m
		} else if a.data.Metrics != nil {
			v = a.data.Metrics.Now
		}
	default:
		if a.detail != nil {
			v = a.detail
		}
	}
	if v == nil {
		a.flash(a.tr("tui.flash.nothing"), true)
		return
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	a.osc52(string(b))
	a.flash(a.tr("tui.flash.json_copied"), false)
}

func (a *App) osc52(s string) {
	fmt.Fprintf(a.out, "\x1b]52;c;%s\x07", base64.StdEncoding.EncodeToString([]byte(s)))
}

// ---------------------------------------------------------------------
// Выбранные элементы
// ---------------------------------------------------------------------

func (a *App) selSocket() (model.Socket, bool) {
	if c := a.lists[pNet].cursor; c < len(a.socks) {
		return a.socks[c], true
	}
	return model.Socket{}, false
}

func (a *App) selPort() (model.Exposure, bool) {
	if c := a.lists[pPorts].cursor; c < len(a.ports) {
		return a.ports[c], true
	}
	return model.Exposure{}, false
}

// portMatches — фильтр панели «Порты»: адрес, порт, доступность,
// сервис, процесс, контейнер, уровень.
func (a *App) portMatches(e model.Exposure) bool {
	svc := ""
	if e.Service != nil {
		svc = e.Service.Name
	}
	return matches(a.lists[pPorts].filter, e.Proto, e.Addr, strconv.Itoa(e.Port), e.Scope, a.scopeName(e.Scope), svc,
		e.ProcName, strconv.Itoa(e.PID), e.User, e.Container, e.Risk.String())
}

func (a *App) selCheck() (model.AuditCheck, bool) {
	if c := a.lists[pAudit].cursor; c < len(a.checks) {
		return a.checks[c], true
	}
	return model.AuditCheck{}, false
}

func (a *App) selBan() (model.Fail2banBan, bool) {
	if c := a.lists[pF2B].cursor; c < len(a.bans) {
		return a.bans[c], true
	}
	return model.Fail2banBan{}, false
}

func (a *App) selEvent() (model.Event, bool) {
	if c := a.lists[pHist].cursor; c < len(a.events) {
		return a.events[c], true
	}
	return model.Event{}, false
}

func (a *App) selMetric() (metricRow, bool) {
	if c := a.lists[pMetrics].cursor; c < len(a.mrows) {
		return a.mrows[c], true
	}
	return metricRow{}, false
}

func (a *App) selSystem() (model.SystemFinding, bool) {
	if c := a.lists[pSys].cursor; c < len(a.system) {
		return a.system[c], true
	}
	return model.SystemFinding{}, false
}

// selectedProc — процесс, к которому относится выбранный элемент
// активной (или последней развёрнутой) панели.
func (a *App) selectedProc() (view.Summary, bool) {
	switch a.expandedOrFocus() {
	case pSusp:
		if c := a.lists[pSusp].cursor; c < len(a.susp) {
			return a.susp[c], true
		}
	case pProcs:
		if c := a.lists[pProcs].cursor; c < len(a.procs) {
			return a.procs[c], true
		}
	case pNet:
		if s, ok := a.selSocket(); ok && s.ProcKey != "" {
			p, ok := a.byKey[s.ProcKey]
			return p, ok
		}
	case pPorts:
		if e, ok := a.selPort(); ok && e.ProcKey != "" {
			p, ok := a.byKey[e.ProcKey]
			return p, ok
		}
	case pHist:
		if e, ok := a.selEvent(); ok && e.Key != "" {
			if p, ok := a.byKey[e.Key]; ok {
				return p, true
			}
			return view.Summary{Key: e.Key, PID: e.PID, Name: e.Name}, true
		}
	}
	return view.Summary{}, false
}

func (a *App) expandedOrFocus() panelID {
	if a.focus == pStatus {
		return pStatus
	}
	return a.focus
}

// eventName — короткое название типа события для узких колонок.
func eventName(l i18n.Lang, t string) string {
	switch t {
	case model.EvBaseline, model.EvStarted, model.EvExited, model.EvChanged, model.EvRiskUp,
		model.EvRiskDown, model.EvFinding, model.EvListen, model.EvSystem, model.EvAudit:
		return i18n.T("tui.event." + t).In(l)
	}
	return t
}

// IsTerminal сообщает, что стандартный ввод — терминал (можно запускать
// интерфейс).
func IsTerminal() bool { return isTerminal(int(os.Stdin.Fd())) }

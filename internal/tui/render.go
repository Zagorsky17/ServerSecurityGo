package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// seg — кусок строки с одним стилем; line — строка из кусков.
type seg struct {
	t  string
	st Style
}
type line []seg

// minHeight — минимальная высота окна для раскладки панелей.
const minHeight = 16

// draw рисует кадр целиком и выводит его.
func (a *App) draw() {
	a.render()
	_ = a.scr.Flush(a.out)
}

// render раскладывает панели и рисует их в буфер (без вывода — удобно
// для тестов).
func (a *App) render() {
	// Меньше 16 строк восемь панелей слева не помещаются даже рамками.
	if a.w < 20 || a.h < minHeight {
		a.scr = newScreen(max(a.w, 1), max(a.h, 1))
		a.scr.Text(0, 0, a.w, a.tr("tui.too_small"), stWarn)
		return
	}
	a.scr = newScreen(a.w, a.h)
	contentH := a.h - 1

	// Ширина левой колонки. В узком окне или при увеличении (+) одна из
	// сторон занимает весь экран.
	lw := a.w * 2 / 5
	lw = min(max(lw, 38), a.w-30)
	showLeft, showMain := true, true
	if a.w < 80 || a.zoom {
		if a.inMain {
			showLeft = false
		} else {
			showMain = false
		}
	}
	if !showLeft {
		lw = 0
	} else if !showMain {
		lw = a.w
	}
	for i := range a.rects {
		a.rects[i] = rect{}
	}

	if showLeft {
		a.layoutLeft(lw, contentH)
	}
	if showMain {
		a.rects[nPanels] = rect{lw, 0, a.w - lw, contentH}
		a.drawMain(a.rects[nPanels])
	}
	a.drawBottom()
	if a.help {
		a.drawHelp()
	}
}

// layoutLeft раскладывает панели слева «гармошкой», как в lazygit:
// развёрнутая панель получает почти всю высоту, остальные — по
// несколько строк.
//
// В низком окне (80×24) свёрнутые панели сжимаются до рамки с заголовком
// (2 строки), а если и этого мало — прячется «Сводка»: развёрнутой
// панели нужно хотя бы несколько строк списка.
func (a *App) layoutLeft(lw, contentH int) {
	// Свёрнутые панели-списки: все, кроме развёрнутой.
	folded := int(nPanels) - 2
	const bigMin = 6
	statusH := 6
	if contentH-statusH < folded*2+bigMin {
		statusH = max(0, contentH-(folded*2+bigMin))
		if statusH < 3 {
			statusH = 0
		}
	}
	a.rects[pStatus] = rect{0, 0, lw, statusH}
	avail := contentH - statusH
	small := min(max(avail/(folded+3), 3), 7)
	big := avail - small*folded
	if big < bigMin {
		small = max(2, min(3, (avail-bigMin)/folded))
		big = avail - small*folded
	}
	y := statusH
	for p := pSusp; p < nPanels; p++ {
		h := small
		if p == a.expanded {
			h = big
		}
		if p == nPanels-1 {
			h = contentH - y // остаток — последней панели
		}
		a.rects[p] = rect{0, y, lw, h}
		y += h
	}
	if statusH > 0 {
		a.drawStatus(a.rects[pStatus])
	}
	for p := pSusp; p < nPanels; p++ {
		a.drawList(p, a.rects[p])
	}
}

func (a *App) panelActive(p panelID) bool { return !a.inMain && a.focus == p }

// ---------------------------------------------------------------------
// Панель «Сводка»
// ---------------------------------------------------------------------

func (a *App) drawStatus(r rect) {
	s := a.scr
	s.Box(r.x, r.y, r.w, r.h, "[1] "+a.panelTitle(pStatus), a.panelActive(pStatus))
	iw := r.w - 4
	x := r.x + 2
	if a.data == nil {
		msg := a.tr("tui.loading")
		if a.err != nil {
			msg = a.tr("tui.error", a.err.Error())
		}
		s.Text(x, r.y+1, iw, msg, stErr)
		return
	}
	st := a.data.Status
	h := st.Host
	host := sanitize(h.Hostname)
	if st.Demo {
		host += " · " + a.tr("tui.demo")
	}
	s.Text(x, r.y+1, iw, fmt.Sprintf("%s · %s · %s", host, h.OS, h.Kernel), stBold)
	s.Text(x, r.y+2, iw, a.tr("tui.scan_line", st.Time.Local().Format("15:04:05"), st.DurationMs, secs(st.Interval), a.txt(a.src.Describe())), stDim)
	cx := x
	for _, rk := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		n := st.Stats.ByRisk[rk]
		stl := riskStyle(rk)
		if n == 0 {
			stl = stDim
		}
		cx += s.Text(cx, r.y+3, x+iw-cx, fmt.Sprintf("%s %d  ", strings.TrimSpace(riskShort(rk)), n), stl)
	}
	line := a.tr("tui.counts_line", st.Stats.Total, st.Stats.Sockets, st.SystemFindings)
	s.Text(x, r.y+4, iw, line, stNormal)
	if len(st.Warnings) > 0 {
		w := fmt.Sprintf(" · ⚠ %d", len(st.Warnings))
		s.Text(x+strWidth(line), r.y+4, iw-strWidth(line), w, stWarn)
	}
}

func secs(f float64) string {
	return (time.Duration(f * float64(time.Second))).String()
}

// ---------------------------------------------------------------------
// Панели-списки
// ---------------------------------------------------------------------

func (a *App) listTitle(p panelID) string {
	t := fmt.Sprintf("[%d] %s (%d)", p+1, a.panelTitle(p), a.count(p))
	if p == pProcs {
		if a.treeMode {
			t += " · " + a.tr("tui.tree")
		} else {
			t += " · " + a.sortName(a.sortMode)
		}
	}
	if f := a.lists[p].filter; f != "" {
		t += " · /" + f
	}
	return t
}

func (a *App) drawList(p panelID, r rect) {
	s := a.scr
	active := a.panelActive(p)
	s.Box(r.x, r.y, r.w, r.h, a.listTitle(p), active)
	iw := r.w - 2
	ih := r.h - 2
	if ih <= 0 {
		return
	}
	x, y := r.x+1, r.y+1
	// Заголовок колонок — только если панель достаточно высокая.
	header := a.columnsHeader(p, iw)
	a.headers[p] = 0
	if header != "" && ih >= 4 {
		s.Text(x, y, iw, header, stDim)
		y++
		ih--
		a.headers[p] = 1
	}
	n := a.count(p)
	l := &a.lists[p]
	// Прокрутка так, чтобы курсор был виден.
	if l.cursor < l.offset {
		l.offset = l.cursor
	}
	if l.cursor >= l.offset+ih {
		l.offset = l.cursor - ih + 1
	}
	l.offset = max(0, min(l.offset, max(0, n-ih)))
	if n == 0 {
		msg := a.tr("tui.empty")
		if p == pSusp && l.filter == "" {
			msg = a.tr("tui.no_suspicious")
		}
		s.Text(x+1, y, iw-1, msg, stDim)
		return
	}
	for i := 0; i < ih && l.offset+i < n; i++ {
		idx := l.offset + i
		segs := a.row(p, idx, iw)
		cx := x
		for _, sg := range segs {
			cx += s.Text(cx, y+i, x+iw-cx, sanitize(sg.t), sg.st)
		}
		if idx == l.cursor {
			// Ярко — в активной панели (или если её элемент открыт в
			// подробностях), приглушённо — в остальных.
			st := stSelBlur
			if active || (a.inMain && a.focus == p) {
				st = stSelFocus
			}
			s.Fill(x, y+i, iw, 1, st)
		}
	}
	// Индикатор позиции в длинном списке.
	if n > ih {
		pos := fmt.Sprintf(" %d/%d ", l.cursor+1, n)
		s.Text(r.x+r.w-1-strWidth(pos)-1, r.y+r.h-1, strWidth(pos), pos, stDim)
	}
}

// columnsHeader — подписи колонок списка для текущей ширины.
func (a *App) columnsHeader(p panelID, w int) string {
	switch p {
	case pSusp:
		return fit(a.tr("tui.cols.susp"), w)
	case pProcs:
		h := a.tr("tui.cols.procs")
		if w >= 90 {
			h += strings.Repeat(" ", 12) + a.tr("tui.cols.command")
		}
		return fit(h, w)
	case pNet:
		return fit(a.tr("tui.cols.net"), w)
	case pPorts:
		return fit(a.tr("tui.cols.ports"), w)
	case pAudit:
		return fit(a.tr("tui.cols.audit"), w)
	case pHist:
		return fit(a.tr("tui.cols.hist"), w)
	case pSys:
		return fit(a.tr("tui.cols.sys"), w)
	}
	return ""
}

func shortUser(u string) string { return fit(u, 8) }

// row — строка списка в виде кусков с цветами.
func (a *App) row(p panelID, i, w int) []seg {
	switch p {
	case pSusp:
		pr := a.susp[i]
		rest := pr.Exe
		if rest == "" {
			rest = pr.Cmdline
		}
		if pr.ExeDeleted {
			rest += " " + a.tr("tui.deleted")
		}
		return []seg{
			{fit(pr.Risk.String(), 8), riskStyle(pr.Risk.String())},
			{fitLeft(strconv.Itoa(pr.PID), 6) + " ", stNormal},
			{shortUser(pr.User) + " ", stDim},
			{fit(pr.Name, 16) + " ", stBold},
			{rest, stDim},
		}
	case pProcs:
		pr := a.procs[i]
		risk := "    "
		rst := stDim
		if pr.Risk != model.RiskInfo {
			risk, rst = riskShort(pr.Risk.String()), riskStyle(pr.Risk.String())
		}
		prefix := ""
		if a.treeMode && i < len(a.procPrefix) {
			prefix = a.procPrefix[i]
		}
		segs := []seg{
			{fitLeft(strconv.Itoa(pr.PID), 6) + " ", stNormal},
			{shortUser(pr.User) + " ", stDim},
			{fitLeft(fmt.Sprintf("%.1f", pr.CPUPercent), 6) + " ", cpuStyle(pr.CPUPercent)},
			{fitLeft(fmtBytes(pr.RSSBytes), 7) + " ", stDim},
			{risk + " ", rst},
			{prefix, stDim},
		}
		name := pr.Name
		if pr.Kernel {
			name = "[" + name + "]"
		}
		if w >= 90 {
			segs = append(segs, seg{fit(name, max(8, 18-strWidth(prefix))) + " ", stBold}, seg{pr.Cmdline, stDim})
		} else {
			segs = append(segs, seg{name, stBold})
		}
		return segs
	case pNet:
		sk := a.socks[i]
		remote := []seg{{fit("—", 21) + " ", stNormal}}
		if sk.RemotePort != 0 {
			remote = addrSegs(sk.RemoteAddr, sk.RemotePort, 21)
		}
		owner := a.tr("tui.unknown")
		ost := stDim
		if sk.PID != 0 {
			owner, ost = fmt.Sprintf("%s(%d)", sk.ProcName, sk.PID), stNormal
		}
		stState := stNormal
		if sk.State == "LISTEN" {
			stState = stAccent
		}
		segs := []seg{{fit(sk.Proto, 5) + " ", stDim}}
		segs = append(segs, addrSegs(sk.LocalAddr, sk.LocalPort, 21)...)
		segs = append(segs, remote...)
		return append(segs, seg{fit(sk.State, 11) + " ", stState}, seg{owner, ost})
	case pPorts:
		e := a.ports[i]
		risk, rst := "    ", stDim
		if e.Risk != model.RiskInfo {
			risk, rst = riskShort(e.Risk.String()), riskStyle(e.Risk.String())
		}
		if e.Suppressed {
			rst = stDim
		}
		scope, sst := a.scopeName(e.Scope), stDim
		if e.Scope == model.ScopePublic {
			sst = stWarn
		}
		svc := "—"
		if e.Service != nil {
			svc = e.Service.Name
		}
		owner := a.tr("tui.unknown")
		ost := stDim
		switch {
		case e.PID != 0:
			owner, ost = fmt.Sprintf("%s(%d)", e.ProcName, e.PID), stNormal
		case e.Docker != nil:
			owner, ost = "docker "+e.Container, stNormal
		}
		segs := []seg{{risk + " ", rst}, {fit(e.Proto, 5) + " ", stDim}}
		segs = append(segs, addrSegs(e.Addr, e.Port, 23)...)
		return append(segs, seg{fit(scope, 10) + " ", sst}, seg{fit(svc, 14) + " ", stBold}, seg{owner, ost})
	case pAudit:
		c := a.checks[i]
		sst := auditStyle(c.Status)
		// Важность имеет смысл только для проблем: у пройденных проверок и
		// советов она сбивала бы с толку.
		sev, sevSt := "    ", stDim
		if c.Status == model.AuditFail || c.Status == model.AuditWarn {
			sev, sevSt = riskShort(c.Severity.String()), riskStyle(c.Severity.String())
		}
		return []seg{
			{auditShort(c.Status) + " ", sst},
			{sev + " ", sevSt},
			{fit(a.groupName(c.Group), 8) + " ", stDim},
			{a.txt(c.Title), stNormal},
		}
	case pHist:
		e := a.events[i]
		who := e.Name
		est := stNormal
		if e.Risk >= model.RiskMedium {
			est = riskStyle(e.Risk.String())
		}
		pid := ""
		if e.PID != 0 {
			pid = strconv.Itoa(e.PID)
		}
		return []seg{
			{e.Time.Local().Format("15:04:05") + " ", stDim},
			{fit(eventName(a.lang, e.Type), 10) + " ", est},
			{fitLeft(pid, 6) + " ", stNormal},
			{fit(who, 15) + " ", stBold},
			{a.txt(e.Details), stDim},
		}
	case pSys:
		f := a.system[i]
		return []seg{
			{riskShort(f.Risk.String()) + " ", riskStyle(f.Risk.String())},
			{a.txt(f.Title) + " ", stNormal},
			{f.Path, stDim},
		}
	}
	return nil
}

func cpuStyle(v float64) Style {
	switch {
	case v >= 80:
		return Style{FG: 203, BG: -1, Bold: true}
	case v >= 20:
		return stWarn
	}
	return stNormal
}

func fmtBytes(n uint64) string {
	switch {
	case n == 0:
		return "0"
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0fM", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%.0fK", float64(n)/(1<<10))
	}
}

// ---------------------------------------------------------------------
// Панель подробностей
// ---------------------------------------------------------------------

func (a *App) drawMain(r rect) {
	s := a.scr
	title, lines := a.mainContent(r.w - 4)
	a.mainLines = lines
	a.mainH = r.h - 2
	maxOff := max(0, len(lines)-a.mainH)
	a.mainOffset = min(max(a.mainOffset, 0), maxOff)
	s.Box(r.x, r.y, r.w, r.h, title, a.inMain)
	for i := 0; i < a.mainH && a.mainOffset+i < len(lines); i++ {
		cx := r.x + 2
		for _, sg := range lines[a.mainOffset+i] {
			cx += s.Text(cx, r.y+1+i, r.x+r.w-2-cx, sg.t, sg.st)
		}
	}
	if len(lines) > a.mainH {
		pct := 100
		if maxOff > 0 {
			pct = a.mainOffset * 100 / maxOff
		}
		ind := fmt.Sprintf(" %d%% ", pct)
		s.Text(r.x+r.w-2-strWidth(ind), r.y+r.h-1, strWidth(ind), ind, stDim)
	}
}

// lb — построитель строк подробностей с переносом по ширине.
type lb struct {
	w     int
	lang  i18n.Lang
	lines []line
}

// tr — строка каталога на языке интерфейса.
func (b *lb) tr(key string, args ...any) string { return i18n.T(key, args...).In(b.lang) }

func (b *lb) add(segs ...seg) { b.lines = append(b.lines, line(segs)) }
func (b *lb) blank()          { b.lines = append(b.lines, nil) }

func (b *lb) header(t string) {
	if len(b.lines) > 0 {
		b.blank()
	}
	b.add(seg{t, Style{FG: 75, BG: -1, Bold: true}})
}

// para — абзац с переносом и отступом.
func (b *lb) para(text string, st Style, indent int) {
	pad := strings.Repeat(" ", indent)
	for _, l := range wrap(sanitize(text), max(10, b.w-indent)) {
		b.add(seg{pad + l, st})
	}
}

// kv — пара «ключ: значение», значение переносится с отступом.
func (b *lb) kv(k, v string) {
	const kw = 20
	parts := wrap(sanitize(v), max(10, b.w-kw-2))
	for i, p := range parts {
		key := ""
		if i == 0 {
			key = k
		}
		b.add(seg{"  " + fit(key, kw), stDim}, seg{p, stNormal})
	}
}

// kvAddr — пара «ключ: адрес:порт» с адресом цвета stAddr.
func (b *lb) kvAddr(k, addr string, port int) {
	b.add(seg{"  " + fit(k, 20), stDim}, seg{sanitize(addr), stAddr}, seg{fmt.Sprintf(":%d", port), stNormal})
}

// addrSegs — колонка «адрес:порт» шириной w плюс пробел-разделитель:
// адрес цвета stAddr, порт обычным цветом. Не помещающийся адрес
// обрезается с «…» и красится целиком.
func addrSegs(addr string, port, w int) []seg {
	p := fmt.Sprintf(":%d", port)
	if strWidth(addr)+strWidth(p) > w {
		return []seg{{fit(addr+p, w) + " ", stAddr}}
	}
	return []seg{{addr, stAddr}, {fit(p, w-strWidth(addr)) + " ", stNormal}}
}

func fmtTime(t time.Time) string {
	if t.IsZero() || t.Year() < 2000 {
		return "—"
	}
	return t.Local().Format("02.01.2006 15:04:05")
}

func (b *lb) ago(t time.Time) string {
	if t.IsZero() || t.Year() < 2000 {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d >= 24*time.Hour:
		return b.tr("tui.ago.days", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return b.tr("tui.ago.hours", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return b.tr("tui.ago.minutes", int(d.Minutes()))
	}
	return b.tr("tui.ago.seconds", int(d.Seconds()))
}

// mainContent возвращает заголовок и строки для панели подробностей в
// зависимости от активной панели слева.
func (a *App) mainContent(w int) (string, []line) {
	b := &lb{w: w, lang: a.lang}
	if a.data == nil {
		b.para(a.tr("tui.no_data", errText(a.err)), stErr, 0)
		return a.tr("tui.title.details"), b.lines
	}
	switch a.focus {
	case pStatus:
		a.overview(b)
		return a.tr("tui.title.overview"), b.lines
	case pNet:
		sk, ok := a.selSocket()
		if !ok {
			return a.tr("tui.title.socket"), nil
		}
		a.socketDetail(b, sk)
		return a.tr("tui.title.socket_addr", sk.LocalAddr, sk.LocalPort), b.lines
	case pPorts:
		e, ok := a.selPort()
		if !ok {
			b.para(a.tr("web.ports.empty"), stDim, 0)
			return a.tr("tui.panel.ports"), b.lines
		}
		a.portDetail(b, e)
		return a.tr("tui.title.port", exposureEndpoint(e)), b.lines
	case pAudit:
		a.auditHeader(b)
		c, ok := a.selCheck()
		if !ok {
			return a.tr("tui.panel.audit"), b.lines
		}
		a.auditDetail(b, c)
		return a.tr("tui.panel.audit") + " · " + auditShort(c.Status), b.lines
	case pSys:
		f, ok := a.selSystem()
		if !ok {
			b.para(a.tr("tui.no_system"), stDim, 0)
			return a.tr("tui.title.check"), b.lines
		}
		a.systemDetail(b, f)
		return a.tr("tui.title.check") + " · " + f.Path, b.lines
	case pHist:
		e, ok := a.selEvent()
		if !ok {
			return a.tr("tui.title.event"), nil
		}
		b.add(seg{fmtTime(e.Time) + "  ", stDim}, seg{eventName(a.lang, e.Type), riskStyle(e.Risk.String())}, seg{"  " + e.Risk.String(), riskStyle(e.Risk.String())})
		b.para(a.txt(e.Details), stNormal, 0)
		if e.Key == "" {
			return a.tr("tui.title.event"), b.lines
		}
	}
	p, ok := a.selectedProc()
	if !ok {
		b.para(a.tr("tui.select_process"), stDim, 0)
		return a.tr("tui.title.process"), b.lines
	}
	a.processDetail(b, p.Key)
	return fmt.Sprintf("PID %d · %s", p.PID, sanitize(p.Name)), b.lines
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ensureDetail загружает карточку процесса, если выбран другой процесс
// или пришло новое сканирование.
func (a *App) ensureDetail(key string) {
	seq := uint64(0)
	if a.data != nil {
		seq = a.data.Status.Seq
	}
	if key == a.detailKey && seq == a.detailSeq && (a.detail != nil || a.detailErr != nil) {
		return
	}
	a.detailKey, a.detailSeq = key, seq
	a.detail, a.detailErr = a.src.Detail(key)
}

func (a *App) processDetail(b *lb, key string) {
	a.ensureDetail(key)
	if a.detailErr != nil {
		b.para(a.tr("tui.detail_error", a.detailErr.Error()), stErr, 0)
		return
	}
	d := a.detail
	if d.Exited && d.Track != nil {
		t := d.Track
		b.add(seg{a.tr("tui.exited"), stWarn})
		b.kv(a.tr("tui.k.name"), t.Name)
		b.kv(a.tr("tui.k.user"), t.User)
		b.kv(a.tr("tui.k.path"), t.Exe)
		b.kv(a.tr("tui.k.command"), t.Cmdline)
		b.kv(a.tr("tui.k.first"), fmtTime(t.FirstSeen))
		b.kv(a.tr("tui.k.last"), fmtTime(t.LastSeen))
		b.kv(a.tr("tui.k.last_risk"), t.Risk.String())
		eventsBlock(b, d.Events)
		return
	}
	p := d.Process
	rs := p.Risk.String()
	b.add(seg{" " + rs + " ", Style{FG: 16, BG: riskStyle(rs).FG, Bold: true}}, seg{"  " + a.tr("tui.points", p.Score, sanitize(p.User), sanitize(p.Name)), stBold})

	active, info := []model.Finding{}, []model.Finding{}
	for _, f := range p.Findings {
		if f.Category == model.CatInfo {
			info = append(info, f)
		} else {
			active = append(active, f)
		}
	}
	b.header(a.tr("tui.h.assessment"))
	b.para(a.txt(p.Explanation), stNormal, 2)
	if len(active) > 0 {
		b.header(a.tr("tui.h.findings"))
		for _, f := range active {
			findingBlock(b, f)
		}
	}
	if len(p.Recommendations) > 0 {
		b.header(a.tr("tui.h.recommendations"))
		for _, r := range p.Recommendations {
			b.para("• "+a.txt(r), stNormal, 2)
		}
	}
	b.header(a.tr("tui.h.cmdline"))
	cmd := p.Cmdline
	if cmd == "" {
		cmd = a.tr("tui.empty_paren")
	}
	b.para(cmd, Style{FG: 223, BG: -1}, 2)

	b.header(a.tr("tui.h.main"))
	b.kv("PID / PPID", fmt.Sprintf("%d / %d", p.PID, p.PPID))
	b.kv(a.tr("tui.k.user"), fmt.Sprintf("%s (UID %d, EUID %d, GID %d)", p.User, p.UID, p.EUID, p.GID))
	exe := p.Exe
	switch {
	case exe == "" && p.Kernel:
		exe = a.tr("tui.kernel_thread")
	case exe == "":
		exe = a.tr("tui.unavailable")
	case p.ExeDeleted:
		exe += " " + a.tr("tui.deleted")
	}
	b.kv(a.tr("tui.k.exe"), exe)
	if p.ExeInfo != nil {
		b.kv(a.tr("tui.k.file_mode"), a.tr("tui.file_mode", p.ExeInfo.Mode, p.ExeInfo.UID, fmtBytes(uint64(p.ExeInfo.Size))))
	}
	b.kv(a.tr("tui.k.cwd"), orDash(p.Cwd))
	b.kv(a.tr("tui.k.started"), fmtTime(p.StartTime)+" ("+b.ago(p.StartTime)+")")
	b.kv(a.tr("tui.k.first_seen"), fmtTime(p.FirstSeen))
	cpu := fmt.Sprintf("%.1f%%", p.CPUPercent)
	if p.CPUAverage {
		cpu += " " + a.tr("tui.cpu_average")
	}
	b.kv("CPU", cpu)
	b.kv(a.tr("tui.k.memory"), a.tr("tui.memory", fmtBytes(p.RSSBytes), fmt.Sprintf("%.1f", p.MemPercent), p.Threads, p.FDCount))
	if len(p.EnvFlags) > 0 {
		b.kv(a.tr("tui.k.env"), strings.Join(p.EnvFlags, ", ")+" "+a.tr("tui.env_values"))
	}
	if p.ContainerRuntime != "" {
		b.kv(a.tr("tui.k.container"), strings.TrimSpace(p.ContainerRuntime+" "+p.Container))
	}
	if len(p.ForeignNS) > 0 {
		b.kv(a.tr("tui.k.foreign_ns"), strings.Join(p.ForeignNS, ", "))
	}
	if len(p.Access) > 0 {
		b.kv(a.tr("tui.k.no_access"), strings.Join(p.Access, ", "))
	}

	b.header(a.tr("tui.h.chain"))
	var chain []string
	for i := len(d.Ancestors) - 1; i >= 0; i-- {
		chain = append(chain, fmt.Sprintf("%s(%d)", d.Ancestors[i].Name, d.Ancestors[i].PID))
	}
	chain = append(chain, fmt.Sprintf("%s(%d)", p.Name, p.PID))
	b.para(strings.Join(chain, " → "), stNormal, 2)
	if len(d.Children) > 0 {
		var kids []string
		for _, c := range d.Children {
			kids = append(kids, fmt.Sprintf("%s(%d)", c.Name, c.PID))
		}
		b.para(a.tr("tui.children", strings.Join(kids, ", ")), stDim, 2)
	}

	var inet []model.Socket
	unix := 0
	for _, sk := range p.Sockets {
		if sk.Proto == "unix" {
			unix++
		} else {
			inet = append(inet, sk)
		}
	}
	b.header(a.tr("tui.h.network", len(inet), unix))
	for _, sk := range inet {
		segs := []seg{{fmt.Sprintf("  %-5s ", sk.Proto), stNormal}, {sk.LocalAddr, stAddr}, {fmt.Sprintf(":%d", sk.LocalPort), stNormal}}
		if sk.RemotePort != 0 {
			segs = append(segs, seg{" → ", stNormal}, seg{sk.RemoteAddr, stAddr}, seg{fmt.Sprintf(":%d", sk.RemotePort), stNormal})
		}
		b.add(append(segs, seg{" ", stNormal}, seg{sk.State, stAccent})...)
	}
	if len(p.Files) > 0 {
		b.header(a.tr("tui.h.files", len(p.Files), p.FDCount))
		for i, f := range p.Files {
			if i >= 40 {
				b.add(seg{"  " + a.tr("tui.more_files", len(p.Files)-40), stDim})
				break
			}
			b.add(seg{fmt.Sprintf("  %4d %-7s ", f.FD, f.Kind), stDim}, seg{sanitize(f.Target), stNormal})
		}
	}
	if len(info) > 0 {
		b.header(a.tr("tui.h.info"))
		for _, f := range info {
			b.para("• "+a.txt(f.Title)+": "+i18n.Join("; ", f.Evidence...).In(a.lang), stDim, 2)
		}
	}
	eventsBlock(b, d.Events)
}

func findingBlock(b *lb, f model.Finding) {
	st := stBold
	mark := "●"
	if f.Strong {
		st = Style{FG: 208, BG: -1, Bold: true}
	}
	if f.Suppressed {
		st = stDim
		mark = "○"
	}
	tags := fmt.Sprintf("  [%s, +%d", detect.CategoryTitle(f.Category).In(b.lang), f.Weight)
	if f.Strong {
		tags += ", " + b.tr("tui.strong")
	}
	if f.Suppressed {
		tags += ", " + b.tr("tui.suppressed")
	}
	tags += "]"
	b.add(seg{"  " + mark + " ", st}, seg{sanitize(f.Title.In(b.lang)), st}, seg{tags, stDim})
	for _, e := range f.Evidence {
		b.para("· "+e.In(b.lang), Style{FG: 250, BG: -1}, 6)
	}
	if !f.Recommendation.IsZero() {
		b.para("→ "+f.Recommendation.In(b.lang), stDim, 6)
	}
}

func eventsBlock(b *lb, evs []model.Event) {
	if len(evs) == 0 {
		return
	}
	b.header(b.tr("tui.h.history"))
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		b.add(seg{"  " + e.Time.Local().Format("02.01 15:04:05") + " ", stDim}, seg{fit(eventName(b.lang, e.Type), 11), riskStyle(e.Risk.String())}, seg{sanitize(e.Details.In(b.lang)), stNormal})
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (a *App) socketDetail(b *lb, sk model.Socket) {
	b.kv(a.tr("tui.k.proto"), sk.Proto)
	b.kvAddr(a.tr("tui.k.local"), sk.LocalAddr, sk.LocalPort)
	if sk.RemotePort != 0 {
		b.kvAddr(a.tr("tui.k.remote"), sk.RemoteAddr, sk.RemotePort)
	}
	b.kv(a.tr("tui.k.state"), sk.State)
	b.kv("inode", strconv.FormatUint(sk.Inode, 10))
	b.kv("Netns", orDash(sk.NetNS))
	if sk.ProcKey == "" {
		b.blank()
		b.para(a.tr("tui.no_owner"), stDim, 2)
		return
	}
	b.blank()
	a.processDetail(b, sk.ProcKey)
}

// auditShort — короткая метка статуса проверки (4 символа, как у риска).
func auditShort(s string) string {
	switch s {
	case model.AuditFail:
		return "FAIL"
	case model.AuditWarn:
		return "WARN"
	case model.AuditPass:
		return "OK  "
	case model.AuditInfo:
		return "INFO"
	case model.AuditNA:
		return "N/A "
	}
	return "??  "
}

func auditStyle(s string) Style {
	switch s {
	case model.AuditFail:
		return riskStyle("CRITICAL")
	case model.AuditWarn:
		return riskStyle("MEDIUM")
	case model.AuditPass:
		return stOK
	}
	return stDim
}

// statusName — подпись статуса проверки.
func (a *App) statusName(s string) string {
	switch s {
	case model.AuditPass:
		return a.tr("audit.status.pass")
	case model.AuditFail:
		return a.tr("audit.status.fail")
	case model.AuditWarn:
		return a.tr("audit.status.warn")
	case model.AuditInfo:
		return a.tr("audit.status.info")
	case model.AuditNA:
		return a.tr("audit.status.na")
	}
	return a.tr("audit.status.unknown")
}

// groupName — подпись группы проверок.
func (a *App) groupName(g string) string {
	switch g {
	case model.AuditGroupSSH:
		return a.tr("audit.group.ssh")
	case model.AuditGroupAccounts:
		return a.tr("audit.group.accounts")
	case model.AuditGroupSudo:
		return a.tr("audit.group.sudo")
	}
	return g
}

// auditHeader — когда была проверка и сколько пройдено.
func (a *App) auditHeader(b *lb) {
	av := a.data.Audit
	switch {
	case av == nil || !av.Enabled:
		b.para(a.tr("web.audit.disabled"), stWarn, 0)
	case !av.Ready || av.Running:
		b.para(a.tr("web.audit.running"), stDim, 0)
	default:
		b.para(a.tr("tui.audit.when", fmtTime(av.Time), av.DurationMs), stDim, 0)
		st := stOK
		if av.Summary.Fail > 0 {
			st = riskStyle("CRITICAL")
		} else if av.Summary.Warn > 0 {
			st = stWarn
		}
		b.para(a.tr("web.audit.score", av.Passed, av.Total, av.Summary.Fail, av.Summary.Warn, av.Summary.Info, av.Summary.NA+av.Summary.Unknown), st, 0)
	}
	b.blank()
}

// auditDetail — подробности проверки: факты, рекомендация, команда.
func (a *App) auditDetail(b *lb, c model.AuditCheck) {
	b.add(seg{" " + auditShort(c.Status) + " ", Style{FG: 16, BG: auditStyle(c.Status).FG, Bold: true}}, seg{"  " + sanitize(a.txt(c.Title)), stBold})
	b.kv(a.tr("web.col.status"), a.statusName(c.Status))
	b.kv(a.tr("web.col.severity"), c.Severity.String())
	b.kv(a.tr("web.col.group"), a.groupName(c.Group))
	b.kv(a.tr("tui.k.rule"), c.ID)
	if len(c.References) > 0 {
		b.kv("ATT&CK", strings.Join(c.References, ", "))
	}
	if len(c.Evidence) > 0 {
		b.header(a.tr("tui.h.facts"))
		for _, m := range c.Evidence {
			b.para("· "+a.txt(m), stNormal, 2)
		}
	}
	if !c.Recommendation.IsZero() {
		b.header(a.tr("tui.h.recommendation"))
		b.para(a.txt(c.Recommendation), stNormal, 2)
	}
	if c.FixCommand != "" {
		b.header(a.tr("tui.h.fix"))
		b.para(c.FixCommand, Style{FG: 223, BG: -1}, 2)
	}
}

// scopeName — подпись области видимости порта.
func (a *App) scopeName(s string) string {
	switch s {
	case model.ScopePublic:
		return a.tr("tui.scope.public")
	case model.ScopePrivate:
		return a.tr("tui.scope.private")
	case model.ScopeLoopback:
		return a.tr("tui.scope.loopback")
	case model.ScopeNetNS:
		return a.tr("tui.scope.netns")
	}
	return s
}

// matchName — как узнан сервис (те же тексты, что в фактах).
func (a *App) matchName(m string) string {
	switch m {
	case "port+process":
		return a.tr("ev.exp_match_port_process")
	case "port+image":
		return a.tr("ev.exp_match_port_image")
	case "process":
		return a.tr("ev.exp_match_process")
	case "image":
		return a.tr("ev.exp_match_image")
	}
	return a.tr("ev.exp_match_port")
}

// fwName — подпись состояния межсетевого экрана для порта.
func (a *App) fwName(s string) string {
	switch s {
	case model.FwOpen:
		return a.tr("tui.fw.open")
	case model.FwFiltered:
		return a.tr("tui.fw.filtered")
	case model.FwBypassed:
		return a.tr("tui.fw.bypassed")
	}
	return "—"
}

// ufwName — подпись состояния ufw на сервере.
func (a *App) ufwName(fw model.FirewallInfo) string {
	switch fw.UFW {
	case "active":
		return a.tr("tui.ufw.active") + " · " + a.tr("tui.ufw.policy", fw.DefaultInput, fw.Rules)
	case "inactive":
		return a.tr("tui.ufw.inactive")
	}
	return a.tr("tui.ufw.absent")
}

func exposureEndpoint(e model.Exposure) string {
	if strings.Contains(e.Addr, ":") {
		return fmt.Sprintf("[%s]:%d", e.Addr, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Addr, e.Port)
}

// portDetail — подробности открытого порта; ниже — карточка процесса,
// который его держит.
func (a *App) portDetail(b *lb, e model.Exposure) {
	rs := e.Risk.String()
	title := exposureEndpoint(e)
	if e.Service != nil {
		title = e.Service.Name + " · " + title
	}
	b.add(seg{" " + rs + " ", Style{FG: 16, BG: riskStyle(rs).FG, Bold: true}}, seg{"  " + sanitize(title), stBold})
	if e.Suppressed {
		b.add(seg{"  " + a.tr("tui.suppressed"), stDim})
	}
	b.kv(a.tr("tui.k.proto"), e.Proto)
	b.kvAddr(a.tr("tui.k.address"), e.Addr, e.Port)
	reach := a.scopeName(e.Scope)
	if e.AllInterfaces {
		reach += " · " + a.tr("tui.all_ifaces")
	}
	b.kv(a.tr("tui.k.reach"), reach)
	if e.Firewall != "" {
		b.kv(a.tr("tui.k.firewall"), a.fwName(e.Firewall))
	}
	if e.Service != nil {
		b.kv(a.tr("tui.k.service"), e.Service.Name+" ("+a.matchName(e.Service.Match)+")")
	}
	if e.Container != "" {
		b.kv(a.tr("tui.k.container"), e.Container)
	}
	if d := e.Docker; d != nil {
		b.kv("Docker", fmt.Sprintf("%s → %d (%s)", exposureEndpoint(model.Exposure{Addr: d.HostIP, Port: d.HostPort}), d.ContainerPort, orDash(d.Image)))
	}
	if len(e.Evidence) > 0 {
		b.header(a.tr("tui.h.facts"))
		for _, m := range e.Evidence {
			b.para("· "+a.txt(m), stNormal, 2)
		}
	}
	if !e.Recommendation.IsZero() {
		b.header(a.tr("tui.h.recommendation"))
		b.para(a.txt(e.Recommendation), stNormal, 2)
	}
	if e.ProcKey == "" {
		return
	}
	b.blank()
	a.processDetail(b, e.ProcKey)
}

func (a *App) systemDetail(b *lb, f model.SystemFinding) {
	rs := f.Risk.String()
	b.add(seg{" " + rs + " ", Style{FG: 16, BG: riskStyle(rs).FG, Bold: true}}, seg{"  " + sanitize(a.txt(f.Title)), stBold})
	b.kv(a.tr("tui.k.file"), f.Path)
	b.kv(a.tr("tui.k.modified"), fmtTime(f.ModTime))
	b.kv(a.tr("tui.k.rule"), f.ID)
	b.header(a.tr("tui.h.facts"))
	for _, e := range f.Evidence {
		b.para("· "+a.txt(e), stNormal, 2)
	}
	if !f.Recommendation.IsZero() {
		b.header(a.tr("tui.h.recommendation"))
		b.para(a.txt(f.Recommendation), stNormal, 2)
	}
}

// overview — содержимое подробностей для панели «Сводка».
func (a *App) overview(b *lb) {
	st := a.data.Status
	h := st.Host
	b.add(seg{"ServerSecurityGo " + st.Version, stBold})
	b.para(a.tr("tui.observe_only"), stDim, 0)
	b.header(a.tr("tui.h.server"))
	b.kv(a.tr("tui.k.host"), h.Hostname)
	b.kv(a.tr("tui.k.os"), h.OS+" / "+h.Kernel)
	b.kv(a.tr("tui.k.boot"), fmtTime(h.BootTime)+" ("+a.tr("tui.ago", b.ago(h.BootTime))+")")
	b.kv(a.tr("tui.k.memory"), fmtBytes(h.MemTotal))
	b.kv(a.tr("tui.k.root"), a.yesNo(h.IsRoot))
	b.kv(a.tr("tui.k.in_container"), a.yesNo(h.InContainer))
	b.header(a.tr("tui.h.source"))
	b.kv(a.tr("tui.k.source"), a.txt(a.src.Describe()))
	b.kv(a.tr("tui.k.last_scan"), fmtTime(st.Time)+" "+a.tr("tui.ms", st.DurationMs))
	b.kv(a.tr("tui.k.refresh"), a.tr("tui.every", a.refresh.String())+a.pausedText())
	b.kv(a.tr("tui.k.lang"), a.tr("tui.lang_name"))
	b.header(a.tr("tui.h.risks"))
	for _, rk := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		b.add(seg{"  " + fit(rk, 10), riskStyle(rk)}, seg{strconv.Itoa(st.Stats.ByRisk[rk]), stNormal})
	}
	if av := a.data.Audit; av != nil && av.Enabled && av.Ready {
		b.header(a.tr("tui.panel.audit"))
		st := stOK
		if av.Summary.Fail > 0 {
			st = riskStyle("CRITICAL")
		} else if av.Summary.Warn > 0 {
			st = stWarn
		}
		b.para(a.tr("web.audit.score", av.Passed, av.Total, av.Summary.Fail, av.Summary.Warn, av.Summary.Info, av.Summary.NA+av.Summary.Unknown), st, 2)
	}
	if x := a.data.Exposure; x != nil {
		b.header(a.tr("tui.h.exposure"))
		pst := stNormal
		if st.Stats.DangerousPorts > 0 {
			pst = stWarn
		}
		b.para(a.tr("tui.ports.summary", st.Stats.PublicPorts, st.Stats.DangerousPorts), pst, 2)
		b.kv(a.tr("tui.k.ufw"), a.ufwName(x.Firewall))
		var addrs []string
		for _, ad := range x.Addrs {
			if ad.Scope != model.ScopeLoopback {
				addrs = append(addrs, ad.Addr+" ("+a.scopeName(ad.Scope)+")")
			}
		}
		if len(addrs) > 0 {
			b.kv(a.tr("tui.k.addrs"), strings.Join(addrs, ", "))
		}
	}
	if len(st.Warnings) > 0 {
		b.header(a.tr("tui.h.limits"))
		for _, w := range st.Warnings {
			b.para("⚠ "+a.txt(w), stWarn, 2)
		}
	}
	b.header(a.tr("tui.h.quickstart"))
	b.para(a.tr("tui.quickstart"), stNormal, 2)
}

func (a *App) yesNo(v bool) string {
	if v {
		return a.tr("tui.yes")
	}
	return a.tr("tui.no")
}

func (a *App) pausedText() string {
	if a.paused {
		return " " + a.tr("tui.paused_paren")
	}
	return ""
}

// ---------------------------------------------------------------------
// Нижняя строка и справка
// ---------------------------------------------------------------------

func (a *App) drawBottom() {
	s := a.scr
	y := a.h - 1
	if a.editing {
		l := a.lists[a.focus]
		cx := s.Text(0, y, a.w, a.tr("tui.filter_prompt", a.panelTitle(a.focus)), stKey)
		cx += s.Text(cx, y, a.w-cx, l.filter, stBold)
		s.Text(cx, y, a.w-cx, "█   "+a.tr("tui.filter_hint"), stDim)
		return
	}
	var hints [][2]string
	switch {
	case a.inMain:
		hints = [][2]string{{"↑↓", a.tr("tui.hint.scroll")}, {"PgUp/PgDn", a.tr("tui.hint.page")}, {"←/Esc", a.tr("tui.hint.to_list")}, {"y", a.tr("tui.hint.copy_cmd")}, {"Y", "JSON"}, {"+", a.tr("tui.hint.fullscreen")}}
	case a.focus == pProcs:
		hints = [][2]string{{"↑↓", a.tr("tui.hint.select")}, {"Enter", a.tr("tui.hint.details")}, {"/", a.tr("tui.hint.filter")}, {"s", a.tr("tui.hint.sort")}, {"t", a.tr("tui.tree")}, {"K", a.tr("tui.hint.kernel")}, {"y", a.tr("tui.hint.copy")}}
	default:
		hints = [][2]string{{"↑↓", a.tr("tui.hint.select")}, {"1-8/Tab", a.tr("tui.hint.panels")}, {"Enter", a.tr("tui.hint.details")}, {"/", a.tr("tui.hint.filter")}, {"r", a.tr("tui.hint.scan")}, {"y", a.tr("tui.hint.copy")}}
	}
	hints = append(hints, [2]string{"L", a.tr("tui.hint.lang")}, [2]string{"?", a.tr("tui.hint.help")}, [2]string{"q", a.tr("tui.hint.quit")})
	cx := 0
	for _, h := range hints {
		need := strWidth(h[0]) + strWidth(h[1]) + 3
		if cx+need > a.w-24 {
			break
		}
		cx += s.Text(cx, y, a.w-cx, h[0], stKey)
		cx += s.Text(cx, y, a.w-cx, " "+h[1]+"  ", stDim)
	}
	// Справа — состояние обновления или сообщение.
	right, rst := "", stDim
	switch {
	case a.msg != "" && time.Since(a.msgTime) < 4*time.Second:
		right, rst = a.msg, stOK
		if a.msgErr {
			rst = stErr
		}
	case a.err != nil:
		right, rst = a.tr("tui.error_lower", a.err.Error()), stErr
	case a.paused:
		right, rst = "⏸ "+a.tr("tui.paused_key"), stWarn
	default:
		right = "⟳ " + a.refresh.String()
	}
	rw := min(strWidth(right), a.w-cx)
	if rw > 0 {
		s.Text(a.w-rw, y, rw, right, rst)
	}
}

// helpLines — справка по клавишам: клавиша и ключ каталога описания.
// Пустая клавиша — заголовок раздела.
var helpLines = [][2]string{
	{"", "tui.help.nav"},
	{"1 … 8", "tui.help.panels"},
	{"Tab / Shift+Tab, [ ]", "tui.help.next_panel"},
	{"↑ ↓ / j k", "tui.help.select"},
	{"PgUp PgDn, Ctrl+U Ctrl+D", "tui.help.page"},
	{"Home End / g G", "tui.help.home_end"},
	{"Enter, →, l", "tui.help.enter"},
	{"←, h, Esc", "tui.help.back"},
	{"+ / z", "tui.help.zoom"},
	{"", "tui.help.mouse_key"},
	{"", "tui.help.actions"},
	{"/", "tui.help.filter"},
	{"s", "tui.help.sort"},
	{"t", "tui.help.tree"},
	{"K", "tui.help.kernel"},
	{"r", "tui.help.rescan"},
	{"p", "tui.help.pause"},
	{"y / Y", "tui.help.copy"},
	{"L", "tui.help.lang"},
	{"q, Ctrl+C", "tui.help.quit"},
	{"", "tui.help.observe"},
}

func (a *App) drawHelp() {
	s := a.scr
	w := min(a.w-4, 96)
	h := min(a.h-2, len(helpLines)+4)
	x := (a.w - w) / 2
	y := (a.h - h) / 2
	for j := y; j < y+h; j++ {
		for i := x; i < x+w; i++ {
			s.Set(i, j, ' ', stNormal)
		}
	}
	s.Box(x, y, w, h, a.tr("tui.help.title"), true)
	for i, hl := range helpLines {
		if i >= h-3 {
			break
		}
		row := y + 2 + i
		if hl[1] == "tui.help.mouse_key" {
			// Строка про мышь: «клавиша» тоже переводится.
			s.Text(x+4, row, 26, a.tr("tui.help.mouse"), stKey)
			s.Text(x+31, row, w-33, a.tr("tui.help.mouse_desc"), stNormal)
			continue
		}
		if hl[0] == "" {
			s.Text(x+2, row, w-4, a.tr(hl[1]), Style{FG: 75, BG: -1, Bold: true})
			continue
		}
		s.Text(x+4, row, 26, hl[0], stKey)
		s.Text(x+31, row, w-33, a.tr(hl[1]), stNormal)
	}
}

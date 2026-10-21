package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// seg — кусок строки с одним стилем; line — строка из кусков.
type seg struct {
	t  string
	st Style
}
type line []seg

// draw рисует кадр целиком и выводит его.
func (a *App) draw() {
	a.render()
	_ = a.scr.Flush(a.out)
}

// render раскладывает панели и рисует их в буфер (без вывода — удобно
// для тестов).
func (a *App) render() {
	if a.w < 20 || a.h < 8 {
		a.scr = newScreen(max(a.w, 1), max(a.h, 1))
		a.scr.Text(0, 0, a.w, "Окно слишком маленькое", stWarn)
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
func (a *App) layoutLeft(lw, contentH int) {
	statusH := 6
	a.rects[pStatus] = rect{0, 0, lw, statusH}
	avail := contentH - statusH
	small := min(max(avail/7, 3), 7)
	big := avail - small*4
	if big < 6 {
		small = 3
		big = avail - small*4
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
	a.drawStatus(a.rects[pStatus])
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
	s.Box(r.x, r.y, r.w, r.h, "[1] "+panelTitles[pStatus], a.panelActive(pStatus))
	iw := r.w - 4
	x := r.x + 2
	if a.data == nil {
		msg := "Загрузка…"
		if a.err != nil {
			msg = "Ошибка: " + a.err.Error()
		}
		s.Text(x, r.y+1, iw, msg, stErr)
		return
	}
	st := a.data.Status
	h := st.Host
	host := sanitize(h.Hostname)
	if st.Demo {
		host += " · ДЕМО"
	}
	s.Text(x, r.y+1, iw, fmt.Sprintf("%s · %s · %s", host, h.OS, h.Kernel), stBold)
	s.Text(x, r.y+2, iw, fmt.Sprintf("Скан %s (%d мс) · каждые %s · %s", st.Time.Local().Format("15:04:05"), st.DurationMs, secs(st.Interval), a.src.Describe()), stDim)
	cx := x
	for _, rk := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		n := st.Stats.ByRisk[rk]
		stl := riskStyle(rk)
		if n == 0 {
			stl = stDim
		}
		cx += s.Text(cx, r.y+3, x+iw-cx, fmt.Sprintf("%s %d  ", strings.TrimSpace(riskShort(rk)), n), stl)
	}
	line := fmt.Sprintf("Процессов %d · сокетов %d · система %d", st.Stats.Total, st.Stats.Sockets, st.SystemFindings)
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
	t := fmt.Sprintf("[%d] %s (%d)", p+1, panelTitles[p], a.count(p))
	if p == pProcs {
		if a.treeMode {
			t += " · дерево"
		} else {
			t += " · " + sortNames[a.sortMode]
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
		msg := "Пусто"
		if p == pSusp && l.filter == "" {
			msg = "Подозрительных процессов нет"
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
		return fit("РИСК    PID ПОЛЬЗ.   ИМЯ", w)
	case pProcs:
		h := "   PID ПОЛЬЗ.     CPU%    RAM РИСК ИМЯ"
		if w >= 90 {
			h += strings.Repeat(" ", 12) + "КОМАНДА"
		}
		return fit(h, w)
	case pNet:
		return fit("ПРОТ  ЛОКАЛЬНЫЙ             УДАЛЁННЫЙ             СОСТОЯНИЕ   ПРОЦЕСС", w)
	case pHist:
		return fit("ВРЕМЯ    СОБЫТИЕ      PID ИМЯ             ПОДРОБНОСТИ", w)
	case pSys:
		return fit("РИСК ПРОВЕРКА / ФАЙЛ", w)
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
			rest += " (удалён)"
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
		owner := "неизвестно"
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
			{fit(eventName(e.Type), 10) + " ", est},
			{fitLeft(pid, 6) + " ", stNormal},
			{fit(who, 15) + " ", stBold},
			{e.Details, stDim},
		}
	case pSys:
		f := a.system[i]
		return []seg{
			{riskShort(f.Risk.String()) + " ", riskStyle(f.Risk.String())},
			{f.Title + " ", stNormal},
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
	lines []line
}

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

func ago(t time.Time) string {
	if t.IsZero() || t.Year() < 2000 {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d д %d ч", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%d ч %d мин", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	}
	return fmt.Sprintf("%d с", int(d.Seconds()))
}

// mainContent возвращает заголовок и строки для панели подробностей в
// зависимости от активной панели слева.
func (a *App) mainContent(w int) (string, []line) {
	b := &lb{w: w}
	if a.data == nil {
		b.para("Нет данных. "+errText(a.err), stErr, 0)
		return "Подробности", b.lines
	}
	switch a.focus {
	case pStatus:
		a.overview(b)
		return "Обзор", b.lines
	case pNet:
		sk, ok := a.selSocket()
		if !ok {
			return "Сокет", nil
		}
		a.socketDetail(b, sk)
		return fmt.Sprintf("Сокет %s:%d", sk.LocalAddr, sk.LocalPort), b.lines
	case pSys:
		f, ok := a.selSystem()
		if !ok {
			b.para("Системных находок нет.", stDim, 0)
			return "Проверка", b.lines
		}
		a.systemDetail(b, f)
		return "Проверка · " + f.Path, b.lines
	case pHist:
		e, ok := a.selEvent()
		if !ok {
			return "Событие", nil
		}
		b.add(seg{fmtTime(e.Time) + "  ", stDim}, seg{eventName(e.Type), riskStyle(e.Risk.String())}, seg{"  " + e.Risk.String(), riskStyle(e.Risk.String())})
		b.para(e.Details, stNormal, 0)
		if e.Key == "" {
			return "Событие", b.lines
		}
	}
	p, ok := a.selectedProc()
	if !ok {
		b.para("Выберите процесс в списке слева.", stDim, 0)
		return "Процесс", b.lines
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
		b.para("Не удалось получить карточку: "+a.detailErr.Error(), stErr, 0)
		return
	}
	d := a.detail
	if d.Exited && d.Track != nil {
		t := d.Track
		b.add(seg{"Процесс завершился", stWarn})
		b.kv("Имя", t.Name)
		b.kv("Пользователь", t.User)
		b.kv("Путь", t.Exe)
		b.kv("Команда", t.Cmdline)
		b.kv("Впервые", fmtTime(t.FirstSeen))
		b.kv("Последний раз", fmtTime(t.LastSeen))
		b.kv("Последний риск", t.Risk.String())
		eventsBlock(b, d.Events)
		return
	}
	p := d.Process
	rs := p.Risk.String()
	b.add(seg{" " + rs + " ", Style{FG: 16, BG: riskStyle(rs).FG, Bold: true}}, seg{fmt.Sprintf("  %d балл. · %s · %s", p.Score, sanitize(p.User), sanitize(p.Name)), stBold})

	active, info := []model.Finding{}, []model.Finding{}
	for _, f := range p.Findings {
		if f.Category == model.CatInfo {
			info = append(info, f)
		} else {
			active = append(active, f)
		}
	}
	b.header("Оценка риска")
	b.para(p.Explanation, stNormal, 2)
	if len(active) > 0 {
		b.header("Признаки")
		for _, f := range active {
			findingBlock(b, f)
		}
	}
	if len(p.Recommendations) > 0 {
		b.header("Рекомендации по проверке")
		for _, r := range p.Recommendations {
			b.para("• "+r, stNormal, 2)
		}
	}
	b.header("Командная строка  (y — копировать, секреты замаскированы)")
	cmd := p.Cmdline
	if cmd == "" {
		cmd = "(пусто)"
	}
	b.para(cmd, Style{FG: 223, BG: -1}, 2)

	b.header("Основное")
	b.kv("PID / PPID", fmt.Sprintf("%d / %d", p.PID, p.PPID))
	b.kv("Пользователь", fmt.Sprintf("%s (UID %d, EUID %d, GID %d)", p.User, p.UID, p.EUID, p.GID))
	exe := p.Exe
	switch {
	case exe == "" && p.Kernel:
		exe = "поток ядра"
	case exe == "":
		exe = "недоступно"
	case p.ExeDeleted:
		exe += " (удалён)"
	}
	b.kv("Исполняемый файл", exe)
	if p.ExeInfo != nil {
		b.kv("Права файла", fmt.Sprintf("%s, владелец UID %d, %s", p.ExeInfo.Mode, p.ExeInfo.UID, fmtBytes(uint64(p.ExeInfo.Size))))
	}
	b.kv("Рабочий каталог", orDash(p.Cwd))
	b.kv("Запущен", fmtTime(p.StartTime)+" ("+ago(p.StartTime)+")")
	b.kv("Впервые замечен", fmtTime(p.FirstSeen))
	cpu := fmt.Sprintf("%.1f%%", p.CPUPercent)
	if p.CPUAverage {
		cpu += " (среднее с запуска)"
	}
	b.kv("CPU", cpu)
	b.kv("Память", fmt.Sprintf("%s RSS (%.1f%%), потоков %d, дескрипторов %d", fmtBytes(p.RSSBytes), p.MemPercent, p.Threads, p.FDCount))
	if len(p.EnvFlags) > 0 {
		b.kv("Окружение", strings.Join(p.EnvFlags, ", ")+" (значения не читаются)")
	}
	if p.ContainerRuntime != "" {
		b.kv("Контейнер", strings.TrimSpace(p.ContainerRuntime+" "+p.Container))
	}
	if len(p.ForeignNS) > 0 {
		b.kv("Другие namespaces", strings.Join(p.ForeignNS, ", "))
	}
	if len(p.Access) > 0 {
		b.kv("Нет доступа к", strings.Join(p.Access, ", "))
	}

	b.header("Цепочка запуска")
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
		b.para("Потомки: "+strings.Join(kids, ", "), stDim, 2)
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
	b.header(fmt.Sprintf("Сеть (TCP/UDP: %d, unix: %d)", len(inet), unix))
	for _, sk := range inet {
		segs := []seg{{fmt.Sprintf("  %-5s ", sk.Proto), stNormal}, {sk.LocalAddr, stAddr}, {fmt.Sprintf(":%d", sk.LocalPort), stNormal}}
		if sk.RemotePort != 0 {
			segs = append(segs, seg{" → ", stNormal}, seg{sk.RemoteAddr, stAddr}, seg{fmt.Sprintf(":%d", sk.RemotePort), stNormal})
		}
		b.add(append(segs, seg{" ", stNormal}, seg{sk.State, stAccent})...)
	}
	if len(p.Files) > 0 {
		b.header(fmt.Sprintf("Открытые файлы (%d из %d)", len(p.Files), p.FDCount))
		for i, f := range p.Files {
			if i >= 40 {
				b.add(seg{fmt.Sprintf("  … ещё %d (полный список — JSON, клавиша Y)", len(p.Files)-40), stDim})
				break
			}
			b.add(seg{fmt.Sprintf("  %4d %-7s ", f.FD, f.Kind), stDim}, seg{sanitize(f.Target), stNormal})
		}
	}
	if len(info) > 0 {
		b.header("Справочно")
		for _, f := range info {
			b.para("• "+f.Title+": "+strings.Join(f.Evidence, "; "), stDim, 2)
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
	tags := fmt.Sprintf("  [%s, +%d", detect.CategoryTitle(f.Category), f.Weight)
	if f.Strong {
		tags += ", сильный"
	}
	if f.Suppressed {
		tags += ", подавлен allowlist"
	}
	tags += "]"
	b.add(seg{"  " + mark + " ", st}, seg{sanitize(f.Title), st}, seg{tags, stDim})
	for _, e := range f.Evidence {
		b.para("· "+e, Style{FG: 250, BG: -1}, 6)
	}
	if f.Recommendation != "" {
		b.para("→ "+f.Recommendation, stDim, 6)
	}
}

func eventsBlock(b *lb, evs []model.Event) {
	if len(evs) == 0 {
		return
	}
	b.header("История процесса")
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		b.add(seg{"  " + e.Time.Local().Format("02.01 15:04:05") + " ", stDim}, seg{fit(eventName(e.Type), 11), riskStyle(e.Risk.String())}, seg{sanitize(e.Details), stNormal})
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (a *App) socketDetail(b *lb, sk model.Socket) {
	b.kv("Протокол", sk.Proto)
	b.kvAddr("Локальный адрес", sk.LocalAddr, sk.LocalPort)
	if sk.RemotePort != 0 {
		b.kvAddr("Удалённый адрес", sk.RemoteAddr, sk.RemotePort)
	}
	b.kv("Состояние", sk.State)
	b.kv("inode", strconv.FormatUint(sk.Inode, 10))
	b.kv("Netns", orDash(sk.NetNS))
	if sk.ProcKey == "" {
		b.blank()
		b.para("Владелец не найден: нет прав на /proc/PID/fd, сокет ядра или соединение уже закрыто (TIME_WAIT).", stDim, 2)
		return
	}
	b.blank()
	a.processDetail(b, sk.ProcKey)
}

func (a *App) systemDetail(b *lb, f model.SystemFinding) {
	rs := f.Risk.String()
	b.add(seg{" " + rs + " ", Style{FG: 16, BG: riskStyle(rs).FG, Bold: true}}, seg{"  " + sanitize(f.Title), stBold})
	b.kv("Файл", f.Path)
	b.kv("Изменён", fmtTime(f.ModTime))
	b.kv("Правило", f.ID)
	b.header("Факты")
	for _, e := range f.Evidence {
		b.para("· "+e, stNormal, 2)
	}
	if f.Recommendation != "" {
		b.header("Рекомендация")
		b.para(f.Recommendation, stNormal, 2)
	}
}

// overview — содержимое подробностей для панели «Сводка».
func (a *App) overview(b *lb) {
	st := a.data.Status
	h := st.Host
	b.add(seg{"ServerSecurityGo " + st.Version, stBold})
	b.para("Только наблюдение: приложение не завершает процессы, не удаляет файлы и не блокирует соединения.", stDim, 0)
	b.header("Сервер")
	b.kv("Хост", h.Hostname)
	b.kv("ОС / ядро", h.OS+" / "+h.Kernel)
	b.kv("Загрузка", fmtTime(h.BootTime)+" ("+ago(h.BootTime)+" назад)")
	b.kv("Память", fmtBytes(h.MemTotal))
	b.kv("Сканер от root", yesNo(h.IsRoot))
	b.kv("В контейнере", yesNo(h.InContainer))
	b.header("Источник данных")
	b.kv("Источник", a.src.Describe())
	b.kv("Последнее сканирование", fmtTime(st.Time)+fmt.Sprintf(" (%d мс)", st.DurationMs))
	b.kv("Обновление экрана", "каждые "+a.refresh.String()+pausedText(a.paused))
	b.header("Риски")
	for _, rk := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		b.add(seg{"  " + fit(rk, 10), riskStyle(rk)}, seg{strconv.Itoa(st.Stats.ByRisk[rk]), stNormal})
	}
	if len(st.Warnings) > 0 {
		b.header("Ограничения сканирования")
		for _, w := range st.Warnings {
			b.para("⚠ "+w, stWarn, 2)
		}
	}
	b.header("Быстрый старт")
	b.para("2 — подозрительные процессы, 3 — все процессы (t — дерево, s — сортировка), 4 — сеть, 5 — история, 6 — проверки закрепления. Enter или → — подробности, / — фильтр, ? — все клавиши.", stNormal, 2)
}

func yesNo(v bool) string {
	if v {
		return "да"
	}
	return "нет"
}

func pausedText(p bool) string {
	if p {
		return " (пауза)"
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
		cx := s.Text(0, y, a.w, "Фильтр ("+panelTitles[a.focus]+"): ", stKey)
		cx += s.Text(cx, y, a.w-cx, l.filter, stBold)
		s.Text(cx, y, a.w-cx, "█   Enter — применить, Esc — сбросить", stDim)
		return
	}
	var hints [][2]string
	switch {
	case a.inMain:
		hints = [][2]string{{"↑↓", "прокрутка"}, {"PgUp/PgDn", "страница"}, {"←/Esc", "к списку"}, {"y", "копировать cmd"}, {"Y", "JSON"}, {"+", "во весь экран"}}
	case a.focus == pProcs:
		hints = [][2]string{{"↑↓", "выбор"}, {"Enter", "подробности"}, {"/", "фильтр"}, {"s", "сортировка"}, {"t", "дерево"}, {"K", "потоки ядра"}, {"y", "копировать"}}
	default:
		hints = [][2]string{{"↑↓", "выбор"}, {"1-6/Tab", "панели"}, {"Enter", "подробности"}, {"/", "фильтр"}, {"r", "сканировать"}, {"y", "копировать"}}
	}
	hints = append(hints, [2]string{"?", "помощь"}, [2]string{"q", "выход"})
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
		right, rst = "ошибка: "+a.err.Error(), stErr
	case a.paused:
		right, rst = "⏸ пауза (p)", stWarn
	default:
		right = "⟳ " + a.refresh.String()
	}
	rw := min(strWidth(right), a.w-cx)
	if rw > 0 {
		s.Text(a.w-rw, y, rw, right, rst)
	}
}

var helpLines = [][2]string{
	{"", "Навигация"},
	{"1 … 6", "перейти к панели (сводка, подозрительные, процессы, сеть, история, система)"},
	{"Tab / Shift+Tab, [ ]", "следующая / предыдущая панель"},
	{"↑ ↓ / j k", "выбор строки (в подробностях — прокрутка)"},
	{"PgUp PgDn, Ctrl+U Ctrl+D", "страница вверх / вниз"},
	{"Home End / g G", "в начало / в конец"},
	{"Enter, →, l", "перейти в подробности"},
	{"←, h, Esc", "вернуться к списку; Esc также сбрасывает фильтр"},
	{"+ / z", "развернуть активную сторону на весь экран"},
	{"мышь", "клик — выбор, колесо — прокрутка"},
	{"", "Действия"},
	{"/", "фильтр активной панели (имя, PID, путь, пользователь, признак, риск)"},
	{"s", "сортировка процессов: риск, CPU, память, PID, имя"},
	{"t", "дерево процессов вкл/выкл"},
	{"K", "показать / скрыть потоки ядра"},
	{"r", "просканировать сейчас"},
	{"p", "пауза автообновления"},
	{"y / Y", "копировать командную строку / JSON (OSC 52, работает по SSH)"},
	{"q, Ctrl+C", "выход"},
	{"", "Приложение только наблюдает: ничего не завершает, не удаляет и не блокирует."},
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
	s.Box(x, y, w, h, "Клавиши · Esc — закрыть", true)
	for i, hl := range helpLines {
		if i >= h-3 {
			break
		}
		row := y + 2 + i
		if hl[0] == "" {
			s.Text(x+2, row, w-4, hl[1], Style{FG: 75, BG: -1, Bold: true})
			continue
		}
		s.Text(x+4, row, 26, hl[0], stKey)
		s.Text(x+31, row, w-33, hl[1], stNormal)
	}
}

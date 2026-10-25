package tui

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// Копирование и работа с текстом терминала.
//
// Интерфейс включает режим мыши, и терминал не даёт выделять текст.
// Поэтому есть три способа забрать текст:
//   - y — главное значение выбранного элемента (IP, команда, адрес),
//     c — меню со всем, что можно скопировать; оба через OSC 52;
//   - v — текстовый режим: подробности обычным текстом без рамок и
//     переносов (терминал сам переносит длинные строки, и выделенная
//     команда копируется одной строкой). Работает и там, где OSC 52 нет
//     (Terminal.app на macOS);
//   - m — выключить мышь: работает обычное выделение терминала.

// Управляющие последовательности режима мыши (нажатия + SGR 1006).
const (
	mouseOnSeq  = "\x1b[?1000h\x1b[?1006h"
	mouseOffSeq = "\x1b[?1000l\x1b[?1006l"
)

// copyItem — то, что можно скопировать: подпись и значение.
type copyItem struct {
	label string
	value string
}

// copyMenu — открытое меню копирования.
type copyMenu struct {
	items  []copyItem
	cursor int
}

// copyItems — что можно скопировать из подробностей выбранного элемента.
// Первым идёт главное значение — его копирует y.
func (a *App) copyItems() []copyItem {
	var out []copyItem
	seen := map[string]bool{}
	add := func(key, v string) {
		v = strings.TrimSpace(v)
		if v == "" || v == "—" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, copyItem{label: a.tr(key), value: v})
	}
	if a.data == nil {
		return nil
	}
	switch a.focus {
	case pAudit:
		if c, ok := a.selCheck(); ok {
			add("tui.copy.fix", c.FixCommand)
			for _, e := range c.Evidence {
				add("tui.copy.fact", a.txt(e))
			}
			add("tui.copy.rec", a.txt(c.Recommendation))
			add("tui.copy.rule", c.ID)
		}
		return out
	case pF2B:
		if b, ok := a.selBan(); ok {
			add("tui.copy.ip", b.IP)
			add("tui.copy.unban", b.UnbanCommand)
			add("tui.copy.jail", b.Jail)
		}
		// Самые активные адреса — их часто нужно проверить или
		// заблокировать вручную.
		if f := a.data.Fail2ban; f != nil {
			for i, s := range f.Top {
				if i >= 10 {
					break
				}
				add("tui.copy.top_ip", s.Addr)
			}
		}
		return out
	case pSys:
		if f, ok := a.selSystem(); ok {
			add("tui.copy.path", f.Path)
			for _, e := range f.Evidence {
				add("tui.copy.fact", a.txt(e))
			}
			add("tui.copy.rec", a.txt(f.Recommendation))
		}
		return out
	case pNet:
		if sk, ok := a.selSocket(); ok {
			if sk.RemotePort != 0 {
				add("tui.copy.remote_ip", sk.RemoteAddr)
				add("tui.copy.remote", endpoint(sk.RemoteAddr, sk.RemotePort))
			}
			add("tui.copy.local", endpoint(sk.LocalAddr, sk.LocalPort))
		}
	case pPorts:
		if e, ok := a.selPort(); ok {
			add("tui.copy.endpoint", exposureEndpoint(e))
			add("tui.copy.ip", e.Addr)
			for _, m := range e.Evidence {
				add("tui.copy.fact", a.txt(m))
			}
			add("tui.copy.rec", a.txt(e.Recommendation))
		}
	case pHist:
		if e, ok := a.selEvent(); ok {
			add("tui.copy.event", a.txt(e.Details))
		}
	case pStatus:
		return nil
	}
	a.procCopyItems(add)
	return out
}

// procCopyItems — командная строка, путь и адреса процесса, к которому
// относится выбранный элемент.
func (a *App) procCopyItems(add func(key, v string)) {
	p, ok := a.selectedProc()
	if !ok {
		return
	}
	add("tui.copy.cmdline", p.Cmdline)
	add("tui.copy.exe", p.Exe)
	add("tui.copy.pid", strconv.Itoa(p.PID))
	a.ensureDetail(p.Key)
	if a.detailErr != nil || a.detail == nil || a.detail.Process == nil {
		return
	}
	d := a.detail.Process
	add("tui.copy.cwd", d.Cwd)
	for _, sk := range d.Sockets {
		if sk.Proto != "unix" && sk.RemotePort != 0 && !model.IsLoopback(sk.RemoteAddr) {
			add("tui.copy.remote_ip", sk.RemoteAddr)
		}
	}
}

// endpoint — «адрес:порт», IPv6 в квадратных скобках.
func endpoint(addr string, port int) string {
	return exposureEndpoint(model.Exposure{Addr: addr, Port: port})
}

// copyValue копирует значение через OSC 52 и сообщает, что именно.
func (a *App) copyValue(it copyItem) {
	a.osc52(it.value)
	a.flash(a.tr("tui.flash.copied", it.label), false)
}

// copyMain — клавиша y: главное значение выбранного элемента.
func (a *App) copyMain() {
	items := a.copyItems()
	if len(items) == 0 {
		a.flash(a.tr("tui.flash.nothing"), true)
		return
	}
	a.copyValue(items[0])
}

// openCopyMenu — клавиша c: меню копирования.
func (a *App) openCopyMenu() {
	items := a.copyItems()
	if len(items) == 0 {
		a.flash(a.tr("tui.flash.nothing"), true)
		return
	}
	a.menu = &copyMenu{items: items}
}

// menuKey — клавиши открытого меню копирования.
func (a *App) menuKey(k Key) {
	m := a.menu
	pick := func(i int) {
		if i >= 0 && i < len(m.items) {
			a.copyValue(m.items[i])
			a.menu = nil
		}
	}
	switch k.Kind {
	case KeyUp:
		m.cursor = max(m.cursor-1, 0)
	case KeyDown:
		m.cursor = min(m.cursor+1, len(m.items)-1)
	case KeyHome:
		m.cursor = 0
	case KeyEnd:
		m.cursor = len(m.items) - 1
	case KeyEnter:
		pick(m.cursor)
	case KeyEsc:
		a.menu = nil
	case KeyRune:
		switch r := k.Rune; {
		case r == 'k':
			m.cursor = max(m.cursor-1, 0)
		case r == 'j':
			m.cursor = min(m.cursor+1, len(m.items)-1)
		case r == 'y':
			pick(m.cursor)
		case r >= '1' && r <= '9':
			pick(int(r - '1'))
		case r == 'q' || r == 'c':
			a.menu = nil
		}
	}
}

// drawCopyMenu рисует меню копирования поверх интерфейса.
func (a *App) drawCopyMenu() {
	s, m := a.scr, a.menu
	w := min(a.w-4, 110)
	h := min(a.h-2, len(m.items)+4)
	x, y := (a.w-w)/2, (a.h-h)/2
	for j := y; j < y+h; j++ {
		for i := x; i < x+w; i++ {
			s.Set(i, j, ' ', stNormal)
		}
	}
	s.Box(x, y, w, h, a.tr("tui.copy.title"), true)
	s.Text(x+2, y+1, w-4, a.tr("tui.copy.hint"), stDim)
	rows := h - 3
	off := max(0, m.cursor-rows+1)
	lw := 0
	for _, it := range m.items {
		lw = max(lw, strWidth(it.label))
	}
	lw = min(lw, 22)
	for i := 0; i < rows && off+i < len(m.items); i++ {
		idx := off + i
		it := m.items[idx]
		row := y + 2 + i
		num := "   "
		if idx < 9 {
			num = fmt.Sprintf("%d  ", idx+1)
		}
		cx := s.Text(x+2, row, w-4, num, stKey)
		cx += s.Text(x+2+cx, row, w-4-cx, fit(it.label, lw)+"  ", stDim)
		s.Text(x+2+cx, row, w-4-cx, sanitize(it.value), stNormal)
		if idx == m.cursor {
			s.Fill(x+1, row, w-2, 1, stSelFocus)
		}
	}
}

// toggleMouse — клавиша m: выключить мышь, чтобы выделять текст средствами
// терминала, или включить обратно.
func (a *App) toggleMouse() {
	a.mouseOff = !a.mouseOff
	if a.mouseOff {
		io.WriteString(a.out, mouseOffSeq)
		a.flash(a.tr("tui.flash.mouse_off"), false)
	} else {
		io.WriteString(a.out, mouseOnSeq)
		a.flash(a.tr("tui.flash.mouse_on"), false)
	}
}

// showPlain — клавиша v: подробности обычным текстом в основном экране
// терминала. Строки не переносятся и не обрамляются, цвета нет: длинную
// команду терминал перенесёт сам и при выделении скопирует одной
// строкой. Любая клавиша возвращает интерфейс.
func (a *App) showPlain() {
	if a.data == nil {
		a.flash(a.tr("tui.flash.nothing"), true)
		return
	}
	title, lines := a.mainContent(1 << 16)
	var b strings.Builder
	// Основной экран, курсор виден, мышь выключена — работает обычное
	// выделение. В сыром режиме терминала перевод строки — \r\n.
	b.WriteString(mouseOffSeq + "\x1b[?1049l\x1b[?25h\x1b[0m\r\n")
	b.WriteString(sanitize(title) + "\r\n\r\n")
	for _, l := range lines {
		var s strings.Builder
		for _, sg := range l {
			s.WriteString(sg.t)
		}
		b.WriteString(strings.TrimRight(sanitize(s.String()), " ") + "\r\n")
	}
	b.WriteString("\r\n" + a.tr("tui.plain.back") + "\r\n")
	io.WriteString(a.out, b.String())
	a.plain = true
}

// leavePlain возвращает интерфейс после текстового режима.
func (a *App) leavePlain() {
	a.plain = false
	seq := "\x1b[?1049h\x1b[?25l"
	if !a.mouseOff {
		seq += mouseOnSeq
	}
	io.WriteString(a.out, seq)
}

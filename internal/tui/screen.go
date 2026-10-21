package tui

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

// Style — оформление символа. Цвета — номера палитры xterm-256
// (-1 — цвет терминала по умолчанию).
type Style struct {
	FG, BG  int
	Bold    bool
	Dim     bool
	Reverse bool
	// KeepFG — цвет текста сохраняется и в выделенной строке (Fill меняет
	// только фон).
	KeepFG bool
}

// Базовые стили интерфейса. Цвета подобраны так, чтобы читаться и на
// тёмной, и на светлой теме терминала.
var (
	stNormal   = Style{FG: -1, BG: -1}
	stDim      = Style{FG: 244, BG: -1}
	stBold     = Style{FG: -1, BG: -1, Bold: true}
	stTitle    = Style{FG: -1, BG: -1, Bold: true}
	stActive   = Style{FG: 76, BG: -1, Bold: true} // рамка активной панели (зелёная, как в lazygit)
	stBorder   = Style{FG: 244, BG: -1}
	stKey      = Style{FG: 75, BG: -1, Bold: true} // клавиши в подсказках
	stAccent   = Style{FG: 75, BG: -1}
	stWarn     = Style{FG: 214, BG: -1}
	stErr      = Style{FG: 203, BG: -1, Bold: true}
	stOK       = Style{FG: 76, BG: -1}
	stSelFocus = Style{FG: 255, BG: 24, Bold: true} // выбранная строка в активной панели
	stSelBlur  = Style{FG: -1, BG: 237}             // выбранная строка в неактивной панели
	// stAddr — IP-адреса. Termius и похожие клиенты сами красят IP в розовый,
	// но только при части перерисовок: при прокрутке адрес получал цвет
	// терминала по умолчанию и «мигал». Явный близкий розовый делает цвет
	// одинаковым в обоих случаях; в выделенной строке он тоже сохраняется.
	stAddr = Style{FG: 168, BG: -1, KeepFG: true}
)

// riskStyle — цвет уровня риска.
func riskStyle(r string) Style {
	switch r {
	case "CRITICAL":
		return Style{FG: 196, BG: -1, Bold: true}
	case "HIGH":
		return Style{FG: 208, BG: -1, Bold: true}
	case "MEDIUM":
		return Style{FG: 178, BG: -1}
	case "LOW":
		return Style{FG: 71, BG: -1}
	default:
		return Style{FG: 244, BG: -1}
	}
}

// riskShort — короткая метка уровня для узких колонок.
func riskShort(r string) string {
	switch r {
	case "CRITICAL":
		return "CRIT"
	case "MEDIUM":
		return "MED "
	case "INFO":
		return "INFO"
	case "HIGH":
		return "HIGH"
	case "LOW":
		return "LOW "
	}
	return r
}

type cell struct {
	r  rune
	st Style
}

// Screen — буфер кадра. Всё рисуется в буфер, затем кадр целиком
// выводится одной записью — так нет мерцания и через SSH.
type Screen struct {
	W, H  int
	cells []cell
}

func newScreen(w, h int) *Screen {
	s := &Screen{W: w, H: h, cells: make([]cell, w*h)}
	s.Clear()
	return s
}

// Clear заполняет буфер пробелами.
func (s *Screen) Clear() {
	for i := range s.cells {
		s.cells[i] = cell{' ', stNormal}
	}
}

// Set ставит символ с обрезкой по границам экрана.
func (s *Screen) Set(x, y int, r rune, st Style) {
	if x < 0 || y < 0 || x >= s.W || y >= s.H {
		return
	}
	s.cells[y*s.W+x] = cell{r, st}
}

// Text выводит строку начиная с (x, y), не дальше maxW символов.
// Возвращает число занятых колонок.
func (s *Screen) Text(x, y, maxW int, text string, st Style) int {
	used := 0
	for _, r := range text {
		w := runeWidth(r)
		if w == 0 {
			continue
		}
		if used+w > maxW {
			break
		}
		s.Set(x+used, y, r, st)
		if w == 2 {
			s.Set(x+used+1, y, 0, st) // вторая половина широкого символа
		}
		used += w
	}
	return used
}

// Fill закрашивает прямоугольник стилем (для выделения строки).
func (s *Screen) Fill(x, y, w, h int, st Style) {
	for j := y; j < y+h; j++ {
		for i := x; i < x+w; i++ {
			if i >= 0 && j >= 0 && i < s.W && j < s.H {
				c := &s.cells[j*s.W+i]
				c.st.BG = st.BG
				if st.FG != -1 && !c.st.KeepFG {
					c.st.FG = st.FG
				}
				c.st.Bold = c.st.Bold || st.Bold
			}
		}
	}
}

// Box рисует рамку с заголовком в верхней границе, как в lazygit.
func (s *Screen) Box(x, y, w, h int, title string, active bool) {
	if w < 2 || h < 2 {
		return
	}
	st := stBorder
	if active {
		st = stActive
	}
	for i := x + 1; i < x+w-1; i++ {
		s.Set(i, y, '─', st)
		s.Set(i, y+h-1, '─', st)
	}
	for j := y + 1; j < y+h-1; j++ {
		s.Set(x, j, '│', st)
		s.Set(x+w-1, j, '│', st)
	}
	s.Set(x, y, '╭', st)
	s.Set(x+w-1, y, '╮', st)
	s.Set(x, y+h-1, '╰', st)
	s.Set(x+w-1, y+h-1, '╯', st)
	if title != "" && w > 4 {
		tst := stTitle
		if active {
			tst = stActive
		}
		s.Text(x+1, y, w-2, " "+title+" ", tst)
	}
}

// Flush выводит кадр. SGR-последовательности пишутся только при смене
// стиля.
func (s *Screen) Flush(out io.Writer) error {
	var b bytes.Buffer
	b.Grow(s.W * s.H * 2)
	b.WriteString("\x1b[H")
	cur := Style{FG: -2}
	for y := 0; y < s.H; y++ {
		fmt.Fprintf(&b, "\x1b[%d;1H", y+1)
		for x := 0; x < s.W; x++ {
			c := s.cells[y*s.W+x]
			if c.r == 0 {
				continue // правая половина широкого символа уже выведена
			}
			if c.st != cur {
				b.WriteString(sgr(c.st))
				cur = c.st
			}
			b.WriteRune(c.r)
		}
	}
	b.WriteString("\x1b[0m")
	_, err := out.Write(b.Bytes())
	return err
}

func sgr(st Style) string {
	var p []string
	p = append(p, "0")
	if st.Bold {
		p = append(p, "1")
	}
	if st.Dim {
		p = append(p, "2")
	}
	if st.Reverse {
		p = append(p, "7")
	}
	if st.FG >= 0 {
		p = append(p, fmt.Sprintf("38;5;%d", st.FG))
	}
	if st.BG >= 0 {
		p = append(p, fmt.Sprintf("48;5;%d", st.BG))
	}
	return "\x1b[" + strings.Join(p, ";") + "m"
}

// String возвращает содержимое буфера как текст (для тестов).
func (s *Screen) String() string {
	var b strings.Builder
	for y := 0; y < s.H; y++ {
		for x := 0; x < s.W; x++ {
			if r := s.cells[y*s.W+x].r; r != 0 {
				b.WriteRune(r)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// runeWidth — ширина символа в колонках: 0 для управляющих и
// комбинируемых, 2 для широких (CJK, эмодзи), иначе 1. Кириллица и
// латиница — 1.
func runeWidth(r rune) int {
	switch {
	case r == 0 || r < 32 || (r >= 0x7f && r < 0xa0) || model.InvisibleRune(r):
		return 0
	case unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r):
		return 0
	case r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) || (r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) || (r >= 0xfe30 && r <= 0xfe4f) || (r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) || (r >= 0x1f300 && r <= 0x1faff) || (r >= 0x20000 && r <= 0x3fffd)):
		return 2
	}
	return 1
}

// strWidth — ширина строки в колонках.
func strWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

// fit обрезает строку до ширины w (с «…») и дополняет пробелами.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if strWidth(s) <= w {
		return s + strings.Repeat(" ", w-strWidth(s))
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := runeWidth(r)
		if used+rw > w-1 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	b.WriteString("…")
	used++
	return b.String() + strings.Repeat(" ", max(0, w-used))
}

// fitLeft — как fit, но выравнивание по правому краю (для чисел).
func fitLeft(s string, w int) string {
	if strWidth(s) >= w {
		return fit(s, w)
	}
	return strings.Repeat(" ", w-strWidth(s)) + s
}

// wrap разбивает текст на строки шириной не больше w, по словам.
// Слишком длинные слова (пути, cmdline) режутся посимвольно.
func wrap(text string, w int) []string {
	if w <= 1 {
		return []string{text}
	}
	var out []string
	for _, para := range strings.Split(text, "\n") {
		line := ""
		lw := 0
		for _, word := range strings.Fields(para) {
			ww := strWidth(word)
			for ww > w { // режем длинное слово
				if lw > 0 {
					out = append(out, line)
					line, lw = "", 0
				}
				head, rest := splitWidth(word, w)
				out = append(out, head)
				word, ww = rest, strWidth(rest)
			}
			switch {
			case lw == 0:
				line, lw = word, ww
			case lw+1+ww <= w:
				line += " " + word
				lw += 1 + ww
			default:
				out = append(out, line)
				line, lw = word, ww
			}
		}
		out = append(out, line)
	}
	return out
}

func splitWidth(s string, w int) (string, string) {
	used := 0
	for i, r := range s {
		rw := runeWidth(r)
		if used+rw > w {
			return s[:i], s[i:]
		}
		used += rw
	}
	return s, ""
}

// sanitize убирает управляющие и невидимые символы из строк, пришедших из
// системы: имя процесса или cmdline могут содержать ESC-последовательности,
// которые иначе выполнил бы терминал, и символы направления текста,
// меняющие вид строки (см. view.Printable).
func sanitize(s string) string { return view.Printable(s) }

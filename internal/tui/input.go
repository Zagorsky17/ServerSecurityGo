package tui

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// KeyKind — тип события ввода.
type KeyKind int

const (
	KeyRune KeyKind = iota // обычный символ (Rune)
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyPgUp
	KeyPgDn
	KeyHome
	KeyEnd
	KeyEnter
	KeyEsc
	KeyTab
	KeyBackTab
	KeyBackspace
	KeyCtrlC
	KeyCtrlD
	KeyCtrlU
	KeyMouse
	KeyUnknown
)

// Key — нажатие клавиши или событие мыши.
type Key struct {
	Kind KeyKind
	Rune rune
	// Для мыши: кнопка (0 — левая, 64/65 — колесо вверх/вниз),
	// координаты (с нуля) и признак нажатия.
	Button int
	X, Y   int
	Press  bool
}

// parseKeys разбирает прочитанный из терминала блок байтов. Один блок
// может содержать несколько нажатий (быстрый ввод, вставка текста).
func parseKeys(b []byte) []Key {
	var keys []Key
	for len(b) > 0 {
		k, n := parseOne(b)
		if n <= 0 {
			n = 1
		}
		keys = append(keys, k)
		b = b[n:]
	}
	return keys
}

func parseOne(b []byte) (Key, int) {
	c := b[0]
	switch {
	case c == 0x1b:
		if len(b) == 1 {
			return Key{Kind: KeyEsc}, 1
		}
		if b[1] == '[' || b[1] == 'O' {
			return parseCSI(b)
		}
		// Alt+клавиша: игнорируем Alt, отдаём саму клавишу как Esc.
		return Key{Kind: KeyEsc}, 1
	case c == '\r' || c == '\n':
		return Key{Kind: KeyEnter}, 1
	case c == '\t':
		return Key{Kind: KeyTab}, 1
	case c == 0x7f || c == 0x08:
		return Key{Kind: KeyBackspace}, 1
	case c == 0x03:
		return Key{Kind: KeyCtrlC}, 1
	case c == 0x04:
		return Key{Kind: KeyCtrlD}, 1
	case c == 0x15:
		return Key{Kind: KeyCtrlU}, 1
	case c < 0x20:
		return Key{Kind: KeyUnknown}, 1
	}
	r, n := utf8.DecodeRune(b)
	return Key{Kind: KeyRune, Rune: r}, n
}

// parseCSI разбирает последовательности ESC [ ... и ESC O ...
// (стрелки, Home/End, PgUp/PgDn, Shift+Tab, мышь SGR 1006, urxvt 1015 и
// старый формат X10).
func parseCSI(b []byte) (Key, int) {
	// Мышь в старом формате X10 (ESC [ M Cb Cx Cy): так её шлют терминалы
	// без SGR 1006, например Terminal.app на macOS. Три байта после M —
	// не текст, а кнопка и координаты плюс 32; без этой ветки они
	// разбирались бы как нажатия клавиш.
	if b[1] == '[' && len(b) >= 3 && b[2] == 'M' {
		if len(b) < 6 {
			return Key{Kind: KeyUnknown}, len(b)
		}
		return legacyMouse(int(b[3])-32, int(b[4])-32, int(b[5])-32), 6
	}
	if b[1] == 'O' && len(b) >= 3 { // режим «application cursor»
		switch b[2] {
		case 'A':
			return Key{Kind: KeyUp}, 3
		case 'B':
			return Key{Kind: KeyDown}, 3
		case 'C':
			return Key{Kind: KeyRight}, 3
		case 'D':
			return Key{Kind: KeyLeft}, 3
		case 'H':
			return Key{Kind: KeyHome}, 3
		case 'F':
			return Key{Kind: KeyEnd}, 3
		}
		return Key{Kind: KeyUnknown}, 3
	}
	// Ищем завершающий байт последовательности (0x40..0x7e).
	end := -1
	for i := 2; i < len(b); i++ {
		if b[i] >= 0x40 && b[i] <= 0x7e {
			end = i
			break
		}
	}
	if end < 0 {
		return Key{Kind: KeyUnknown}, len(b)
	}
	params := string(b[2:end])
	final := b[end]
	n := end + 1
	if strings.HasPrefix(params, "<") && (final == 'M' || final == 'm') {
		parts := strings.Split(params[1:], ";")
		if len(parts) == 3 {
			btn, _ := strconv.Atoi(parts[0])
			x, _ := strconv.Atoi(parts[1])
			y, _ := strconv.Atoi(parts[2])
			return Key{Kind: KeyMouse, Button: btn, X: x - 1, Y: y - 1, Press: final == 'M'}, n
		}
		return Key{Kind: KeyUnknown}, n
	}
	// urxvt 1015: ESC [ Cb ; Cx ; Cy M — числа десятичные, кнопка плюс 32.
	if final == 'M' && strings.Count(params, ";") == 2 {
		parts := strings.Split(params, ";")
		cb, e1 := strconv.Atoi(parts[0])
		x, e2 := strconv.Atoi(parts[1])
		y, e3 := strconv.Atoi(parts[2])
		if e1 == nil && e2 == nil && e3 == nil {
			return legacyMouse(cb-32, x, y), n
		}
		return Key{Kind: KeyUnknown}, n
	}
	switch final {
	case 'A':
		return Key{Kind: KeyUp}, n
	case 'B':
		return Key{Kind: KeyDown}, n
	case 'C':
		return Key{Kind: KeyRight}, n
	case 'D':
		return Key{Kind: KeyLeft}, n
	case 'H':
		return Key{Kind: KeyHome}, n
	case 'F':
		return Key{Kind: KeyEnd}, n
	case 'Z':
		return Key{Kind: KeyBackTab}, n
	case '~':
		switch params {
		case "1", "7":
			return Key{Kind: KeyHome}, n
		case "4", "8":
			return Key{Kind: KeyEnd}, n
		case "5":
			return Key{Kind: KeyPgUp}, n
		case "6":
			return Key{Kind: KeyPgDn}, n
		}
	}
	return Key{Kind: KeyUnknown}, n
}

// legacyMouse — событие мыши в форматах X10 и urxvt: cb — кнопка с
// модификаторами (Shift 4, Meta 8, Ctrl 16), x и y — с единицы. Отпускание
// кнопки в этих форматах — код 3 без номера кнопки.
func legacyMouse(cb, x, y int) Key {
	if cb < 0 || x < 1 || y < 1 {
		return Key{Kind: KeyUnknown}
	}
	btn := cb &^ (4 | 8 | 16)
	if btn&^32 == 3 {
		return Key{Kind: KeyMouse, Button: 0, X: x - 1, Y: y - 1, Press: false}
	}
	return Key{Kind: KeyMouse, Button: btn &^ 32, X: x - 1, Y: y - 1, Press: true}
}

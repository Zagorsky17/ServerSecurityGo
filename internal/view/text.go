package view

import (
	"strings"
	"unicode/utf8"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// Printable готовит строку из системы (имя процесса, cmdline, путь) к
// выводу в терминал: табуляция и перевод строки становятся пробелом,
// управляющие символы (ESC-последовательности выполнил бы терминал),
// невалидный UTF-8 и невидимые символы форматирования (model.InvisibleRune)
// — видимым «�».
func Printable(s string) string {
	if !strings.ContainsFunc(s, needsReplace) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(' ')
		case needsReplace(r):
			b.WriteRune('�')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsReplace(r rune) bool {
	return r < 32 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError || model.InvisibleRune(r)
}

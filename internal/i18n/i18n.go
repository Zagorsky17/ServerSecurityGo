// Пакет i18n — перевод видимых пользователю текстов на русский и
// английский.
//
// Сканер работает один раз, а смотреть результат могут одновременно на
// разных языках (браузер на английском, терминал на русском), и язык
// можно переключить на лету. Поэтому тексты признаков, событий и
// предупреждений хранятся не готовой строкой, а сообщением Msg: ключ
// каталога и аргументы. Строка собирается при выводе, на языке
// конкретного клиента: в Go — Msg.In, в веб-панели — тем же каталогом,
// который отдаёт сервер (static/i18n.js).
//
// Шаблоны в каталоге используют плейсхолдеры {0}, {1}, … вместо
// fmt-глаголов: в английском порядок слов бывает другим, а такой формат
// одинаково просто разобрать в Go и в JavaScript.
package i18n

import (
	"os"
	"strings"
	"sync/atomic"
)

// Lang — язык интерфейса.
type Lang string

const (
	RU Lang = "ru"
	EN Lang = "en"
)

// Langs — все поддерживаемые языки в порядке показа в переключателе.
var Langs = []Lang{RU, EN}

// Parse разбирает код языка ("ru", "EN", "en-US") без учёта регистра.
// Пустая строка и неизвестные языки — false.
func Parse(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "-_.@"); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "ru":
		return RU, true
	case "en":
		return EN, true
	}
	return "", false
}

// primary — первичный код языка из локали или тега ("ru_RU.UTF-8" → "ru").
func primary(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "-_.@"); i >= 0 {
		s = s[:i]
	}
	return s
}

// fromPrimary: русский — RU, любой другой настоящий язык — EN (как
// международный), отсутствие языка (пусто, C, POSIX) — "".
func fromPrimary(p string) Lang {
	switch p {
	case "", "c", "posix", "*":
		return ""
	case "ru":
		return RU
	}
	return EN
}

// FromLocale выбирает язык по значениям переменных локали в порядке
// приоритета (LC_ALL, LC_MESSAGES, LANG): берётся первое непустое.
// Если язык не задан (пусто, C, POSIX — типично для служб systemd),
// возвращается RU: так ведут себя установки, сделанные до появления
// английского языка.
func FromLocale(values ...string) Lang {
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if l := fromPrimary(primary(v)); l != "" {
			return l
		}
		return RU
	}
	return RU
}

// FromAcceptLanguage выбирает язык по заголовку Accept-Language
// браузера: первый (с наибольшим q) язык из списка. Пустой заголовок —
// RU.
func FromAcceptLanguage(header string) Lang {
	best, bestQ := Lang(""), -1.0
	for _, part := range strings.Split(header, ",") {
		tag, params, _ := strings.Cut(part, ";")
		l := fromPrimary(primary(tag))
		if l == "" {
			continue
		}
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			q = parseQ(v)
		}
		if q > bestQ {
			best, bestQ = l, q
		}
	}
	if best == "" || bestQ <= 0 {
		return RU
	}
	return best
}

// parseQ разбирает вес q (0…1, не больше трёх знаков после точки) без
// strconv, чтобы мусор в заголовке давал 0, а не ошибку.
func parseQ(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" || (s[0] != '0' && s[0] != '1') {
		return 0
	}
	v, div := 0.0, 1.0
	frac := false
	for _, c := range s {
		switch {
		case c == '.' && !frac:
			frac = true
		case c >= '0' && c <= '9':
			if frac {
				div *= 10
				v += float64(c-'0') / div
			} else {
				v = v*10 + float64(c-'0')
			}
		default:
			return 0
		}
	}
	if v > 1 {
		return 1
	}
	return v
}

// FromEnv — язык процесса: SSG_LANG, а если она пуста или неверна —
// по локали (LC_ALL, LC_MESSAGES, LANG).
func FromEnv() Lang {
	if l, ok := Parse(os.Getenv("SSG_LANG")); ok {
		return l
	}
	return FromLocale(os.Getenv("LC_ALL"), os.Getenv("LC_MESSAGES"), os.Getenv("LANG"))
}

var defaultLang atomic.Value // Lang

// Default — язык процесса для вывода CLI, журнала и ошибок.
func Default() Lang {
	if l, ok := defaultLang.Load().(Lang); ok {
		return l
	}
	return RU
}

// SetDefault задаёт язык процесса (вызывается в main при запуске).
func SetDefault(l Lang) {
	if _, ok := Parse(string(l)); ok {
		defaultLang.Store(l)
	}
}

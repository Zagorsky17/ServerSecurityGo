package i18n

import "fmt"

// entry — перевод одного ключа: [0] — русский, [1] — английский.
type entry = [2]string

// catalog — все сообщения. Заполняется в init файлов catalog_*.go,
// разложенных по областям (правила, история, терминал, веб...).
var catalog = map[string]entry{}

// add регистрирует часть каталога. Повтор ключа — ошибка разработчика,
// которую лучше поймать сразу при запуске тестов.
func add(part map[string]entry) {
	for k, v := range part {
		if _, dup := catalog[k]; dup {
			panic(fmt.Sprintf("i18n: ключ %q объявлен дважды", k))
		}
		catalog[k] = v
	}
}

func lookup(key string, l Lang) (string, bool) {
	e, ok := catalog[key]
	if !ok {
		return "", false
	}
	if l == EN {
		return e[1], true
	}
	return e[0], true
}

// Has сообщает, что ключ есть в каталоге.
func Has(key string) bool {
	_, ok := catalog[key]
	return ok
}

// Keys — все ключи каталога (для тестов).
func Keys() []string {
	out := make([]string, 0, len(catalog))
	for k := range catalog {
		out = append(out, k)
	}
	return out
}

// Catalog — каталог одного языка {ключ: шаблон} для веб-панели.
func Catalog(l Lang) map[string]string {
	out := make(map[string]string, len(catalog))
	for k := range catalog {
		out[k], _ = lookup(k, l)
	}
	return out
}

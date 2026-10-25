package i18n

import (
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
)

// TestCatalogComplete: у каждого ключа оба перевода непустые и с
// одинаковым набором плейсхолдеров — иначе на одном из языков аргумент
// потеряется или останется «{1}».
func TestCatalogComplete(t *testing.T) {
	for k, e := range catalog {
		if strings.TrimSpace(e[0]) == "" || strings.TrimSpace(e[1]) == "" {
			t.Errorf("%s: пустой перевод %q", k, e)
			continue
		}
		ru, en := Placeholders(e[0]), Placeholders(e[1])
		if !maps.Equal(ru, en) {
			t.Errorf("%s: плейсхолдеры различаются: ru %v, en %v", k, ru, en)
		}
		// Плейсхолдеры идут подряд с нуля: пропуск — почти всегда опечатка.
		for i := range len(ru) {
			if !ru[i] {
				t.Errorf("%s: нет плейсхолдера {%d}", k, i)
			}
		}
	}
}

// TestEnglishHasNoCyrillic: английские шаблоны не содержат кириллицы,
// кроме названия языка в переключателе.
func TestEnglishHasNoCyrillic(t *testing.T) {
	allowed := map[string]bool{"tui.lang_name": true, "tui.hint.lang": true, "tui.help.lang": true, "web.btn.lang": true, "web.btn.lang_title": true}
	for k, e := range catalog {
		if allowed[k] {
			continue
		}
		if strings.ContainsFunc(e[1], func(r rune) bool { return r >= 0x400 && r <= 0x4FF }) {
			t.Errorf("%s: кириллица в английском тексте: %q", k, e[1])
		}
	}
}

func TestMsgIn(t *testing.T) {
	m := T("hist.started_parent", "/bin/sh -c x", 42)
	if got := m.In(RU); got != "Новый процесс: /bin/sh -c x (родитель PID 42)" {
		t.Errorf("ru: %q", got)
	}
	if got := m.In(EN); got != "New process: /bin/sh -c x (parent PID 42)" {
		t.Errorf("en: %q", got)
	}
	// Вложенное сообщение переводится на тот же язык.
	n := T("hist.finding", T("rule.exe_in_temp.title"))
	if got := n.In(EN); got != "Indicator: Executable in a temporary directory" {
		t.Errorf("вложенное: %q", got)
	}
	j := Join("; ", L("a"), Msg{}, T("tui.yes"))
	if got := j.In(EN); got != "a; yes" {
		t.Errorf("склейка: %q", got)
	}
	if got := T("no.such.key", 1).In(EN); got != "no.such.key" {
		t.Errorf("неизвестный ключ: %q", got)
	}
	if !(Msg{}).IsZero() || L("x").IsZero() {
		t.Error("IsZero")
	}
}

// TestExpandSinglePass: «{0}» в аргументе (командную строку задаёт
// злоумышленник) не раскрывается повторно, лишние скобки остаются.
func TestExpandSinglePass(t *testing.T) {
	m := T("hist.risk", "{1}", "{0}")
	if got := m.In(RU); got != "Риск {1} → {0}" {
		t.Errorf("повторная подстановка: %q", got)
	}
	if got := expand("a {5} {x} {} {12", func(i int) (string, bool) { return "", false }); got != "a {5} {x} {} {12" {
		t.Errorf("скобки без аргументов: %q", got)
	}
}

func TestMsgJSON(t *testing.T) {
	in := []Msg{L("plain"), T("hist.risk", "LOW", T("tui.yes")), Join(" ", L("a"), T("tui.no")), {}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), `["plain",{"key":"hist.risk","args":["LOW",{"key":"tui.yes"}]}`) {
		t.Errorf("формат JSON: %s", b)
	}
	var out []Msg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	for i := range in {
		if in[i].In(EN) != out[i].In(EN) || in[i].In(RU) != out[i].In(RU) {
			t.Errorf("%d: %q != %q", i, in[i].In(EN), out[i].In(EN))
		}
	}
	// Старый формат — простая строка (events.jsonl до перевода).
	var old Msg
	if err := json.Unmarshal([]byte(`"Новый процесс: x"`), &old); err != nil || old.In(EN) != "Новый процесс: x" {
		t.Errorf("старый формат: %v %q", err, old.In(EN))
	}
}

func TestRenderJSON(t *testing.T) {
	v := map[string]any{
		"title":   T("rule.exe_in_temp.title"),
		"details": Join(": ", L("x"), T("tui.yes")),
		"link":    map[string]any{"key": "1-2", "pid": 1}, // не сообщение: есть другие поля
		"list":    []Msg{L("a")},
	}
	got, err := RenderJSON(v, EN)
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["title"] != "Executable in a temporary directory" || m["details"] != "x: yes" || m["list"].([]any)[0] != "a" {
		t.Errorf("перевод: %v", m)
	}
	if link := m["link"].(map[string]any); link["key"] != "1-2" {
		t.Errorf("обычный объект изменён: %v", link)
	}
}

func TestErrorf(t *testing.T) {
	base := errors.New("permission denied")
	err := Errorf("err.data_dir", base)
	if !errors.Is(err, base) {
		t.Error("Errorf должен оборачивать ошибку-аргумент")
	}
	SetDefault(EN)
	defer SetDefault(RU)
	if err.Error() != "data directory: permission denied" {
		t.Errorf("текст: %q", err.Error())
	}
	// Ошибка-сообщение, вложенная в другое сообщение, переводится.
	if got := T("cli.error", Errorf("err.no_data")).In(RU); got != "ошибка: нет данных" {
		t.Errorf("вложенная ошибка: %q", got)
	}
}

func TestLangDetection(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want Lang
	}{
		{nil, RU},
		{[]string{"", "", ""}, RU},
		{[]string{"", "", "ru_RU.UTF-8"}, RU},
		{[]string{"", "", "en_US.UTF-8"}, EN},
		{[]string{"", "", "C.UTF-8"}, RU},
		{[]string{"POSIX"}, RU},
		{[]string{"de_DE.UTF-8"}, EN},
		{[]string{"en_GB", "", "ru_RU"}, EN}, // LC_ALL главнее LANG
	} {
		if got := FromLocale(c.in...); got != c.want {
			t.Errorf("FromLocale(%q) = %s, ожидался %s", c.in, got, c.want)
		}
	}
	for h, want := range map[string]Lang{
		"":                        RU,
		"ru-RU,ru;q=0.9,en;q=0.8": RU,
		"en-US,en;q=0.9":          EN,
		"de-DE,de;q=0.9":          EN,
		"en;q=0.5, ru;q=0.9":      RU,
		"*":                       RU,
		"fr;q=0":                  RU,
		"ru;q=garbage, en;q=0.1":  EN,
	} {
		if got := FromAcceptLanguage(h); got != want {
			t.Errorf("FromAcceptLanguage(%q) = %s, ожидался %s", h, got, want)
		}
	}
	for s, want := range map[string]bool{"ru": true, "EN": true, "en-US": true, "": false, "de": false} {
		if _, ok := Parse(s); ok != want {
			t.Errorf("Parse(%q) = %v", s, ok)
		}
	}
}

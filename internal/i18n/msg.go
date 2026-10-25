package i18n

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Msg — переводимое сообщение. Бывает трёх видов:
//   - литерал (Lit): факт из системы — путь, командная строка, число;
//     выводится как есть на любом языке;
//   - сообщение каталога (Key + Args): шаблон по ключу, в который
//     подставляются аргументы, переведённые на тот же язык;
//   - склейка (Join + Args): части через разделитель Sep.
//
// Нулевое значение — пустая строка.
type Msg struct {
	Key  string
	Args []Msg
	Lit  string
	Sep  string
	Join bool
}

// T — сообщение каталога. Аргумент-Msg вкладывается как есть и
// переводится вместе с внешним; ошибка *Error — своим сообщением;
// остальное становится литералом через fmt.Sprint.
func T(key string, args ...any) Msg {
	m := Msg{Key: key}
	if len(args) > 0 {
		m.Args = make([]Msg, len(args))
		for i, a := range args {
			m.Args[i] = arg(a)
		}
	}
	return m
}

func arg(a any) Msg {
	switch v := a.(type) {
	case Msg:
		return v
	case *Error:
		return v.Msg
	case string:
		return L(v)
	case error:
		return L(v.Error())
	}
	return L(fmt.Sprint(a))
}

// L — литерал без перевода.
func L(s string) Msg { return Msg{Lit: s} }

// Ls — литералы из списка строк.
func Ls(ss []string) []Msg {
	out := make([]Msg, len(ss))
	for i, s := range ss {
		out[i] = L(s)
	}
	return out
}

// Join склеивает части через разделитель; пустые части пропускаются.
func Join(sep string, parts ...Msg) Msg {
	return Msg{Join: true, Sep: sep, Args: parts}
}

// IsZero сообщает, что сообщение пустое.
func (m Msg) IsZero() bool {
	return m.Key == "" && m.Lit == "" && !m.Join
}

// In собирает строку на языке l. Подстановка однопроходная: аргумент,
// содержащий «{0}» (а командную строку задаёт злоумышленник), не
// раскрывается повторно. Неизвестный ключ выводится как есть — так
// клиент новой версии не ломается на сообщениях службы другой версии.
func (m Msg) In(l Lang) string {
	switch {
	case m.Join:
		parts := make([]string, 0, len(m.Args))
		for _, a := range m.Args {
			if s := a.In(l); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, m.Sep)
	case m.Key != "":
		tmpl, ok := lookup(m.Key, l)
		if !ok {
			return m.Key
		}
		return expand(tmpl, func(i int) (string, bool) {
			if i < len(m.Args) {
				return m.Args[i].In(l), true
			}
			return "", false
		})
	}
	return m.Lit
}

// String — строка на языке процесса (для журнала и fmt).
func (m Msg) String() string { return m.In(Default()) }

// expand подставляет {N} за один проход по шаблону. Фигурные скобки,
// не образующие плейсхолдер с существующим аргументом, остаются как есть.
func expand(tmpl string, get func(int) (string, bool)) string {
	if !strings.Contains(tmpl, "{") {
		return tmpl
	}
	var b strings.Builder
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] == '{' {
			j := i + 1
			n := 0
			for j < len(tmpl) && j-i <= 3 && tmpl[j] >= '0' && tmpl[j] <= '9' {
				n = n*10 + int(tmpl[j]-'0')
				j++
			}
			if j > i+1 && j < len(tmpl) && tmpl[j] == '}' {
				if s, ok := get(n); ok {
					b.WriteString(s)
					i = j
					continue
				}
			}
		}
		b.WriteByte(tmpl[i])
	}
	return b.String()
}

// Placeholders — номера плейсхолдеров шаблона (для проверки каталога).
func Placeholders(tmpl string) map[int]bool {
	set := map[int]bool{}
	expand(tmpl, func(i int) (string, bool) { set[i] = true; return "", true })
	return set
}

// jsonMsg — форма сообщения в JSON. Литерал пишется простой строкой
// (см. MarshalJSON), поэтому старые клиенты и скрипты видят текст.
type jsonMsg struct {
	Key   string `json:"key,omitempty"`
	Args  []Msg  `json:"args,omitempty"`
	Sep   string `json:"sep,omitempty"`
	Parts []Msg  `json:"parts,omitempty"`
}

// MarshalJSON: литерал — строка, сообщение каталога — {"key","args"},
// склейка — {"sep","parts"}.
func (m Msg) MarshalJSON() ([]byte, error) {
	switch {
	case m.Join:
		return json.Marshal(jsonMsg{Sep: m.Sep, Parts: nonNil(m.Args)})
	case m.Key != "":
		return json.Marshal(jsonMsg{Key: m.Key, Args: m.Args})
	}
	return json.Marshal(m.Lit)
}

func nonNil(a []Msg) []Msg {
	if a == nil {
		return []Msg{}
	}
	return a
}

// UnmarshalJSON принимает и строку: так читаются events.jsonl и ответы
// API, записанные до появления перевода.
func (m *Msg) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*m = L(s)
		return nil
	}
	var j struct {
		Key   string `json:"key"`
		Args  []Msg  `json:"args"`
		Sep   string `json:"sep"`
		Parts []Msg  `json:"parts"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	if j.Parts != nil {
		*m = Msg{Join: true, Sep: j.Sep, Args: j.Parts}
		return nil
	}
	*m = Msg{Key: j.Key, Args: j.Args}
	return nil
}

// Error — ошибка с переводимым текстом. Текст выводится на языке
// процесса; если среди аргументов есть ошибка, она доступна через
// errors.Is/As (Unwrap).
type Error struct {
	Msg Msg
	Err error
}

func (e *Error) Error() string { return e.Msg.In(Default()) }
func (e *Error) Unwrap() error { return e.Err }

// Errorf — ошибка по ключу каталога. Первая ошибка среди аргументов
// становится обёрнутой (аналог %w).
func Errorf(key string, args ...any) error {
	e := &Error{Msg: T(key, args...)}
	for _, a := range args {
		if err, ok := a.(error); ok {
			e.Err = err
			break
		}
	}
	return e
}

// S — строка по ключу на языке процесса (вывод CLI, журнал).
func S(key string, args ...any) string { return T(key, args...).In(Default()) }

// RenderJSON превращает значение в дерево JSON (map/срезы), в котором
// все сообщения заменены готовым текстом на языке l. Нужен для вывода
// в скрипты (scan --format json), где каталога переводов нет.
func RenderJSON(v any, l Lang) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(b, &tree); err != nil {
		return nil, err
	}
	return renderTree(tree, l), nil
}

// renderTree обходит дерево и заменяет объекты-сообщения строкой.
// Сообщение узнаётся по набору полей: {"key"[, "args"]} со строковым key
// или {"sep"[, "parts"]} с массивом parts. В остальных структурах API
// поле key соседствует с другими (pid, name...), так что путаницы нет.
func renderTree(v any, l Lang) any {
	switch t := v.(type) {
	case []any:
		for i := range t {
			t[i] = renderTree(t[i], l)
		}
		return t
	case map[string]any:
		if isMsgObject(t) {
			b, _ := json.Marshal(t)
			var m Msg
			if json.Unmarshal(b, &m) == nil {
				return m.In(l)
			}
		}
		for k, x := range t {
			t[k] = renderTree(x, l)
		}
		return t
	}
	return v
}

func isMsgObject(m map[string]any) bool {
	if k, ok := m["key"].(string); ok && k != "" {
		for f := range m {
			if f != "key" && f != "args" {
				return false
			}
		}
		return true
	}
	if _, ok := m["parts"].([]any); ok {
		for f := range m {
			if f != "sep" && f != "parts" {
				return false
			}
		}
		return true
	}
	return false
}

package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

// doc — отчёт в нейтральном виде для HTML и Markdown: заголовок, итог,
// примечания, разделы-таблицы. Все строки уже переведены и очищены
// view.Printable; экранирование под формат делает отрисовщик.
type doc struct {
	Lang     string
	Title    string
	Subtitle string
	Verdict  string // уровень итога: CRITICAL, HIGH… или «OK»
	Class    string // класс оформления итога: risk-HIGH, st-pass…
	Summary  string
	Notes    []string // ограничения проверки, предупреждения
	Sections []section
	Footer   string
}

type section struct {
	Title   string
	Columns []string
	Rows    [][]cell
	Empty   string // текст, если строк нет
}

// cell — ячейка: текст, бейдж уровня или статуса, список, команда.
// Code — только для команд исправления, которые формирует само
// приложение: в коде Markdown экранирование не действует, поэтому данные
// из системы (пути, имена) туда не попадают.
type cell struct {
	Text  string
	Badge string // класс бейджа (risk-HIGH, st-fail); Text — подпись
	List  []string
	Code  string
}

func txt(s string) cell          { return cell{Text: view.Printable(s)} }
func badge(class, s string) cell { return cell{Text: s, Badge: class} }
func list(items []string) cell   { return cell{List: clean(items)} }
func withCode(c cell, code string) cell {
	c.Code = view.Printable(code)
	return c
}

func clean(items []string) []string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		out = append(out, view.Printable(s))
	}
	return out
}

//go:embed page.html
var templates embed.FS

var htmlTmpl = template.Must(template.ParseFS(templates, "page.html"))

// renderHTML — самодостаточная страница: встроенный CSS, без скриптов.
// html/template экранирует всё, что пришло из системы.
func renderHTML(w io.Writer, d *doc) error { return htmlTmpl.Execute(w, d) }

// renderMarkdown — отчёт в Markdown (GitHub/GitLab-совместимые таблицы).
func renderMarkdown(w io.Writer, d *doc) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", md(d.Title))
	fmt.Fprintf(&b, "%s\n\n", md(d.Subtitle))
	fmt.Fprintf(&b, "**%s** — %s\n\n", md(d.Verdict), md(d.Summary))
	// Каждое примечание — отдельный абзац цитаты, иначе Markdown склеит
	// их в одну строку.
	for i, n := range d.Notes {
		if i > 0 {
			b.WriteString(">\n")
		}
		fmt.Fprintf(&b, "> ⚠ %s\n", md(n))
	}
	if len(d.Notes) > 0 {
		b.WriteString("\n")
	}
	for _, s := range d.Sections {
		fmt.Fprintf(&b, "## %s\n\n", md(s.Title))
		if len(s.Rows) == 0 {
			fmt.Fprintf(&b, "%s\n\n", md(s.Empty))
			continue
		}
		b.WriteString("|")
		for _, c := range s.Columns {
			fmt.Fprintf(&b, " %s |", md(c))
		}
		b.WriteString("\n|")
		for range s.Columns {
			b.WriteString(" --- |")
		}
		b.WriteString("\n")
		for _, row := range s.Rows {
			b.WriteString("|")
			for _, c := range row {
				fmt.Fprintf(&b, " %s |", mdCell(c))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "---\n\n%s\n", md(d.Footer))
	_, err := io.WriteString(w, b.String())
	return err
}

func mdCell(c cell) string {
	var parts []string
	if c.Text != "" {
		t := md(c.Text)
		if c.Badge != "" {
			t = "**" + t + "**"
		}
		parts = append(parts, t)
	}
	for _, it := range c.List {
		parts = append(parts, "• "+md(it))
	}
	if c.Code != "" {
		parts = append(parts, mdCode(c.Code))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "<br>")
}

// mdSpecial — символы разметки Markdown. Экранируются обратной косой
// чертой, чтобы имя процесса не стало ссылкой, картинкой, HTML-тегом или
// не сломало таблицу («|»). «:» — против автоссылок GFM (https://…).
const mdSpecial = "\\`*_{}[]()<>#+-.!|~&:"

// md экранирует строку для Markdown (в таблице — в одну строку).
func md(s string) string {
	var b strings.Builder
	for _, r := range view.Printable(s) {
		if strings.ContainsRune(mdSpecial, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mdCode — команда в коде. Внутри `…` обычное экранирование не работает,
// поэтому ограничитель длиннее любой серии обратных кавычек в тексте.
// «|» в ячейке таблицы разорвал бы строку даже внутри кода; GFM понимает
// «\|» и там и показывает его как «|», так что команда копируется верно.
func mdCode(s string) string {
	s = strings.ReplaceAll(view.Printable(s), "|", `\|`)
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	return fence + " " + s + " " + fence
}

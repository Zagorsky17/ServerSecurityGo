// Пакет report выводит результаты разовых проверок (scan, audit) в
// разных форматах и определяет код выхода для cron, CI и мониторинга.
//
// Форматы:
//   - text — таблица для терминала (как раньше);
//   - json — стабильная схема с полем schema_version для скриптов;
//   - html — самодостаточный отчёт одним файлом (встроенный CSS, без JS);
//   - md — Markdown-файл для документации или тикета.
//
// Имена процессов, командные строки, пути и строки конфигов задаёт
// потенциальный злоумышленник. Поэтому в тексте и Markdown они проходят
// через view.Printable (без ESC-последовательностей и невидимых символов)
// и экранирование Markdown, а HTML строится через html/template.
package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// SchemaVersion — версия схемы JSON. Увеличивается при несовместимых
// изменениях: удалении или переименовании полей. Новые поля добавляются
// без смены версии.
const SchemaVersion = 1

// Format — формат отчёта.
type Format string

const (
	Text     Format = "text"
	JSON     Format = "json"
	HTML     Format = "html"
	Markdown Format = "md"
)

// ParseFormat разбирает значение --format. «table» — прежнее имя
// текстового формата, оставлено для совместимости.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text", "table":
		return Text, nil
	case "json":
		return JSON, nil
	case "html":
		return HTML, nil
	case "md", "markdown":
		return Markdown, nil
	}
	return "", i18n.Errorf("err.unknown_format", fmt.Sprintf("%q", s))
}

// Коды выхода scan и audit.
const (
	ExitOK         = 0 // нет находок уровня --fail-on и выше
	ExitFindings   = 1 // есть находки уровня --fail-on и выше
	ExitError      = 2 // ошибка выполнения (нет прав, сломан конфиг, неверный флаг)
	ExitIncomplete = 3 // находок нет, но проверка неполная (нет прав на часть данных)
)

// FailOn — порог кода выхода 1. Off — код выхода не зависит от находок.
type FailOn struct {
	Level model.Risk
	Off   bool
}

// ParseFailOn разбирает --fail-on: LOW…CRITICAL или none (off). INFO не
// принимается: справочные сведения есть на любом сервере, и такой порог
// означал бы «всегда 1».
func ParseFailOn(s string) (FailOn, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none", "off", "never":
		return FailOn{Off: true}, nil
	}
	r, ok := model.ParseRisk(s)
	if !ok || r < model.RiskLow {
		return FailOn{}, i18n.Errorf("err.bad_fail_on", fmt.Sprintf("%q", s))
	}
	return FailOn{Level: r}, nil
}

// CodeError — ошибка команды scan или audit с кодом выхода (2 — ошибка
// выполнения). main печатает Err и завершается с Code.
type CodeError struct {
	Code int
	Err  error
}

func (e *CodeError) Error() string { return e.Err.Error() }
func (e *CodeError) Unwrap() error { return e.Err }

// AsRunError оборачивает ошибку scan или audit в код 2: код 1 у этих
// команд означает «есть находки», и ошибка не должна с ним совпасть.
func AsRunError(err error) error {
	if err == nil {
		return nil
	}
	return &CodeError{Code: ExitError, Err: err}
}

// ExitCode — код выхода по итогу проверки. Находки важнее неполноты:
// если опасное найдено, неважно, что часть данных не прочитана.
// found — есть ли вообще находки (уровень verdict имеет смысл только
// тогда: у пустого результата он нулевой, то есть INFO).
func ExitCode(found bool, verdict model.Risk, f FailOn, incomplete bool) int {
	switch {
	case !f.Off && found && verdict >= f.Level:
		return ExitFindings
	case incomplete:
		return ExitIncomplete
	}
	return ExitOK
}

// Write отдаёт отчёт в stdout (path пустой или «-») или записывает в
// файл. Отчёт содержит командные строки и пути, поэтому новый файл
// создаётся с правами 0600 (os.CreateTemp) и атомарно переименовывается
// на место: ни полузаписанного отчёта, ни записи по чужому симлинку.
//
// Особые цели (служба работает от root, и ошибка тут дорогая):
//   - существующий симлинк — отказ: переименование заменило бы сам
//     симлинк (/dev/stdout), а запись по нему в /tmp — чужой файл;
//   - устройство или FIFO (/dev/null, именованный канал) — запись
//     напрямую, без замены: иначе /dev/null стал бы обычным файлом;
//   - каталог и прочее — отказ.
func Write(path string, render func(io.Writer) error) error {
	if path == "" || path == "-" {
		return render(os.Stdout)
	}
	if fi, err := os.Lstat(path); err == nil {
		switch m := fi.Mode(); {
		case m&os.ModeSymlink != 0:
			return i18n.Errorf("err.output_symlink", path)
		case m&(os.ModeDevice|os.ModeCharDevice|os.ModeNamedPipe) != 0:
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			if err := render(f); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		case !m.IsRegular():
			return i18n.Errorf("err.output_not_file", path)
		}
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ssg-report-*") // создаётся с правами 0600
	if err != nil {
		return err
	}
	name := tmp.Name()
	err = render(tmp)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

package i18n

// Тексты отчётов scan и audit в HTML и Markdown (internal/report) и
// флагов --format, --output, --fail-on.
func init() {
	add(map[string]entry{
		"report.title_scan":       {"Проверка процессов: {0}", "Process check: {0}"},
		"report.title_audit":      {"Результаты аудита: {0}", "Audit results: {0}"},
		"report.generated":        {"Сформирован {0} · {1} · ядро {2} · ServerSecurityGo {3}", "Generated {0} · {1} · kernel {2} · ServerSecurityGo {3}"},
		"report.generated_audit":  {"Сформирован {0} · ServerSecurityGo {1}", "Generated {0} · ServerSecurityGo {1}"},
		"report.scan_summary":     {"процессов {0}: CRITICAL {1}, HIGH {2}, MEDIUM {3}, LOW {4} · системных находок {5} · публичных портов {6}, опасных {7}", "{0} processes: CRITICAL {1}, HIGH {2}, MEDIUM {3}, LOW {4} · {5} system findings · {6} public ports, {7} dangerous"},
		"report.h.processes":      {"Процессы с уровнем {0} и выше", "Processes with level {0} or higher"},
		"report.h.checks":         {"Проверки", "Checks"},
		"report.no_public_ports":  {"Публичных портов нет.", "No public ports."},
		"report.no_problems":      {"Проблем не найдено.", "No problems found."},
		"report.audit_incomplete": {"Проверка неполная: {0} проверок не выполнено — нет прав на чтение. Запустите от root.", "The check is incomplete: {0} checks could not run — no permission to read. Run as root."},

		"cli.flag.output":     {"записать отчёт в файл (права 0600) вместо вывода на экран", "write the report to a file (mode 0600) instead of the screen"},
		"cli.flag.fail_on":    {"код выхода 1, если есть находки этого уровня и выше: LOW, MEDIUM, HIGH, CRITICAL; none — не зависеть от находок (код 3 при неполной проверке остаётся)", "exit code 1 if there are findings of this level or higher: LOW, MEDIUM, HIGH, CRITICAL; none — do not depend on findings (code 3 for an incomplete check remains)"},
		"report.verdict_ok":   {"В ПОРЯДКЕ", "OK"},
		"err.bad_fail_on":     {"неверный порог --fail-on {0}: допустимы LOW, MEDIUM, HIGH, CRITICAL или none", "invalid --fail-on threshold {0}: allowed are LOW, MEDIUM, HIGH, CRITICAL or none"},
		"err.output_symlink":  {"--output {0}: это символическая ссылка — укажите сам файл (по ссылкам отчёт не пишется)", "--output {0}: this is a symbolic link — give the file itself (reports are not written through links)"},
		"err.output_not_file": {"--output {0}: это не обычный файл", "--output {0}: not a regular file"},
		"err.unknown_format":  {"неизвестный формат {0}: допустимы text, json, html, md", "unknown format {0}: allowed are text, json, html, md"},
	})
}

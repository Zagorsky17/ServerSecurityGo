package i18n

// Тексты сканера (internal/scanner, procfs): предупреждения об условиях
// сканирования (warn.*), сообщения журнала (log.*) и ошибки.
func init() {
	add(map[string]entry{
		"warn.not_root":     {"Сканер запущен не от root: у процессов других пользователей недоступны exe, cwd, открытые файлы и окружение. Часть правил не сможет сработать.", "The scanner is not running as root: exe, cwd, open files and environment of other users' processes are unavailable. Some rules will not be able to work."},
		"warn.in_container": {"Сканер работает внутри контейнера: видны только процессы его PID-пространства. Для анализа хоста запускайте на хосте.", "The scanner runs inside a container: only processes of its PID namespace are visible. Run it on the host to analyze the host."},
		"warn.restricted":   {"Неполные данные у {0} процессов из-за прав доступа (hidepid, ptrace_scope, LSM).", "Incomplete data for {0} processes due to access restrictions (hidepid, ptrace_scope, LSM)."},
		"warn.read_errors":  {"Не удалось прочитать {0} процессов.", "Failed to read {0} processes."},

		"log.scan_error": {"ошибка сканирования", "scan error"},
		"log.high_risk":  {"обнаружен процесс с высоким риском", "high-risk process detected"},
		"log.scan_done":  {"сканирование завершено", "scan finished"},
		"log.boot_time":  {"не удалось определить время загрузки", "failed to determine boot time"},

		"err.read_path": {"чтение {0}: {1}", "reading {0}: {1}"},
	})
}

package i18n

// Тексты истории (internal/history): описания событий (hist.*) и
// названия типов событий (event.<тип>, общие для веб-панели и терминала).
func init() {
	add(map[string]entry{
		"event.baseline":  {"Начало наблюдения", "Monitoring start"},
		"event.started":   {"Запуск", "Started"},
		"event.exited":    {"Завершение", "Exited"},
		"event.changed":   {"Изменение", "Changed"},
		"event.risk_up":   {"Рост риска", "Risk up"},
		"event.risk_down": {"Снижение риска", "Risk down"},
		"event.finding":   {"Новый признак", "New indicator"},
		"event.listen":    {"Новый порт", "New port"},
		"event.system":    {"Система", "System"},

		"hist.started":        {"Новый процесс: {0}", "New process: {0}"},
		"hist.started_parent": {"Новый процесс: {0} (родитель PID {1})", "New process: {0} (parent PID {1})"},
		"hist.user_changed":   {"пользователь: {0} → {1}", "user: {0} → {1}"},
		"hist.risk":           {"Риск {0} → {1}", "Risk {0} → {1}"},
		"hist.finding":        {"Признак: {0}", "Indicator: {0}"},
		"hist.listen":         {"Начал слушать {0}", "Started listening on {0}"},
		"hist.exited":         {"Процесс завершился (наблюдался с {0})", "Process exited (observed since {0})"},
		"hist.system":         {"{0}: {1}", "{0}: {1}"},
		"hist.baseline":       {"Первое сканирование: зафиксировано процессов — {0}. Далее отслеживаются изменения.", "First scan: {0} processes recorded. Changes are tracked from now on."},

		"err.data_dir": {"каталог данных: {0}", "data directory: {0}"},
	})
}

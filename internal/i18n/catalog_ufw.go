package i18n

func init() {
	add(map[string]entry{
		"tui.panel.ufw":        {"UFW", "UFW"},
		"web.ufw.hint":         {"Сохранённая конфигурация UFW. Изменения файлов могут ещё не быть применены; активные правила ядра и правила Docker здесь не проверяются. Порядок обработки: before → user → after, отдельно для IPv4 и IPv6. Только просмотр.", "Saved UFW configuration. File changes may not have been applied; active kernel rules and Docker rules are not verified here. Evaluation order: before → user → after, separately for IPv4 and IPv6. Read-only."},
		"web.ufw.files":        {"Файлы настроек и правил", "Configuration and rule files"},
		"web.ufw.unavailable":  {"Данные UFW недоступны (в том числе у старой версии службы)", "UFW data unavailable (including older service versions)"},
		"web.ufw.absent":       {"Конфигурация UFW не найдена", "UFW configuration not found"},
		"web.ufw.unknown":      {"Не определено", "Unknown"},
		"web.ufw.empty":        {"Пусто", "Empty"},
		"web.ufw.enabled":      {"Включён в конфигурации (ENABLED)", "Enabled in configuration (ENABLED)"},
		"web.ufw.input":        {"Политика входящего трафика", "Incoming policy"},
		"web.ufw.output":       {"Политика исходящего трафика", "Outgoing policy"},
		"web.ufw.forward":      {"Политика маршрутизируемого трафика", "Forwarded traffic policy"},
		"web.ufw.ipv6":         {"Поддержка IPv6", "IPv6 support"},
		"web.ufw.logging":      {"Уровень журналирования", "Logging level"},
		"web.ufw.application":  {"Политика профилей приложений", "Application profile policy"},
		"web.ufw.builtins":     {"Управление встроенными цепочками", "Manage built-in chains"},
		"web.ufw.modules":      {"Загружаемые модули conntrack", "Conntrack modules to load"},
		"web.ufw.sysctl":       {"Файл параметров ядра", "Kernel parameter file"},
		"warn.ufw_read":        {"Не удалось прочитать {0}: {1}", "Could not read {0}: {1}"},
		"warn.ufw_sysctl_path": {"Путь IPT_SYSCTL не является безопасным буквальным путём: {0}; файл не прочитан", "IPT_SYSCTL is not a safe literal path: {0}; file not read"},
		"err.ufw_changed":      {"Настройка UFW изменилась во время чтения", "UFW configuration changed during reading"},
		"err.ufw_text":         {"Конфигурация UFW содержит двоичные данные или некорректный UTF-8", "UFW configuration contains binary data or invalid UTF-8"},
	})
}

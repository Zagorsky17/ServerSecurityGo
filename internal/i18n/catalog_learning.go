package i18n

func init() {
	add(map[string]entry{
		"err.learning_hours":    {"SSG_LEARNING_HOURS должен быть от 0 до 168; 0 выключает обучение.", "SSG_LEARNING_HOURS must be between 0 and 168; 0 disables learning."},
		"allow.weak_scope":      {"Правило allowlist #{0} имеет широкий шаблон пути или подавляет все признаки: {1}", "Allowlist rule #{0} has a broad path pattern or suppresses all findings: {1}"},
		"warn.allow_unused":     {"Правило allowlist #{0} не совпадало с находками с {1} (прошло не менее 30 календарных дней; простой службы тоже учитывается). Проверьте, нужно ли оно.", "Allowlist rule #{0} has not matched findings since {1} (at least 30 calendar days; service downtime also counts). Review whether it is still needed."},
		"warn.learning_state":   {"Состояние обучения недоступно: {0}. Предложения не применяются автоматически.", "Learning state unavailable: {0}. Suggestions are never applied automatically."},
		"warn.learning_clock":   {"Время ушло назад; наблюдение обучения в этом скане пропущено.", "Time moved backwards; learning observations were skipped for this scan."},
		"warn.learning_limit":   {"Отслеживание использования ограничено первыми 1000 правилами allowlist.", "Usage tracking is limited to the first 1,000 allowlist rules."},
		"web.tab.learning":      {"Allowlist и обучение", "Allowlist and learning"},
		"web.allow.legitimate":  {"Это легитимно — показать исключение", "This is legitimate — show exception"},
		"web.allow.review":      {"Проверьте происхождение бинарника и причину срабатывания. Фрагмент ограничен точным путём, пользователем и одним ID; скопируйте правило в allowlist.json вручную и перезапустите службу. Приложение файл не изменяет. Критические процессы и сильные признаки не предлагаются.", "Verify executable provenance and the signal's cause. The fragment is restricted to the exact path, user and one ID; manually copy the rule into allowlist.json and restart the service. The application does not edit that file. Critical processes and strong signals are excluded."},
		"web.learning.disabled": {"Обучение выключено или его окно завершено. Для включения задайте SSG_LEARNING_HOURS; оценка риска продолжает работать без изменений.", "Learning is disabled or its window has ended. Set SSG_LEARNING_HOURS to enable it; risk scoring continues unchanged."},
		"web.learning.until":    {"Сбор кандидатов до {0}; минимум три скана за пять минут, только текущие находки LOW без сильных признаков.", "Collecting candidates until {0}; at least three scans over five minutes, currently present LOW findings without strong signals only."},
		"web.learning.count":    {"Наблюдений: {0}; впервые {1}, последнее {2}.", "Observations: {0}; first {1}, latest {2}."},
	})
}

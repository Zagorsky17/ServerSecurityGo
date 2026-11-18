package i18n

func init() {
	add(map[string]entry{
		"web.overview.empty":        {"В текущем представлении нет результатов. Проверьте условия сканирования и включите все результаты для просмотра подробностей.", "No results in this view. Review scan conditions and enable all results to see details."},
		"web.overview.system":       {"В сводке: {0}; из них неполных проверок: {1}. INFO в подробностях: {2}.", "Overview: {0}; including incomplete checks: {1}. INFO in details: {2}."},
		"web.overview.toggle":       {"i — все результаты: {0}; поиск включает подробности.", "i — all results: {0}; search includes details."},
		"web.overview.all":          {"Показать все результаты, включая INFO", "Show all results, including INFO"},
		"web.overview.attention":    {"Проблемы, изменения и недоступные проверки", "Problems, changes and unavailable checks"},
		"web.overview.logins":       {"Записей: {0}; период: {1} — {2}.", "Records: {0}; period: {1} — {2}."},
		"web.overview.login_groups": {"Неудачные входы сгруппированы по IP, журналу и методу в интервалах по 15 минут UTC. Счётчик показывает записи, а не уникальные попытки. Подробности содержат все события группы.", "Failed logins are grouped by IP, log source and method in 15-minute UTC intervals. Counts represent records, not unique attempts. Details contain every event in the group."},
		"web.overview.group":        {"Записей: {0}; {1} — {2}", "Records: {0}; {1} — {2}"},
		"web.overview.incomplete":   {"Данные неполные; отсутствие событий не подтверждает отсутствие активности.", "Data is incomplete; missing events do not confirm absence of activity."},
	})
}

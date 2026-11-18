package i18n

func init() {
	add(map[string]entry{
		"web.system.group":    {"Файлы с неизвестным владельцем или группой: {0}", "Unknown owner or group: {0} files"},
		"web.system.back":     {"К списку групп и находок", "Back to groups and findings"},
		"tui.system.open":     {"Enter в списке открывает все файлы группы. ← или Esc возвращает к группам. / ищет по каждому файлу и UID/GID.", "Enter in the list opens all group files. Left or Esc returns to groups. / searches every file and UID/GID."},
		"tui.system.members":  {"Файлы группы: {0} · ← назад", "Group files: {0} · Left to go back"},
		"tui.system.examples": {"Примеры путей (первые {0}); полный список — Enter", "Example paths (first {0}); Enter opens the full list"},
	})
}

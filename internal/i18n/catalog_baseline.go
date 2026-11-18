package i18n

func init() {
	add(map[string]entry{
		"err.baseline_private":           {"Каталог снимков должен быть обычным каталогом с правами 700, файлы — 600.", "The snapshot directory must be a real directory with mode 700 and files with mode 600."},
		"err.baseline_invalid":           {"Недопустимое имя или повреждённый снимок базовой линии.", "Invalid name or corrupt baseline snapshot."},
		"err.baseline_ports":             {"Нельзя принять неполный список публичных портов: требуется доступ к таблицам сокетов и исполняемым файлам владельцев.", "Cannot accept an incomplete public-port inventory: socket tables and owner executables must be accessible."},
		"err.baseline_usage":             {"Используйте baseline save|list|accept --ports либо diff --from ИМЯ --to now; форматы text/json.", "Use baseline save|list|accept --ports or diff --from NAME --to now; formats text/json."},
		"cli.baseline.name":              {"Имя снимка (буквы, цифры, _ и -, до 64 символов)", "Snapshot name (letters, digits, _ and -, up to 64 characters)"},
		"cli.baseline.from":              {"Исходный снимок", "Source snapshot"},
		"cli.baseline.to":                {"Конечный снимок или now", "Target snapshot or now"},
		"cli.baseline.ports":             {"Принять текущие публичные порты и бинарники как ожидаемые", "Accept current public ports and binaries as expected"},
		"cli.baseline.saved":             {"Базовая линия сохранена: {0}", "Baseline saved: {0}"},
		"warn.baseline_missing":          {"Снимок для выбранного периода ещё отсутствует.", "No snapshot exists for the selected period yet."},
		"warn.baseline_host":             {"Снимки повреждены или относятся к разным machine-id; сравнение запрещено.", "Snapshots are invalid or have different machine IDs; comparison refused."},
		"warn.baseline_section":          {"Раздел {0} не сравнивается: неполные данные или разная область проверки.", "Section {0} is not compared: incomplete data or different inspection scope."},
		"warn.baseline_storage":          {"Не удалось прочитать или сохранить базовую линию: {0}", "Unable to read or save a baseline: {0}"},
		"warn.baseline_week":             {"Использован последний доступный снимок до границы 7 дней. Точный период указан датами сравнения.", "Using the latest available snapshot before the 7-day cutoff. Comparison timestamps show the actual period."},
		"warn.baseline_ports":            {"Эталон публичных портов ещё недоступен. Проверка новых портов неполная.", "Expected public ports are unavailable. New-port detection is incomplete."},
		"warn.baseline_partial":          {"Снимок сохранён с неполными разделами; они не участвуют в diff.", "Snapshot saved with incomplete sections; these will not participate in diff."},
		"rule.new_public_listener.title": {"Новый публичный порт или другой исполняемый файл владельца", "New public listener or changed owner executable"},
		"rule.new_public_listener.rec":   {"Проверьте назначение порта и бинарник. После проверки примите текущий список командой serversecuritygo baseline accept --ports. Это меняет только эталон, а не firewall.", "Verify the port's purpose and executable. After review, accept the current list with serversecuritygo baseline accept --ports. This changes only the baseline, not the firewall."},
		"web.tab.changes":                {"Изменения", "Changes"},
		"web.changes.installation":       {"С момента установки / первого снимка", "Since installation / first snapshot"},
		"web.changes.week":               {"За 7 дней (по доступному снимку)", "Last 7 days (available snapshot)"},
		"web.changes.period":             {"Снимки: {0} → {1}. Обновление сравнения — раз в час.", "Snapshots: {0} → {1}. Comparison refreshes hourly."},
		"web.changes.kind":               {"Изменение", "Change"},
		"web.changes.before":             {"Было", "Before"},
		"web.changes.after":              {"Стало", "After"},
	})
}

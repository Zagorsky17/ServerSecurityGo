package i18n

func init() {
	add(map[string]entry{
		"ev.self_unit_path":                 {"Изменён, добавлен или удалён: {0}", "Changed, added or removed: {0}"},
		"rule.self_check_unavailable.title": {"Самоконтроль: проверка недоступна — {0}", "Self-check unavailable: {0}"},
		"rule.self_check_unavailable.rec":   {"Проверьте наличие, права и тип файла, журнал службы и эталон self.sha256. Отсутствие эталона не означает целостность установки; не создавайте новый эталон из непроверенных файлов.", "Check the file's existence, permissions and type, service logs and self.sha256 baseline. A missing baseline does not prove integrity; do not replace it with unchecked files."},
		"rule.self_baseline_changed.title":  {"Эталон самоконтроля изменён после запуска", "Self-check baseline changed after startup"},
		"rule.self_baseline_changed.rec":    {"Сверьте изменение с действиями администратора. До перезапуска используется исходный эталон; не принимайте новый без проверки.", "Compare the change with administrator actions. The original baseline remains in use until restart; verify any replacement before accepting it."},
		"rule.self_binary_changed.title":    {"SHA256 запущенного бинарника не совпадает с эталоном установки", "Running binary SHA256 does not match the installation baseline"},
		"rule.self_binary_changed.rec":      {"Проверьте происхождение бинарника и историю обновлений. Восстановите проверенную версию штатным обновлением; одно несовпадение не доказывает атаку.", "Verify the binary's origin and update history. Restore a verified version through the update procedure; a mismatch alone does not prove an attack."},
		"rule.self_unit_changed.title":      {"Файлы systemd-юнита или его drop-in отличаются от эталона", "Systemd unit files or drop-ins differ from the baseline"},
		"rule.self_unit_changed.rec":        {"Проверьте systemctl cat serversecuritygo и файлы service.d/serversecuritygo.service.d. Изменение может быть штатной настройкой; содержимое на диске не обязательно уже загружено systemd.", "Check systemctl cat serversecuritygo and service.d/serversecuritygo.service.d files. This may be an administrator change; files on disk may not yet be loaded by systemd."},
		"rule.self_allowlist_changed.title": {"Файл исключений изменён, создан или удалён", "Allowlist file changed, appeared or disappeared"},
		"rule.self_allowlist_changed.rec":   {"Сверьте изменение с действиями администратора. Работающий сканер сохраняет загруженные правила до перезапуска; содержимое и контрольная сумма исключений в отчёт не выводятся.", "Compare the change with administrator actions. The scanner keeps its loaded rules until restart; neither allowlist contents nor its checksum are included in reports."},
		"rule.self_clock_back.title":        {"Системное время сместилось назад относительно монотонных часов более чем на секунду", "Wall clock moved backwards by more than one second relative to the monotonic clock"},
		"rule.self_clock_back.rec":          {"Проверьте синхронизацию времени и журнал администратора. Время событий может нарушать порядок; контроль зависания использует монотонные часы. Предупреждение сохраняется до перезапуска.", "Check time synchronization and administrator logs. Event timestamps may be out of order; scan freshness uses the monotonic clock. This warning remains until restart."},
		"rule.self_scan_stalled.title":      {"Более трёх интервалов нет успешно завершённого сканирования", "No successful scan completed for more than three scan intervals"},
		"rule.self_scan_stalled.rec":        {"Данные устарели. Проверьте journalctl -u serversecuritygo и доступ к /proc. Watchdog systemd перестаёт получать подтверждения и перезапускает только эту службу.", "Data is stale. Check journalctl -u serversecuritygo and /proc access. The systemd watchdog stops receiving heartbeats and restarts only this service."},
		"hist.self_recovered":               {"Самоконтроль: условие {0} больше не наблюдается", "Self-check: condition {0} is no longer observed"},
		"log.self_check":                    {"событие самоконтроля", "self-check event"},
		"log.self_history_failed":           {"не удалось сохранить событие самоконтроля", "failed to persist self-check event"},
		"log.self_notify_failed":            {"не удалось уведомить watchdog systemd", "failed to notify systemd watchdog"},
	})
}

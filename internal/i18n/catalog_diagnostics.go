package i18n

func init() {
	add(map[string]entry{
		"err.sarif_scope":       {"SARIF поддерживается для scan, audit и triage.", "SARIF is supported for scan, audit and triage."},
		"cli.diagnostics_usage": {"serversecuritygo explain <ID> [--format text|json]; serversecuritygo doctor [--format text|json|html|md|sarif] [--env-file PATH]", "serversecuritygo explain <ID> [--format text|json]; serversecuritygo doctor [--format text|json|html|md|sarif] [--env-file PATH]"},
		"err.explain_unknown":   {"Неизвестный ID: {0}", "Unknown ID: {0}"},
		"cli.explain_template":  {"Справка по правилу. Параметры {N} обозначают значения из конкретной находки; команды проверки не выполняются.", "Rule reference. Parameters {N} represent values from a specific finding; verification commands are not executed."},
		"cli.doctor.root":       {"Корень проверяемой системы", "Inspected system root"},
		"cli.doctor.root_rec":   {"Проверьте SSG_HOST_ROOT и права чтения каталога.", "Check SSG_HOST_ROOT and directory read permissions."},
		"cli.doctor.data":       {"Каталог данных: тип, владелец и права", "Data directory: type, owner and permissions"},
		"cli.doctor.data_rec":   {"Проверьте SSG_DATA_DIR. Каталог должен принадлежать root и иметь права 0700. Не меняйте владельца каталога с чужими данными.", "Check SSG_DATA_DIR. The directory must be owned by root with mode 0700. Do not change ownership of a directory containing unrelated data."},
		"cli.doctor.socket":     {"Unix-сокет и права его каталога", "Unix socket and parent directory permissions"},
		"cli.doctor.socket_rec": {"Проверьте systemctl status serversecuritygo и SSG_SOCKET_PATH. Ожидаются сокет 0600 и каталог 0700, владелец root. Проверка не подтверждает готовность службы; смотрите /healthz.", "Check systemctl status serversecuritygo and SSG_SOCKET_PATH. Expect a root-owned socket 0600 and directory 0700. This does not verify service readiness; inspect /healthz."},
		"cli.doctor.unit":       {"Основной файл юнита systemd", "Main systemd unit file"},
		"cli.doctor.unit_rec":   {"Сверьте systemctl cat serversecuritygo и systemctl status serversecuritygo с установленной версией. Doctor проверяет наличие и права основного файла; drop-in и загруженное состояние проверяйте отдельно.", "Compare systemctl cat serversecuritygo and systemctl status serversecuritygo with the installed version. Doctor checks the main file and permissions; inspect drop-ins and loaded state separately."},
		"cli.doctor.auth":       {"Доступность auth.log", "auth.log availability"},
		"cli.doctor.auth_rec":   {"Проверьте журнал SSH и настройку rsyslog: без /var/log/auth.log часть истории входов недоступна. Журнал может храниться только в journald.", "Check SSH logging and rsyslog: without /var/log/auth.log part of login history is unavailable. Logs may exist only in journald."},
		"cli.doctor.dpkg":       {"Полнота локальной базы dpkg", "Local dpkg database completeness"},
		"cli.doctor.dpkg_rec":   {"Проверьте /var/lib/dpkg/status и info/*.list. Отсутствующая или повреждённая база не позволяет судить о принадлежности файлов пакетам.", "Inspect /var/lib/dpkg/status and info/*.list. A missing or damaged database cannot establish package ownership."},
		"cli.doctor.kernel":     {"Версия работающего ядра", "Running kernel version"},
		"cli.doctor.kernel_rec": {"Версия прочитана из SSG_PROC_ROOT/sys/kernel/osrelease. Это инвентаризация; наличие исправлений CVE по одной версии не определяется.", "Read from SSG_PROC_ROOT/sys/kernel/osrelease. This is inventory; a version alone does not establish CVE patch status."},
		"cli.doctor.proc":       {"Чтение /proc других процессов: выборка до 32", "Reading other processes in /proc: sample of up to 32"},
		"cli.doctor.proc_rec":   {"Запускайте службу от root; проверьте hidepid, пространства имён и ограничения systemd. Успешная выборка не подтверждает доступ ко всем PID — смотрите ограничения полного сканирования.", "Run the service as root; inspect hidepid, namespaces and systemd restrictions. A successful sample does not prove access to every PID; inspect full-scan limitations."},
	})
}

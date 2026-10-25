package i18n

// Тексты командной строки (cmd/serversecuritygo), настроек
// (internal/config), журнала службы (log.*) и ошибок веб-API (web.err.*).
func init() {
	add(map[string]entry{
		"cli.usage": {`ServerSecurityGo {0} — мониторинг и анализ процессов Linux-сервера

Использование:
  serversecuritygo                                  терминальный интерфейс (то же, что tui)
  serversecuritygo tui [--local] [--socket PATH]    терминальный интерфейс
  serversecuritygo serve [--env-file PATH]          запустить сканер и веб-панель
  serversecuritygo scan [--format table|json] [--min-risk LOW] [--env-file PATH]
  serversecuritygo demo [--tui] [--listen ADDR]     демонстрационные данные (веб или терминал)
  serversecuritygo hash-password                    хеш пароля для SSG_AUTH_PASSWORD_HASH
  serversecuritygo version

Настройки задаются переменными окружения SSG_* (см. .env.example).
Язык: SSG_LANG=ru или SSG_LANG=en (по умолчанию — по локали терминала).
`, `ServerSecurityGo {0} — Linux server process monitoring and analysis

Usage:
  serversecuritygo                                  terminal interface (same as tui)
  serversecuritygo tui [--local] [--socket PATH]    terminal interface
  serversecuritygo serve [--env-file PATH]          run the scanner and the web panel
  serversecuritygo scan [--format table|json] [--min-risk LOW] [--env-file PATH]
  serversecuritygo demo [--tui] [--listen ADDR]     demo data (web or terminal)
  serversecuritygo hash-password                    password hash for SSG_AUTH_PASSWORD_HASH
  serversecuritygo version

Settings are taken from SSG_* environment variables (see .env.example).
Language: SSG_LANG=ru or SSG_LANG=en (default: from the terminal locale).
`},
		"cli.error": {"ошибка: {0}", "error: {0}"},

		"cli.flag.env_file":        {"файл с переменными SSG_*", "file with SSG_* variables"},
		"cli.flag.env_file_manual": {"файл с переменными SSG_* (для ручного запуска)", "file with SSG_* variables (for manual runs)"},
		"cli.flag.env_file_tui":    {"файл с переменными SSG_* (по умолчанию /opt/serversecuritygo/.env, если он есть)", "file with SSG_* variables (default /opt/serversecuritygo/.env, if it exists)"},
		"cli.flag.socket":          {"Unix-сокет службы (по умолчанию из SSG_SOCKET_PATH или {0})", "service Unix socket (default from SSG_SOCKET_PATH or {0})"},
		"cli.flag.local":           {"не подключаться к службе, сканировать самостоятельно", "do not connect to the service, scan locally"},
		"cli.flag.interval_local":  {"период сканирования в локальном режиме", "scan interval in local mode"},
		"cli.flag.refresh":         {"период обновления экрана", "screen refresh interval"},
		"cli.flag.format":          {"формат вывода: table или json", "output format: table or json"},
		"cli.flag.min_risk":        {"минимальный уровень для вывода: INFO, LOW, MEDIUM, HIGH, CRITICAL", "minimum level to show: INFO, LOW, MEDIUM, HIGH, CRITICAL"},
		"cli.flag.sample":          {"сделать два замера с этим интервалом для точного CPU% (например, 2s)", "take two samples with this interval for accurate CPU% (e.g. 2s)"},
		"cli.flag.listen":          {"адрес веб-панели (только loopback)", "web panel address (loopback only)"},
		"cli.flag.interval":        {"период сканирования", "scan interval"},
		"cli.flag.demo_tui":        {"открыть демо в терминальном интерфейсе вместо веб-панели", "open the demo in the terminal interface instead of the web panel"},

		"cli.scan.host":   {"Хост: {0}, {1}, ядро {2}. Процессов: {3}, сокетов: {4}, сканирование {5}", "Host: {0}, {1}, kernel {2}. Processes: {3}, sockets: {4}, scan took {5}"},
		"cli.scan.levels": {"По уровням: CRITICAL {0}, HIGH {1}, MEDIUM {2}, LOW {3}, INFO {4}", "By level: CRITICAL {0}, HIGH {1}, MEDIUM {2}, LOW {3}, INFO {4}"},
		"cli.scan.header": {"РИСК\tБАЛЛЫ\tPID\tПОЛЬЗОВАТЕЛЬ\tИМЯ\tПУТЬ\tПРИЗНАКИ", "RISK\tSCORE\tPID\tUSER\tNAME\tPATH\tINDICATORS"},
		"cli.scan.none":   {"Процессов с уровнем {0} и выше нет.", "No processes with level {0} or higher."},
		"cli.scan.system": {"Системные проверки:", "System checks:"},
		"cli.scan.footer": {"Оценка основана на косвенных признаках и не является доказательством компрометации. Подробности: --format json или веб-панель.", "The assessment is based on indirect indicators and is not proof of compromise. Details: --format json or the web panel."},

		"cli.pw.prompt":   {"Пароль (не короче 12 символов): ", "Password (at least 12 characters): "},
		"cli.pw.repeat":   {"Повторите пароль: ", "Repeat the password: "},
		"cli.pw.add_line": {"Добавьте строку в /opt/serversecuritygo/.env:", "Add this line to /opt/serversecuritygo/.env:"},

		"err.env_file":               {"файл настроек: {0}", "settings file: {0}"},
		"err.env_line":               {"{0}: ожидается KEY=VALUE", "{0}: expected KEY=VALUE"},
		"err.env_duration":           {"{0}: неверная длительность {1} (пример: 30s, 5m, 168h)", "{0}: invalid duration {1} (example: 30s, 5m, 168h)"},
		"err.env_int":                {"{0}: ожидается неотрицательное целое, получено {1}", "{0}: expected a non-negative integer, got {1}"},
		"err.env_number":             {"{0}: ожидается число, получено {1}", "{0}: expected a number, got {1}"},
		"err.env_bool":               {"{0}: ожидается true/false", "{0}: expected true/false"},
		"err.env_uids":               {"SSG_LOCAL_UIDS: ожидаются числовые UID через запятую, получено {0}", "SSG_LOCAL_UIDS: expected comma-separated numeric UIDs, got {0}"},
		"err.env_lang":               {"SSG_LANG: ожидается ru или en, получено {0}", "SSG_LANG: expected ru or en, got {0}"},
		"err.env_interval_min":       {"SSG_SCAN_INTERVAL: минимум 2s", "SSG_SCAN_INTERVAL: minimum is 2s"},
		"err.tls_pair":               {"SSG_TLS_CERT и SSG_TLS_KEY задаются только вместе", "SSG_TLS_CERT and SSG_TLS_KEY must be set together"},
		"err.proxy_needs_password":   {"SSG_TRUST_PROXY_TLS=true означает доступ через reverse proxy — задайте SSG_AUTH_PASSWORD_HASH (serversecuritygo hash-password)", "SSG_TRUST_PROXY_TLS=true means access through a reverse proxy — set SSG_AUTH_PASSWORD_HASH (serversecuritygo hash-password)"},
		"err.network_needs_password": {"адрес {0} доступен из сети, но SSG_AUTH_PASSWORD_HASH не задан. Задайте пароль (serversecuritygo hash-password) или используйте 127.0.0.1 и SSH-туннель", "address {0} is reachable from the network, but SSG_AUTH_PASSWORD_HASH is not set. Set a password (serversecuritygo hash-password) or use 127.0.0.1 and an SSH tunnel"},
		"err.network_needs_tls":      {"адрес {0} доступен из сети без TLS. Задайте SSG_TLS_CERT/SSG_TLS_KEY или, если TLS завершается на reverse proxy, SSG_TRUST_PROXY_TLS=true", "address {0} is reachable from the network without TLS. Set SSG_TLS_CERT/SSG_TLS_KEY or, if TLS is terminated on a reverse proxy, SSG_TRUST_PROXY_TLS=true"},
		"err.bad_hash":               {"SSG_AUTH_PASSWORD_HASH имеет неверный формат; получите его командой serversecuritygo hash-password", "SSG_AUTH_PASSWORD_HASH has an invalid format; generate it with serversecuritygo hash-password"},
		"err.need_allowed_hosts":     {"для доступа из сети задайте SSG_ALLOWED_HOSTS — доменное имя или IP, по которому открывается панель (защита от DNS rebinding)", "for network access set SSG_ALLOWED_HOSTS — the domain name or IP used to open the panel (DNS rebinding protection)"},
		"err.listen":                 {"не удалось открыть {0}: {1}", "failed to listen on {0}: {1}"},
		"err.dir_mode":               {"каталог {0} должен иметь права 0700", "directory {0} must have mode 0700"},
		"err.socket_busy":            {"сокет занят другим запущенным экземпляром", "the socket is used by another running instance"},
		"err.tui_needs_terminal":     {"терминальный интерфейс нужно запускать в терминале; для скриптов используйте scan", "the terminal interface must run in a terminal; use scan for scripts"},
		"err.unknown_level":          {"неизвестный уровень {0}", "unknown level {0}"},
		"err.demo_loopback":          {"демо-режим работает только на 127.0.0.1", "demo mode works only on 127.0.0.1"},
		"err.demo_tui_terminal":      {"demo --tui нужно запускать в терминале", "demo --tui must run in a terminal"},
		"err.pw_mismatch":            {"пароли не совпадают", "the passwords do not match"},

		"log.start":         {"запуск", "starting"},
		"log.not_linux":     {"приложение рассчитано на Linux; на этой ОС нет /proc — используйте режим demo", "the application is designed for Linux; this OS has no /proc — use demo mode"},
		"log.not_root":      {"запуск не от root: данные о процессах других пользователей будут неполными", "not running as root: data about other users' processes will be incomplete"},
		"log.weak_allow":    {"слабое правило allowlist", "weak allowlist rule"},
		"log.socket_failed": {"локальный сокет для терминального интерфейса не создан", "local socket for the terminal interface was not created"},
		"log.socket":        {"локальный сокет для терминального интерфейса", "local socket for the terminal interface"},
		"log.panel_url":     {"веб-панель доступна", "web panel is available"},
		"log.stop_signal":   {"остановка по сигналу", "stopping on signal"},
		"log.demo":          {"демо-режим: данные вымышленные", "demo mode: the data is fictional"},
		"log.peer_denied":   {"отклонён доступ к панели без пароля: пользователь не в SSG_LOCAL_UIDS", "denied passwordless panel access: user is not in SSG_LOCAL_UIDS"},
		"log.login_blocked": {"вход заблокирован: слишком много попыток", "login blocked: too many attempts"},
		"log.login_failed":  {"неудачная попытка входа", "failed login attempt"},
		"log.login_ok":      {"успешный вход", "successful login"},

		"web.err.host":           {"недопустимый заголовок Host (см. SSG_ALLOWED_HOSTS)", "invalid Host header (see SSG_ALLOWED_HOSTS)"},
		"web.err.peer":           {"без пароля панель доступна только root (SSG_LOCAL_UIDS); задайте пароль или подключитесь через SSH-туннель под root", "without a password the panel is available only to root (SSG_LOCAL_UIDS); set a password or connect through an SSH tunnel as root"},
		"web.err.login_required": {"требуется вход", "login required"},
		"web.err.csrf":           {"неверный CSRF-токен, обновите страницу", "invalid CSRF token, reload the page"},
		"web.err.bad_request":    {"неверный запрос", "bad request"},
		"web.err.too_many":       {"слишком много неудачных попыток, повторите через 15 минут", "too many failed attempts, try again in 15 minutes"},
		"web.err.busy":           {"сервер занят проверкой других попыток входа, повторите через несколько секунд", "the server is busy checking other login attempts, try again in a few seconds"},
		"web.err.bad_password":   {"неверный пароль", "wrong password"},
	})
}

package i18n

func init() {
	add(map[string]entry{
		"warn.advanced_process_pending": {"ELF ещё не проверен для текущих процессов: {0}. Ожидается очередной фоновый проход.", "ELF has not been inspected for {0} current processes. Awaiting the next background pass."},
		"warn.promisc_unavailable":      {"Флаги сетевых интерфейсов недоступны или повреждены; проверка promiscuous неполная.", "Network interface flags are unavailable or malformed; promiscuous-mode inspection is incomplete."},
		"warn.packet_incomplete":        {"Таблица AF_PACKET недоступна, повреждена или превышает лимит; проверка пакетных сокетов неполная.", "AF_PACKET table unavailable, malformed or over limit; packet-socket inspection is incomplete."},
		"warn.advanced_pending":         {"Проверка ELF и включённого поиска веб-шеллов ещё не завершена.", "ELF inspection and enabled web-shell scanning have not finished yet."},
		"warn.advanced_incomplete":      {"Проверка ELF/веб-файлов неполная: недоступные данные, изменившийся файл или предел чтения/времени.", "ELF/web-file inspection is incomplete: inaccessible data, a changing file, or read/time limits."},
		"rule.bpf_unexpected.title":     {"У процесса открыты дескрипторы eBPF", "Process holds eBPF descriptors"},
		"rule.bpf_unexpected.rec":       {"Проверьте владельца, тип и tag программы через /proc/PID/fdinfo и bpftool. Наличие дескриптора не подтверждает прикрепление программы к ядру. Известный пакетный инструмент наблюдения уменьшает оценку; имя процесса само по себе не считается доверием.", "Review owner, program type and tag through /proc/PID/fdinfo and bpftool. A descriptor does not prove that a program is attached. Known packaged monitoring tools reduce the score; the process name alone is not trusted."},
		"rule.raw_packet_socket.title":  {"Процесс держит пакетный сокет AF_PACKET", "Process holds an AF_PACKET socket"},
		"rule.raw_packet_socket.rec":    {"Проверьте назначение процесса и интерфейс. DHCP, мониторинг сети и tcpdump используют такие сокеты штатно. Пакетный сокет не доказывает перехват данных; приложение само пакеты не читает.", "Review the process purpose and interface. DHCP, network monitoring and tcpdump legitimately use these sockets. A packet socket does not prove interception; this application does not capture packets."},
		"rule.iface_promisc.title":      {"Интерфейс в режиме promiscuous", "Interface is in promiscuous mode"},
		"rule.iface_promisc.rec":        {"Сверьте режим с настройками мостов, виртуализации, сетевого мониторинга и захвата трафика. Флаг интерфейса сам по себе не доказывает сниффинг.", "Compare this mode with bridge, virtualization, monitoring and packet-capture configuration. The interface flag alone does not prove sniffing."},
		"rule.exe_packed.title":         {"В ELF обнаружен признак упаковки или высокой энтропии", "ELF has a packing marker or high entropy"},
		"rule.exe_packed.rec":           {"Сверьте хеш и происхождение бинарника с доверенной сборкой. UPX применяется и для обычных программ; высокая энтропия сама по себе справочная. Проверка ограничена размером и не распаковывает и не запускает файл.", "Compare the executable hash and provenance with a trusted build. UPX also packs legitimate programs; high entropy alone is informational. Inspection is size-limited and never unpacks or executes the file."},
		"rule.exe_static_in_temp.title": {"Статический ELF во временном каталоге", "Static ELF in a temporary directory"},
		"rule.exe_static_in_temp.rec":   {"Проверьте источник запуска. Статические Go-бинарники, сборки и установщики могут временно запускаться из /tmp штатно.", "Verify the launch source. Static Go binaries, builds and installers may legitimately execute from /tmp."},
		"rule.webshell_pattern.title":   {"Недавно изменённый веб-файл содержит подозрительный шаблон", "Recently modified web file contains a suspicious pattern"},
		"rule.webshell_pattern.rec":     {"Сверьте файл с репозиторием приложения и журналами развёртывания. Шаблон может встречаться в библиотеке, тесте или примере; это подсказка для проверки, не подтверждение веб-шелла. Содержимое файла в отчёт не включается.", "Compare the file with the application repository and deployment logs. Patterns may occur in libraries, tests or examples; this is a review hint, not proof of a web shell. File contents are not included in the report."},
		"ev.webshell_related":           {"Недавний веб-файл для сопоставления с цепочкой запуска: {0}; причинная связь не установлена.", "Recent web file to compare with the launch chain: {0}; causation is not established."},
		"err.webshell_days":             {"SSG_WEBSHELL_DAYS должен быть от 1 до 365.", "SSG_WEBSHELL_DAYS must be between 1 and 365."},
		"tui.h.bpf":                     {"Дескрипторы eBPF", "eBPF descriptors"},
		"tui.h.elf":                     {"Последняя проверка ELF", "Latest ELF inspection"},
	})
}

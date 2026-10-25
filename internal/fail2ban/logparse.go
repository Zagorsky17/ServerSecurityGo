package fail2ban

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/netip"
	"time"
)

// Действия в журнале fail2ban.
const (
	actFound     uint8 = iota + 1 // [jail] Found IP — попытка, засчитанная фильтром
	actBan                        // [jail] Ban IP
	actRestore                    // [jail] Restore Ban IP — бан восстановлен после перезапуска
	actUnban                      // [jail] Unban IP
	actIncrease                   // [jail] Increase Ban IP (… -> дата) — бан продлён
	actIgnore                     // [jail] Ignore IP by … — адрес из ignoreip
	actStart                      // Starting Fail2ban vX
	actStop                       // Exiting Fail2ban
	actJailStart                  // Jail 'name' started
	actJailStop                   // Jail 'name' stopped
)

// Пределы памяти на все файлы журнала вместе. Журнал пишет fail2ban от
// root, но IP в нём выбирают атакующие: у владельца сети IPv6 /64
// миллиарды адресов, и они не должны раздувать память службы (в юните
// MemoryMax=256M). Запись счётчика — около 100 байт, события — около 80.
// Переменные, а не константы — чтобы тест мог уменьшить бюджет.
const maxLineLen = 8 << 10 // длиннее — строка пропускается

var (
	maxTotalIPs  = 200_000 // разных пар (IP, jail, сутки) и адресов ignoreip
	maxTotalEvts = 400_000 // банов, разбанов и перезапусков
)

// event — бан, разбан или перезапуск (строки Found в события не
// попадают: их слишком много, они сразу сворачиваются в счётчики).
type event struct {
	t      int64 // Unix-время, секунды
	act    uint8
	jail   string
	ip     string
	until  int64 // для actIncrease: до какого времени продлён бан
	detail string
}

type hourKey struct {
	jail string
	hour int64 // Unix-время / 3600
}

type ipKey struct {
	ip   string
	jail string
	day  int64 // Unix-время / 86400
}

// fileData — разобранная часть одного файла журнала: счётчики и события.
type fileData struct {
	id       fileID
	size     int64
	mtime    time.Time
	offset   int64 // сколько байт разобрано (для дочитывания текущего файла)
	gz       bool
	found    map[hourKey]int
	byIP     map[ipKey]int
	ignored  map[string]int
	overflow int // попытки, не попавшие в byIP из-за предела
	events   []event
	dropped  bool // часть событий отброшена из-за предела
	// ipCap, evCap — сколько записей этому файлу осталось из общего
	// бюджета (maxTotalIPs, maxTotalEvts); выставляет Collector.load.
	ipCap, evCap int
	cut          bool // файл прочитан не целиком (больше предела)
	version      string
	lines        int
}

func newFileData() *fileData {
	return &fileData{found: map[hourKey]int{}, byIP: map[ipKey]int{}, ignored: map[string]int{}, ipCap: maxTotalIPs, evCap: maxTotalEvts}
}

// consume разбирает строки из r и возвращает число байт полностью
// разобранных строк. final = true — последняя строка без перевода строки
// тоже разбирается (сжатый или ротированный файл больше не растёт); иначе
// она остаётся на следующий раз: fail2ban мог ещё не дописать её.
func (fd *fileData) consume(r io.Reader, limit int64, final bool, loc *time.Location) int64 {
	br := bufio.NewReaderSize(io.LimitReader(r, limit), 64<<10)
	var n int64
	skipping := false
	for {
		line, err := br.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			// Слишком длинная строка: пропускаем до конца строки.
			n += int64(len(line))
			skipping = true
			continue
		case err == nil:
			n += int64(len(line))
			if !skipping {
				fd.line(line[:len(line)-1], loc)
			}
			skipping = false
			continue
		}
		// EOF или ошибка чтения.
		if len(line) > 0 && final {
			n += int64(len(line))
			if !skipping {
				fd.line(line, loc)
			}
		}
		if errors.Is(err, io.EOF) && n >= limit {
			fd.cut = true
		}
		return n
	}
}

// line разбирает одну строку журнала:
//
//	2024-01-15 10:23:45,123 fail2ban.filter  [1234]: INFO    [sshd] Found 203.0.113.5 - 2024-01-15 10:23:45
//	2024-01-15 10:23:46,456 fail2ban.actions [1234]: NOTICE  [sshd] Ban 203.0.113.5
//
// В старых версиях (0.8) после имени модуля нет [PID]. Строки другого
// вида пропускаются.
func (fd *fileData) line(b []byte, loc *time.Location) {
	b = bytes.TrimRight(b, "\r")
	if len(b) > maxLineLen || len(b) < 24 {
		return
	}
	t, ok := parseStamp(b[:19], loc)
	if !ok {
		return
	}
	fd.lines++
	msg := message(b[19:])
	if msg == nil {
		return
	}
	ts := t.Unix()
	if msg[0] != '[' {
		fd.serverLine(ts, msg)
		return
	}
	end := bytes.IndexByte(msg, ']')
	if end < 0 || !validJail(msg[1:end]) {
		return
	}
	jail := string(msg[1:end])
	rest := bytes.TrimLeft(msg[end+1:], " ")
	act, rest := action(rest)
	if act == 0 {
		return
	}
	ipb := rest
	if i := bytes.IndexAny(ipb, " ,"); i >= 0 {
		ipb = ipb[:i]
	}
	// Адрес с зоной IPv6 («fe80::1%eth0») fail2ban не банит; зона — любой
	// текст, и в команду разбана он попасть не должен.
	a, err := netip.ParseAddr(string(ipb))
	if err != nil || a.Zone() != "" {
		return
	}
	ip := a.Unmap().String()
	switch act {
	case actFound:
		fd.found[hourKey{jail, ts / 3600}]++
		k := ipKey{ip, jail, ts / 86400}
		if _, ok := fd.byIP[k]; ok || len(fd.byIP)+len(fd.ignored) < fd.ipCap {
			fd.byIP[k]++
		} else {
			fd.overflow++
		}
	case actIgnore:
		if _, ok := fd.ignored[ip]; ok || len(fd.byIP)+len(fd.ignored) < fd.ipCap {
			fd.ignored[ip]++
		} else {
			fd.overflow++
		}
	case actIncrease:
		// «Increase Ban 1.2.3.4 (3 # 4:00:00 -> 2024-01-15 14:23:46)»
		var until int64
		if i := bytes.LastIndex(rest, []byte("-> ")); i >= 0 && len(rest) >= i+3+19 {
			if u, ok := parseStamp(rest[i+3:i+3+19], loc); ok {
				until = u.Unix()
			}
		}
		fd.addEvent(event{t: ts, act: act, jail: jail, ip: ip, until: until})
	default:
		fd.addEvent(event{t: ts, act: act, jail: jail, ip: ip})
	}
}

// serverLine — сообщения сервера без jail: запуск, остановка, jail
// запущен/остановлен.
func (fd *fileData) serverLine(ts int64, msg []byte) {
	switch {
	case bytes.HasPrefix(msg, []byte("Starting Fail2ban v")):
		v := string(bytes.TrimSpace(msg[len("Starting Fail2ban v"):]))
		if len(v) > 32 {
			v = v[:32]
		}
		fd.version = v
		fd.addEvent(event{t: ts, act: actStart, detail: v})
	case bytes.HasPrefix(msg, []byte("Exiting Fail2ban")):
		fd.addEvent(event{t: ts, act: actStop})
	case bytes.HasPrefix(msg, []byte("Jail '")):
		rest := msg[len("Jail '"):]
		i := bytes.IndexByte(rest, '\'')
		if i < 0 || !validJail(rest[:i]) {
			return
		}
		name, tail := string(rest[:i]), bytes.TrimSpace(rest[i+1:])
		switch string(tail) {
		case "started":
			fd.addEvent(event{t: ts, act: actJailStart, jail: name})
		case "stopped":
			fd.addEvent(event{t: ts, act: actJailStop, jail: name})
		}
	}
}

// validJail — имя jail в журнале: 1–64 печатных символа без пробелов и
// скобок (в конфигурации это имя секции).
func validJail(b []byte) bool {
	if len(b) == 0 || len(b) > 64 {
		return false
	}
	for _, c := range b {
		if c <= ' ' || c == ']' || c == '[' || c == '\'' || c == 0x7f {
			return false
		}
	}
	return true
}

func (fd *fileData) addEvent(e event) {
	if len(fd.events) >= fd.evCap {
		fd.dropped = true
		if fd.evCap < 2 {
			return
		}
		// Для текущих банов важны последние события: отбрасываем старую
		// половину.
		fd.events = append(fd.events[:0], fd.events[len(fd.events)/2:]...)
	}
	fd.events = append(fd.events, e)
}

// action — действие в начале сообщения jail и остаток с IP.
func action(b []byte) (uint8, []byte) {
	for _, a := range [...]struct {
		p   string
		act uint8
	}{
		{"Found ", actFound}, {"Ban ", actBan}, {"Unban ", actUnban}, {"Restore Ban ", actRestore},
		{"Increase Ban ", actIncrease}, {"Ignore ", actIgnore},
	} {
		if bytes.HasPrefix(b, []byte(a.p)) {
			return a.act, b[len(a.p):]
		}
	}
	return 0, nil
}

// message пропускает «,мс модуль [PID]: УРОВЕНЬ» после времени и
// возвращает текст сообщения.
func message(b []byte) []byte {
	// «,123 fail2ban.filter         [1234]: INFO    текст»
	i := bytes.Index(b, []byte(": "))
	if i < 0 || i > 80 || !bytes.Contains(b[:i], []byte("fail2ban")) {
		return nil
	}
	rest := bytes.TrimLeft(b[i+2:], " ")
	// Уровень: INFO, NOTICE, WARNING, ERROR, DEBUG, CRITICAL, HEAVYDEBUG.
	j := bytes.IndexByte(rest, ' ')
	if j <= 0 || j > 12 {
		return nil
	}
	for _, c := range rest[:j] {
		if c < 'A' || c > 'Z' {
			return nil
		}
	}
	rest = bytes.TrimLeft(rest[j:], " ")
	if len(rest) == 0 {
		return nil
	}
	return rest
}

// parseStamp разбирает «2006-01-02 15:04:05» в местном времени сервера:
// fail2ban пишет время без часового пояса.
func parseStamp(b []byte, loc *time.Location) (time.Time, bool) {
	if len(b) != 19 || b[4] != '-' || b[7] != '-' || b[10] != ' ' || b[13] != ':' || b[16] != ':' {
		return time.Time{}, false
	}
	num := func(s []byte) (int, bool) {
		n := 0
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int(c-'0')
		}
		return n, true
	}
	y, ok1 := num(b[0:4])
	mo, ok2 := num(b[5:7])
	d, ok3 := num(b[8:10])
	h, ok4 := num(b[11:13])
	mi, ok5 := num(b[14:16])
	s, ok6 := num(b[17:19])
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60 || y < 2000 {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(mo), d, h, mi, s, 0, loc), true
}

// gzipReader — распаковка ротированного журнала (.gz).
func gzipReader(r io.Reader) (io.Reader, error) {
	return gzip.NewReader(r)
}

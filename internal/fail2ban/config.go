package fail2ban

import (
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// maxConfigFile — предел размера одного файла конфигурации fail2ban.
const maxConfigFile = 1 << 20

// maxConfigFiles — сколько файлов из jail.d/fail2ban.d читается.
const maxConfigFiles = 200

// Значения по умолчанию из jail.conf (fail2ban 0.10–1.x): если jail.conf
// нет или в нём параметр не задан, fail2ban использует их же.
const (
	defaultMaxRetry = 5
	defaultFindTime = 600
	defaultBanTime  = 600
	defaultLogPath  = "/var/log/fail2ban.log"
)

// ini — объединённая конфигурация из нескольких файлов: секция → ключ →
// значение и файл, откуда значение взято. Ключи в нижнем регистре, как
// у configparser в Python, на котором написан fail2ban; имена секций —
// с учётом регистра.
type ini struct {
	order []string
	vals  map[string]map[string]string
	src   map[string]map[string]string
}

func newINI() *ini {
	return &ini{vals: map[string]map[string]string{}, src: map[string]map[string]string{}}
}

// parse добавляет файл в конфигурацию: более поздние файлы
// переопределяют значения более ранних (так fail2ban применяет .local
// поверх .conf). Строки-продолжения (с отступом) дописываются к
// предыдущему значению — так обычно записан многострочный ignoreip.
func (c *ini) parse(data, source string) {
	sec, key := "", ""
	for raw := range strings.SplitSeq(data, "\n") {
		raw = strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(raw)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		// Строка с отступом продолжает значение предыдущего ключа.
		if key != "" && sec != "" && (raw[0] == ' ' || raw[0] == '\t') {
			c.vals[sec][key] += "\n" + stripInline(t)
			continue
		}
		if t[0] == '[' {
			if end := strings.IndexByte(t, ']'); end > 0 {
				sec, key = strings.TrimSpace(t[1:end]), ""
				if _, ok := c.vals[sec]; !ok {
					c.vals[sec] = map[string]string{}
					c.src[sec] = map[string]string{}
					c.order = append(c.order, sec)
				}
			}
			continue
		}
		if sec == "" {
			continue // ключ вне секции configparser отвергает
		}
		i := strings.IndexAny(t, "=:")
		if i <= 0 {
			key = ""
			continue
		}
		key = strings.ToLower(strings.TrimSpace(t[:i]))
		c.vals[sec][key] = stripInline(strings.TrimSpace(t[i+1:]))
		c.src[sec][key] = source
	}
}

// stripInline убирает комментарий в конце строки. fail2ban признаёт
// только «;» и только после пробела: «#» внутри значения (например, в
// регулярном выражении фильтра) комментарием не считается.
func stripInline(s string) string {
	for i := 1; i < len(s); i++ {
		if s[i] == ';' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

// raw — значение ключа секции с запасным значением из [DEFAULT].
func (c *ini) raw(sec, key string) (string, bool) {
	if v, ok := c.vals[sec][key]; ok {
		return v, true
	}
	v, ok := c.vals["DEFAULT"][key]
	return v, ok
}

// get — значение с подстановкой %(имя)s (интерполяция configparser).
// Глубина ограничена: ссылка на самого себя не зацикливает разбор.
func (c *ini) get(sec, key string) (string, bool) {
	v, ok := c.raw(sec, key)
	if !ok {
		return "", false
	}
	return c.interpolate(sec, v, 0), true
}

// maxValue — предел длины значения после подстановок: «a = %(a)s%(a)s»
// иначе разрастается экспоненциально.
const maxValue = 64 << 10

func (c *ini) interpolate(sec, v string, depth int) string {
	if depth > 10 || !strings.Contains(v, "%") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v) && b.Len() <= maxValue; i++ {
		if v[i] != '%' || i+1 >= len(v) {
			b.WriteByte(v[i])
			continue
		}
		if v[i+1] == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		end := strings.Index(v[i:], ")s")
		if v[i+1] != '(' || end < 0 {
			b.WriteByte(v[i])
			continue
		}
		name := strings.ToLower(v[i+2 : i+end])
		repl, ok := "", false
		if name == "__name__" {
			repl, ok = sec, true
		} else if r, found := c.raw(sec, name); found {
			repl, ok = c.interpolate(sec, r, depth+1), true
		}
		if !ok {
			// Неизвестная ссылка (например, на paths-*.conf, который не
			// разбирается) остаётся как есть.
			b.WriteString(v[i : i+end+2])
		} else {
			b.WriteString(repl)
		}
		i += end + 1
	}
	return b.String()
}

// readConfigSet читает базовый файл и его переопределения в порядке
// fail2ban: name.conf, name.d/*.conf, name.local, name.d/*.local. Возвращает
// объединённую конфигурацию и список прочитанных файлов (пути хоста).
func readConfigSet(hostRoot, name string) (*ini, []string) {
	c := newINI()
	var read []string
	dir := filepath.Join(hostRoot, "etc/fail2ban")
	add := func(path string) {
		data, _, err := safefile.ReadRegular(path, maxConfigFile, true)
		if err != nil {
			return
		}
		rel := hostPath(hostRoot, path)
		c.parse(string(data), rel)
		read = append(read, rel)
	}
	glob := func(pattern string) []string {
		m, _ := filepath.Glob(filepath.Join(dir, name+".d", pattern))
		sort.Strings(m)
		if len(m) > maxConfigFiles {
			m = m[:maxConfigFiles]
		}
		return m
	}
	add(filepath.Join(dir, name+".conf"))
	for _, p := range glob("*.conf") {
		add(p)
	}
	add(filepath.Join(dir, name+".local"))
	for _, p := range glob("*.local") {
		add(p)
	}
	return c, read
}

// hostPath — путь внутри хоста («/etc/...») по пути на диске сканера.
func hostPath(hostRoot, p string) string {
	return "/" + strings.TrimPrefix(strings.TrimPrefix(p, filepath.Clean(hostRoot)), "/")
}

// serverConfig — нужное из fail2ban.conf: куда пишется журнал и уровень.
type serverConfig struct {
	LogTarget string // путь или SYSTEMD-JOURNAL, SYSLOG, STDOUT, STDERR
	LogLevel  string
}

func readServerConfig(hostRoot string) serverConfig {
	c, _ := readConfigSet(hostRoot, "fail2ban")
	sc := serverConfig{LogTarget: defaultLogPath, LogLevel: "INFO"}
	if v, ok := c.get("Definition", "logtarget"); ok && strings.TrimSpace(v) != "" {
		sc.LogTarget = strings.TrimSpace(v)
	}
	if v, ok := c.get("Definition", "loglevel"); ok && strings.TrimSpace(v) != "" {
		sc.LogLevel = strings.ToUpper(strings.TrimSpace(v))
	}
	return sc
}

// logFile — путь журнала, если logtarget — файл. SYSTEMD-JOURNAL, SYSLOG,
// STDOUT и STDERR журналом-файлом не являются.
func (sc serverConfig) logFile() (string, bool) {
	t := sc.LogTarget
	if !strings.HasPrefix(t, "/") {
		return "", false
	}
	return filepath.Clean(t), true
}

// verbose — уровень журнала не выше INFO: строки «Found» (засчитанные
// попытки) пишутся только на INFO и подробнее.
func (sc serverConfig) verbose() bool {
	switch sc.LogLevel {
	case "CRITICAL", "ERROR", "WARNING", "NOTICE":
		return false
	}
	// Числовой уровень Python: INFO = 20.
	if n, err := strconv.Atoi(sc.LogLevel); err == nil {
		return n <= 20
	}
	return true
}

// jailConfig — включённые jail с параметрами.
type jailConfig struct {
	Jails []jail
	Files []string // прочитанные файлы
	// BanTimes — bantime каждой секции, включая выключенные jail и
	// DEFAULT: баны выключенного позже jail ещё могут действовать.
	BanTimes map[string]int64
}

type jail struct {
	Name      string
	Filter    string
	Port      string
	MaxRetry  int
	FindTime  int64
	BanTime   int64
	Increment bool
	IgnoreIP  []string
	Source    string
}

// SSH — jail защищает SSH: по имени (sshd, ssh, sshd-ddos) или фильтру.
func (j jail) SSH() bool {
	n := strings.ToLower(j.Name)
	return strings.Contains(n, "ssh") || strings.HasPrefix(strings.ToLower(j.Filter), "sshd")
}

// SSHJail сообщает, есть ли включённый jail fail2ban для SSH (проверка
// готовности в audit). Журналы при этом не читаются — только настройки.
func SSHJail(hostRoot string) bool {
	for _, j := range readJails(hostRoot).Jails {
		if j.SSH() {
			return true
		}
	}
	return false
}

// readJails разбирает jail.conf и переопределения и возвращает
// включённые jail. Секции DEFAULT и INCLUDES — служебные.
func readJails(hostRoot string) jailConfig {
	c, files := readConfigSet(hostRoot, "jail")
	jc := jailConfig{Files: files, BanTimes: map[string]int64{}}
	for _, sec := range c.order {
		if sec == "INCLUDES" {
			continue
		}
		if v, ok := c.get(sec, "bantime"); ok {
			if n, ok := parseDuration(v); ok {
				jc.BanTimes[sec] = n
			}
		}
		if sec == "DEFAULT" {
			continue
		}
		v, _ := c.get(sec, "enabled")
		if !parseBool(v) {
			continue
		}
		j := jail{Name: sec, MaxRetry: defaultMaxRetry, FindTime: defaultFindTime, BanTime: defaultBanTime}
		j.Source = c.src[sec]["enabled"]
		if j.Source == "" {
			j.Source = c.src["DEFAULT"]["enabled"]
		}
		if f, ok := c.get(sec, "filter"); ok {
			// «sshd[mode=aggressive]» — имя фильтра и его параметры.
			f = strings.TrimSpace(f)
			if i := strings.IndexByte(f, '['); i >= 0 {
				f = f[:i]
			}
			j.Filter = strings.TrimSpace(f)
		}
		if j.Filter == "" {
			j.Filter = sec
		}
		if p, ok := c.get(sec, "port"); ok {
			j.Port = strings.Join(strings.Fields(p), " ")
		}
		if v, ok := c.get(sec, "maxretry"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
				j.MaxRetry = n
			}
		}
		if v, ok := c.get(sec, "findtime"); ok {
			if n, ok := parseDuration(v); ok {
				j.FindTime = n
			}
		}
		if v, ok := c.get(sec, "bantime"); ok {
			if n, ok := parseDuration(v); ok {
				j.BanTime = n
			}
		}
		if v, ok := c.get(sec, "bantime.increment"); ok {
			j.Increment = parseBool(v)
		}
		if v, ok := c.get(sec, "ignoreip"); ok {
			j.IgnoreIP = strings.FieldsFunc(v, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
		}
		jc.Jails = append(jc.Jails, j)
	}
	sort.SliceStable(jc.Jails, func(i, k int) bool { return jc.Jails[i].Name < jc.Jails[k].Name })
	return jc
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "1", "on":
		return true
	}
	return false
}

// durationUnits — суффиксы времени, которые понимает fail2ban
// (str2seconds): «10m», «1h 30m», «1d», «1w», «2mo», «1y».
var durationUnits = map[string]int64{
	"s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
	"m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
	"h": 3600, "hour": 3600, "hours": 3600,
	"d": 86400, "day": 86400, "days": 86400,
	"w": 604800, "week": 604800, "weeks": 604800,
	"mo": 2629800, "mon": 2629800, "month": 2629800, "months": 2629800,
	"y": 31557600, "year": 31557600, "years": 31557600,
}

// maxDuration — больше ста лет — уже не срок бана, а ошибка в значении.
const maxDuration = 100 * 31557600

// parseDuration переводит время fail2ban в секунды. Отрицательное
// значение (bantime = -1) — навсегда.
func parseDuration(v string) (int64, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return 0, false
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		switch {
		case math.IsNaN(f) || f > maxDuration:
			return 0, false
		case f < 0:
			return -1, true
		}
		return int64(f), true
	}
	neg := strings.HasPrefix(v, "-")
	v = strings.TrimPrefix(v, "-")
	var total int64
	i, parts := 0, 0
	for i < len(v) {
		for i < len(v) && v[i] == ' ' {
			i++
		}
		if i >= len(v) {
			break
		}
		start := i
		for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == '.') {
			i++
		}
		num, err := strconv.ParseFloat(v[start:i], 64)
		if err != nil {
			return 0, false
		}
		for i < len(v) && v[i] == ' ' {
			i++
		}
		us := i
		for i < len(v) && v[i] >= 'a' && v[i] <= 'z' {
			i++
		}
		unit := int64(1)
		if us < i {
			u, ok := durationUnits[v[us:i]]
			if !ok {
				return 0, false
			}
			unit = u
		}
		if math.IsNaN(num) || num*float64(unit) > maxDuration {
			return 0, false
		}
		total += int64(num * float64(unit))
		parts++
		if parts > 10 || total > maxDuration {
			return 0, false
		}
	}
	if parts == 0 {
		return 0, false
	}
	if neg {
		return -1, true
	}
	return total, true
}

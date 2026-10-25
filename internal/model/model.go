// Пакет model описывает общие структуры данных: процесс, сокет, признак
// (finding), уровень риска, снимок сканирования и событие истории.
// Эти типы сериализуются в JSON и отдаются веб-интерфейсу как есть,
// поэтому имена полей JSON — часть публичного API.
package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
)

// Risk — уровень риска процесса или системной проверки.
// Значения упорядочены: чем больше число, тем выше риск.
type Risk int

const (
	RiskInfo Risk = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
)

var riskNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// String возвращает каноническое имя уровня (INFO, LOW, ...).
func (r Risk) String() string {
	if r < RiskInfo || r > RiskCritical {
		return fmt.Sprintf("Risk(%d)", int(r))
	}
	return riskNames[r]
}

// ParseRisk разбирает имя уровня без учёта регистра.
func ParseRisk(s string) (Risk, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	for i, n := range riskNames {
		if n == s {
			return Risk(i), true
		}
	}
	return RiskInfo, false
}

// MarshalJSON сериализует уровень строкой, чтобы JSON был читаемым.
func (r Risk) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// UnmarshalJSON принимает строковое имя уровня.
func (r *Risk) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, ok := ParseRisk(s)
	if !ok {
		return i18n.Errorf("err.unknown_risk", strconv.Quote(s))
	}
	*r = v
	return nil
}

// Категории признаков. Оценка риска учитывает, сколько разных
// категорий сработало: несколько независимых признаков весомее
// одного, даже очень «громкого».
const (
	CatLocation    = "location"    // расположение исполняемого файла или рабочего каталога
	CatIntegrity   = "integrity"   // целостность файла: удалён, memfd, права
	CatMasquerade  = "masquerade"  // маскировка имени, необычные имена
	CatChain       = "chain"       // подозрительная цепочка родитель → потомок
	CatNetwork     = "network"     // сетевые признаки
	CatContent     = "content"     // содержимое командной строки
	CatBehavior    = "behavior"    // поведение: длительная нагрузка CPU/RAM
	CatEnvironment = "environment" // переменные окружения (LD_PRELOAD)
	CatPrivilege   = "privilege"   // привилегии (root из записываемого каталога)
	CatPersistence = "persistence" // признаки закрепления в системе
	CatExposure    = "exposure"    // поверхность атаки: сервис доступен из сети
	CatInfo        = "info"        // справочные сведения, не влияют на оценку
)

// Finding — один сработавший признак. Evidence содержит проверяемые
// факты (что именно прочитано и откуда), а не выводы.
type Finding struct {
	ID             string     `json:"id"`
	Title          i18n.Msg   `json:"title"`
	Category       string     `json:"category"`
	Weight         int        `json:"weight"`
	Strong         bool       `json:"strong"`
	Evidence       []i18n.Msg `json:"evidence"`
	Recommendation i18n.Msg   `json:"recommendation"`
	// Suppressed — признак подавлен правилом allowlist; он показывается,
	// но не учитывается в оценке.
	Suppressed bool `json:"suppressed,omitempty"`
}

// Socket — сетевой сокет (TCP/UDP/Unix), прочитанный из /proc/net/*.
type Socket struct {
	Proto      string `json:"proto"` // tcp, tcp6, udp, udp6, unix
	LocalAddr  string `json:"localAddr"`
	LocalPort  int    `json:"localPort"`
	RemoteAddr string `json:"remoteAddr"`
	RemotePort int    `json:"remotePort"`
	State      string `json:"state"`
	Inode      uint64 `json:"inode"`
	UID        int    `json:"uid"`
	NetNS      string `json:"netns,omitempty"`
	Path       string `json:"path,omitempty"` // путь Unix-сокета
	// Владелец сокета (заполняется при сопоставлении с fd процессов).
	PID      int    `json:"pid,omitempty"`
	ProcKey  string `json:"procKey,omitempty"`
	ProcName string `json:"procName,omitempty"`
	User     string `json:"user,omitempty"`
}

// IsLoopback сообщает, что удалённый или локальный адрес — петлевой.
func IsLoopback(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1" || strings.HasPrefix(addr, "::ffff:127.")
}

// OpenFile — открытый дескриптор процесса (цель симлинка /proc/PID/fd/N).
type OpenFile struct {
	FD     int    `json:"fd"`
	Target string `json:"target"`
	Kind   string `json:"kind"` // file, socket, pipe, anon, memfd, deleted, device
}

// FileInfo — сведения об исполняемом файле (stat через /proc/PID/exe).
type FileInfo struct {
	Mode          string    `json:"mode"`
	UID           int       `json:"uid"`
	Size          int64     `json:"size"`
	ModTime       time.Time `json:"modTime"`
	WorldWritable bool      `json:"worldWritable"`
	SetUID        bool      `json:"setuid"`
	SetGID        bool      `json:"setgid"`
}

// Process — всё, что удалось собрать о процессе, плюс результат анализа.
type Process struct {
	// Key = "PID-starttime": PID переиспользуется, а пара с временем
	// старта однозначно определяет экземпляр процесса.
	Key     string   `json:"key"`
	PID     int      `json:"pid"`
	PPID    int      `json:"ppid"`
	Name    string   `json:"name"` // comm, до 15 символов
	State   string   `json:"state"`
	UID     int      `json:"uid"`
	EUID    int      `json:"euid"`
	GID     int      `json:"gid"`
	User    string   `json:"user"`
	Cmdline string   `json:"cmdline"` // секреты замаскированы
	Args    []string `json:"args"`
	// CmdlineTruncated — командная строка длиннее лимита сканера и
	// прочитана не целиком (см. procfs.Limits).
	CmdlineTruncated bool      `json:"cmdlineTruncated,omitempty"`
	Exe              string    `json:"exe"`
	ExeDeleted       bool      `json:"exeDeleted"`
	Cwd              string    `json:"cwd"`
	StartTime        time.Time `json:"startTime"`
	StartTicks       uint64    `json:"-"`
	CPUTicks         uint64    `json:"-"` // utime+stime в тиках
	Threads          int       `json:"threads"`
	RSSBytes         uint64    `json:"rssBytes"`
	VMSBytes         uint64    `json:"vmsBytes"`
	MemPercent       float64   `json:"memPercent"`
	CPUPercent       float64   `json:"cpuPercent"`
	// CPUAverage — CPU посчитан как среднее с момента запуска (первое
	// наблюдение процесса, мгновенного значения ещё нет).
	CPUAverage bool `json:"cpuAverage"`
	Kernel     bool `json:"kernel"`

	Container        string            `json:"container,omitempty"`
	ContainerRuntime string            `json:"containerRuntime,omitempty"`
	Namespaces       map[string]string `json:"namespaces,omitempty"`
	ForeignNS        []string          `json:"foreignNs,omitempty"` // какие ns отличаются от PID 1
	NSPID            []int             `json:"nspid,omitempty"`

	Children []int      `json:"children"`
	FDCount  int        `json:"fdCount"`
	Files    []OpenFile `json:"files,omitempty"`
	Sockets  []Socket   `json:"sockets,omitempty"`
	EnvFlags []string   `json:"envFlags,omitempty"` // только имена опасных переменных
	ExeInfo  *FileInfo  `json:"exeInfo,omitempty"`
	// Access — что не удалось прочитать (обычно из-за прав).
	Access []string `json:"access,omitempty"`

	Findings        []Finding  `json:"findings"`
	Score           int        `json:"score"`
	Risk            Risk       `json:"risk"`
	Explanation     i18n.Msg   `json:"explanation"`
	Recommendations []i18n.Msg `json:"recommendations"`
	FirstSeen       time.Time  `json:"firstSeen"`
	LastSeen        time.Time  `json:"lastSeen"`
}

// SystemFinding — результат системной проверки (cron, systemd, ld.so.preload...).
type SystemFinding struct {
	Finding
	Path    string    `json:"path"`
	Risk    Risk      `json:"risk"`
	ModTime time.Time `json:"modTime,omitempty"`
}

// HostInfo — сведения о сервере и об условиях сканирования.
type HostInfo struct {
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Kernel      string    `json:"kernel"`
	BootTime    time.Time `json:"bootTime"`
	IsRoot      bool      `json:"isRoot"`
	InContainer bool      `json:"inContainer"`
	MemTotal    uint64    `json:"memTotal"`
}

// Stats — сводка по снимку.
type Stats struct {
	Total      int            `json:"total"`
	Kernel     int            `json:"kernel"`
	ByRisk     map[string]int `json:"byRisk"`
	Restricted int            `json:"restricted"` // процессы с неполными данными
	Sockets    int            `json:"sockets"`
	// PublicPorts — слушающие порты, доступные из интернета; DangerousPorts —
	// из них известные опасные сервисы (без подавленных allowlist).
	PublicPorts    int `json:"publicPorts"`
	DangerousPorts int `json:"dangerousPorts"`
}

// Snapshot — результат одного сканирования.
type Snapshot struct {
	Time      time.Time           `json:"time"`
	Duration  time.Duration       `json:"duration"`
	Seq       uint64              `json:"seq"`
	Host      HostInfo            `json:"host"`
	Processes []*Process          `json:"processes"`
	Sockets   []Socket            `json:"sockets"`
	System    []SystemFinding     `json:"system"`
	Exposure  *ExposureReport     `json:"exposure,omitempty"`
	Warnings  []i18n.Msg          `json:"warnings"`
	Stats     Stats               `json:"stats"`
	ByKey     map[string]*Process `json:"-"`
}

// Области видимости адреса, на котором слушает сокет.
const (
	ScopeLoopback = "loopback" // 127.0.0.0/8, ::1 — только с самого сервера
	ScopePrivate  = "private"  // частные сети: 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, link-local
	ScopePublic   = "public"   // всё остальное, включая 0.0.0.0 и :: (все интерфейсы)
	ScopeNetNS    = "netns"    // отдельное сетевое пространство имён (контейнер): снаружи доступен только через опубликованный порт
)

// Состояние межсетевого экрана для конкретного порта.
const (
	FwOpen     = "open"     // ufw разрешает порт с любых адресов
	FwFiltered = "filtered" // ufw включён и не разрешает порт всем
	FwBypassed = "bypassed" // порт опубликован Docker: его правила iptables срабатывают раньше ufw
)

// IfaceAddr — локальный адрес сервера.
type IfaceAddr struct {
	Iface string `json:"iface,omitempty"` // имя интерфейса (известно только для IPv6)
	Addr  string `json:"addr"`
	Scope string `json:"scope"`
}

// Service — сервис, узнанный на слушающем порту.
type Service struct {
	ID    string `json:"id"`    // redis, mongodb, docker_api...
	Name  string `json:"name"`  // имя для людей: Redis, MongoDB
	Class string `json:"class"` // database, docker_api, admin_panel, remote_access, file_sharing, info_service
	// Match — как узнан: port+process, process, port+image, image, port.
	// Только по порту — наименее надёжно: на порту может быть другая программа.
	Match string `json:"match"`
}

// PortBinding — порт контейнера Docker, опубликованный на хосте.
type PortBinding struct {
	ContainerID   string `json:"containerId,omitempty"`
	ContainerName string `json:"containerName,omitempty"`
	Image         string `json:"image,omitempty"`
	Proto         string `json:"proto"` // tcp, udp
	HostIP        string `json:"hostIp"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	// Source — откуда известно: docker-proxy (аргументы процесса) или
	// config (config.v2.json контейнера).
	Source string `json:"source"`
}

// Exposure — слушающий сокет (или опубликованный порт контейнера) с
// оценкой того, откуда он доступен и насколько это опасно.
type Exposure struct {
	Proto         string       `json:"proto"` // tcp, tcp6, udp, udp6
	Addr          string       `json:"addr"`
	Port          int          `json:"port"`
	Scope         string       `json:"scope"`
	AllInterfaces bool         `json:"allInterfaces,omitempty"` // 0.0.0.0 или ::
	NetNS         string       `json:"netns,omitempty"`
	Inode         uint64       `json:"inode,omitempty"`
	PID           int          `json:"pid,omitempty"`
	ProcKey       string       `json:"procKey,omitempty"`
	ProcName      string       `json:"procName,omitempty"`
	User          string       `json:"user,omitempty"`
	Exe           string       `json:"exe,omitempty"`
	Container     string       `json:"container,omitempty"`
	Service       *Service     `json:"service,omitempty"`
	Docker        *PortBinding `json:"docker,omitempty"`
	Firewall      string       `json:"firewall,omitempty"`
	// Risk — опасность доступности сервиса (не процесса): INFO, если
	// сервис не узнан или порт не публичный.
	Risk           Risk       `json:"risk"`
	FindingID      string     `json:"findingId,omitempty"`
	Evidence       []i18n.Msg `json:"evidence,omitempty"`
	Recommendation i18n.Msg   `json:"recommendation,omitzero"`
	// Suppressed — признак подавлен allowlist (уровень при этом INFO).
	Suppressed bool `json:"suppressed,omitempty"`
}

// FirewallInfo — что известно о межсетевом экране ufw.
type FirewallInfo struct {
	// UFW: absent (не установлен), inactive, active.
	UFW string `json:"ufw"`
	// DefaultInput — политика входящих по умолчанию (DROP, REJECT, ACCEPT).
	DefaultInput string `json:"defaultInput,omitempty"`
	Rules        int    `json:"rules"` // число разобранных правил user.rules/user6.rules
}

// ExposureReport — внешняя поверхность атаки по данным одного сканирования.
type ExposureReport struct {
	Entries  []Exposure    `json:"entries"`
	Addrs    []IfaceAddr   `json:"addrs"`
	Firewall FirewallInfo  `json:"firewall"`
	Bindings []PortBinding `json:"bindings"`
	Warnings []i18n.Msg    `json:"warnings,omitempty"`
}

// Типы событий истории.
const (
	EvBaseline = "baseline"  // первое сканирование после запуска с пустой историей
	EvStarted  = "started"   // появился новый процесс
	EvExited   = "exited"    // процесс завершился
	EvChanged  = "changed"   // у процесса сменились exe/cmdline/пользователь (execve, setuid)
	EvRiskUp   = "risk_up"   // уровень риска вырос
	EvRiskDown = "risk_down" // уровень риска снизился
	EvFinding  = "finding"   // появился новый признак
	EvListen   = "listen"    // процесс начал слушать порт
	EvSystem   = "system"    // новый результат системной проверки
)

// Event — запись в истории изменений.
type Event struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Key     string    `json:"key,omitempty"`
	PID     int       `json:"pid,omitempty"`
	Name    string    `json:"name,omitempty"`
	User    string    `json:"user,omitempty"`
	Exe     string    `json:"exe,omitempty"`
	Details i18n.Msg  `json:"details"`
	Risk    Risk      `json:"risk"`
}

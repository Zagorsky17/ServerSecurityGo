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
	// TxQueue, RxQueue — поле tx_queue:rx_queue из /proc/net/tcp. У
	// слушающего сокета это backlog и текущая длина очереди accept
	// (сколько соединений ждёт, пока приложение их примет), у
	// остальных — байты в очередях отправки и приёма.
	TxQueue uint64 `json:"txQueue,omitempty"`
	RxQueue uint64 `json:"rxQueue,omitempty"`
	Path    string `json:"path,omitempty"` // путь Unix-сокета
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
	// NetAlerts — сработавшие признаки сетевой нагрузки (netload).
	NetAlerts int `json:"netAlerts"`
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
	Fail2ban  *Fail2banReport     `json:"fail2ban,omitempty"`
	NetLoad   *NetLoadReport      `json:"netLoad,omitempty"`
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

// Fail2banJail — включённый jail fail2ban: параметры из конфигурации и
// счётчики из журнала за окно отчёта.
type Fail2banJail struct {
	Name   string `json:"name"`
	Filter string `json:"filter,omitempty"`
	Port   string `json:"port,omitempty"`
	// MaxRetry, FindTime, BanTime — как в jail.local; время в секундах,
	// BanTime < 0 — бан навсегда.
	MaxRetry  int   `json:"maxRetry"`
	FindTime  int64 `json:"findTime"`
	BanTime   int64 `json:"banTime"`
	Increment bool  `json:"banTimeIncrement,omitempty"`
	// IgnoreIP — адреса и сети, которые jail никогда не банит.
	IgnoreIP []string `json:"ignoreIp,omitempty"`
	// Source — файл, в котором jail включён (enabled = true).
	Source string `json:"source,omitempty"`
	SSH    bool   `json:"ssh,omitempty"` // jail защищает SSH
	Found  int    `json:"found"`         // попыток за окно
	Bans   int    `json:"bans"`          // банов за окно
	Banned int    `json:"banned"`        // забанено сейчас
}

// Fail2banBan — текущая блокировка, восстановленная по журналу.
type Fail2banBan struct {
	IP    string    `json:"ip"`
	Jail  string    `json:"jail"`
	Since time.Time `json:"since"`
	// Until — когда бан истечёт; нулевое при Permanent.
	Until     time.Time `json:"until,omitzero"`
	Permanent bool      `json:"permanent,omitempty"`
	// Restored — бан восстановлен после перезапуска fail2ban (Restore Ban):
	// Since — время восстановления, а не первого бана.
	Restored bool `json:"restored,omitempty"`
	// Count — сколько раз этот IP банили за окно (рецидивисты).
	Count int `json:"count"`
	// UnbanCommand — команда разблокировки. Только текст: приложение её
	// не выполняет.
	UnbanCommand string `json:"unbanCommand,omitempty"`
}

// Fail2banBucket — попытки и баны за интервал (час или сутки).
type Fail2banBucket struct {
	Time  time.Time `json:"time"`
	Found int       `json:"found"`
	Bans  int       `json:"bans"`
}

// Fail2banSource — IP или подсеть с числом попыток за окно.
type Fail2banSource struct {
	Addr  string   `json:"addr"` // IP или сеть /24 (/64 для IPv6)
	Found int      `json:"found"`
	Bans  int      `json:"bans"`
	IPs   int      `json:"ips,omitempty"` // для подсети — сколько разных IP
	Jails []string `json:"jails,omitempty"`
	// Ignored — адрес из ignoreip: fail2ban видит перебор, но не банит.
	Ignored bool `json:"ignored,omitempty"`
}

// Fail2banEvent — событие журнала fail2ban (бан, разбан, перезапуск).
type Fail2banEvent struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"` // ban, unban, restore, increase, start, stop
	Jail   string    `json:"jail,omitempty"`
	IP     string    `json:"ip,omitempty"`
}

// Fail2banReport — состояние fail2ban и интенсивность перебора паролей.
// Installed = false — fail2ban на сервере нет, остальные поля пусты, и
// интерфейсы раздел не показывают.
type Fail2banReport struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	Version   string `json:"version,omitempty"` // из журнала: «Starting Fail2ban v1.0.2»
	// LogTarget — logtarget из fail2ban.conf (путь, SYSTEMD-JOURNAL, SYSLOG...).
	LogTarget string `json:"logTarget,omitempty"`
	// LogFiles — прочитанные файлы журнала (с ротированными).
	LogFiles []string `json:"logFiles,omitempty"`
	// LogAvailable — журнал прочитан: статистика и баны достоверны.
	LogAvailable bool             `json:"logAvailable"`
	Days         int              `json:"days"`
	From         time.Time        `json:"from"`
	Jails        []Fail2banJail   `json:"jails"`
	Bans         []Fail2banBan    `json:"bans"`
	Hourly       []Fail2banBucket `json:"hourly"`
	Daily        []Fail2banBucket `json:"daily"`
	Top          []Fail2banSource `json:"top"`
	TopNets      []Fail2banSource `json:"topNets"`
	Recent       []Fail2banEvent  `json:"recent"`
	Found        int              `json:"found"`    // попыток за окно
	BanCount     int              `json:"banCount"` // банов за окно
	Found24h     int              `json:"found24h"`
	Bans24h      int              `json:"bans24h"`
	Peak         Fail2banBucket   `json:"peak"` // час с наибольшим числом попыток
	Warnings     []i18n.Msg       `json:"warnings,omitempty"`
}

// PortLoad — нагрузка на один слушающий порт сервера.
type PortLoad struct {
	Proto string `json:"proto"` // tcp или udp
	Port  int    `json:"port"`
	Addr  string `json:"addr,omitempty"`
	// Процесс, который слушает порт (если известен).
	PID      int    `json:"pid,omitempty"`
	ProcName string `json:"procName,omitempty"`
	ProcKey  string `json:"procKey,omitempty"`
	// HalfOpen — полуоткрытые соединения (SYN_RECV и NEW_SYN_RECV):
	// клиент начал рукопожатие и не ответил. При SYN-флуде их много.
	HalfOpen    int `json:"halfOpen"`
	Established int `json:"established"`
	// AcceptQueue, Backlog — очередь принятия соединений и её предел:
	// очередь у предела означает, что приложение не успевает принимать.
	AcceptQueue int `json:"acceptQueue"`
	Backlog     int `json:"backlog"`
	// Sources — сколько разных удалённых адресов.
	Sources int `json:"sources"`
}

// SourceLoad — один источник соединений: отдельный адрес или подсеть.
type SourceLoad struct {
	Addr string `json:"addr"` // IP или CIDR подсети
	// Subnet — строка описывает подсеть (/24 для IPv4, /64 для IPv6).
	Subnet bool `json:"subnet,omitempty"`
	Conns  int  `json:"conns"`
	// HalfOpen — из них полуоткрытых.
	HalfOpen int `json:"halfOpen"`
	// Addresses — сколько разных адресов в подсети.
	Addresses int   `json:"addresses,omitempty"`
	Ports     []int `json:"ports"`
	// Trusted — адрес входит в SSG_NET_TRUSTED_NETS (CDN, прокси):
	// источником флуда не считается.
	Trusted bool `json:"trusted,omitempty"`
	// Private — частная сеть: свой прокси или соседний контейнер.
	Private bool `json:"private,omitempty"`
}

// NetLoadCounters — скорости счётчиков ядра (в секунду) и мгновенные
// значения на момент замера.
type NetLoadCounters struct {
	// Скорости (в секунду).
	CookiesSent     float64 `json:"cookiesSent"`
	CookiesRecv     float64 `json:"cookiesRecv"`
	CookiesFailed   float64 `json:"cookiesFailed"`
	ListenOverflows float64 `json:"listenOverflows"`
	ListenDrops     float64 `json:"listenDrops"`
	ReqQFullDrop    float64 `json:"reqQFullDrop"`
	BacklogDrop     float64 `json:"backlogDrop"`
	AbortOnMemory   float64 `json:"abortOnMemory"`
	PassiveOpens    float64 `json:"passiveOpens"`
	AttemptFails    float64 `json:"attemptFails"`
	RetransSegs     float64 `json:"retransSegs"`
	UDPNoPorts      float64 `json:"udpNoPorts"`
	UDPInErrors     float64 `json:"udpInErrors"`
	UDPRcvbufErrors float64 `json:"udpRcvbufErrors"`
	RxDrops         float64 `json:"rxDrops"`
	SoftnetDropped  float64 `json:"softnetDropped"`
	TimeSqueeze     float64 `json:"timeSqueeze"`
	PPSIn           float64 `json:"ppsIn"`
	PPSOut          float64 `json:"ppsOut"`
	// Мгновенные значения.
	CurrEstab   int `json:"currEstab"`
	TCPInuse    int `json:"tcpInuse"`
	TCPOrphan   int `json:"tcpOrphan"`
	TCPTimeWait int `json:"tcpTimeWait"`
	UDPInuse    int `json:"udpInuse"`
	// Пределы ядра (/proc/sys): для процентов и рекомендаций.
	MaxSynBacklog int `json:"maxSynBacklog"`
	MaxOrphans    int `json:"maxOrphans"`
	SomaxConn     int `json:"somaxconn"`
	SynCookies    int `json:"synCookies"`
	// Average — скорости посчитаны за время с загрузки (первый замер).
	Average bool `json:"average,omitempty"`
}

// ConntrackInfo — таблица отслеживания соединений. nil в отчёте —
// модуль conntrack не загружен (без firewall и Docker его нет).
type ConntrackInfo struct {
	Count   int     `json:"count"`
	Max     int     `json:"max"`
	Percent float64 `json:"percent"`
	// Скорости потерь (в секунду): ядро уже теряет соединения.
	Drop         float64 `json:"drop"`
	EarlyDrop    float64 `json:"earlyDrop"`
	InsertFailed float64 `json:"insertFailed"`
}

// NetLoadReport — сетевая нагрузка и признаки атаки. Только наблюдение:
// приложение ничего не блокирует и не меняет правила firewall.
type NetLoadReport struct {
	Time       time.Time       `json:"time"`
	Listen     []PortLoad      `json:"listen"`
	TopSources []SourceLoad    `json:"topSources"`
	Counters   NetLoadCounters `json:"counters"`
	Conntrack  *ConntrackInfo  `json:"conntrack,omitempty"`
	// Truncated — таблица сокетов больше SSG_NET_MAX_SOCKETS: показаны
	// не все соединения, числа занижены.
	Truncated bool `json:"truncated,omitempty"`
	Dropped   int  `json:"dropped,omitempty"`
	// Active — ID сработавших признаков (net_*).
	Active []string `json:"active"`
	// Baseline — есть ли база «как обычно» (метрик меньше шести часов —
	// относительные пороги не применяются).
	Baseline bool `json:"baseline"`
	// TrustedNets — заданные владельцем доверенные сети.
	TrustedNets []string `json:"trustedNets,omitempty"`
}

// Статусы проверки аудита конфигурации.
const (
	AuditPass    = "pass"    // настройка в порядке
	AuditFail    = "fail"    // настройка опасна
	AuditWarn    = "warn"    // стоит проверить или улучшить
	AuditInfo    = "info"    // совет или справка, на «пройдено N из M» не влияет
	AuditNA      = "n/a"     // неприменимо (например, sshd не установлен)
	AuditUnknown = "unknown" // нет прав на чтение или данных
)

// Группы проверок аудита.
const (
	AuditGroupSSH      = "ssh"
	AuditGroupAccounts = "accounts"
	AuditGroupSudo     = "sudo"
	AuditGroupKernel   = "kernel"
)

// AuditCheck — результат одной проверки конфигурации. Severity —
// важность проверки при провале (для pass — та же важность, чтобы было
// видно, что именно проверено).
type AuditCheck struct {
	ID             string     `json:"id"`
	Group          string     `json:"group"`
	Title          i18n.Msg   `json:"title"`
	Status         string     `json:"status"`
	Severity       Risk       `json:"severity"`
	Evidence       []i18n.Msg `json:"evidence,omitempty"`
	Recommendation i18n.Msg   `json:"recommendation,omitzero"`
	// FixCommand — готовая команда исправления. Только текст: приложение
	// ничего не выполняет, команду запускает администратор.
	FixCommand string   `json:"fixCommand,omitempty"`
	References []string `json:"references,omitempty"` // MITRE ATT&CK и т. п.
	// Change — проверка изменений (новый пользователь, правка sudoers):
	// возврат в pass означает «изменение устарело», а не «исправлено».
	Change bool `json:"change,omitempty"`
}

// AuditReport — результат одного запуска аудита.
type AuditReport struct {
	Time     time.Time     `json:"time"`
	Duration time.Duration `json:"duration"`
	Checks   []AuditCheck  `json:"checks"`
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
	EvAudit    = "audit"     // изменился результат проверки аудита конфигурации
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

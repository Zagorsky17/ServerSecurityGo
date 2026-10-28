// Пакет netload наблюдает за сетевой нагрузкой сервера и ищет признаки
// атаки: SYN-флуд, наплыв соединений с одного адреса или подсети,
// переполнение очереди accept и таблицы conntrack, отбросы пакетов.
//
// Только наблюдение. Приложение не блокирует адреса, не меняет правила
// firewall и не создаёт нагрузку: в рекомендациях даются готовые
// команды, а применяет их владелец сервера. Объёмную атаку, которая
// забивает канал до сервера, изнутри не видно вообще — видны только
// последствия, и об этом интерфейс говорит прямо.
//
// Счётчики ядра (/proc/net/netstat, snmp, sockstat, softnet_stat,
// conntrack) снимает горутина метрик каждые SSG_METRICS_INTERVAL:
// атака развивается за секунды, а интервал сканирования процессов (30 с)
// для этого слишком редкий. Таблицы сокетов разбираются в ScanOnce —
// там они уже прочитаны.
package netload

import (
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// maxProcFile — предел чтения одного файла /proc.
const maxProcFile = 8 << 20

// Пороги по умолчанию (таблица 16.3 плана). Стартовые: их нужно
// уточнять на живом сервере, поэтому они собраны в одном месте.
const (
	// cookiesRate — SYN cookies в секунду: ядро отвечает ими, когда
	// очередь полуоткрытых соединений переполнена.
	cookiesRate = 50
	// halfOpenMin — полуоткрытых соединений на порт, с которого есть
	// смысл говорить о флуде (вместе с долей от backlog).
	halfOpenMin   = 256
	halfOpenShare = 0.5
	halfOpenHigh  = 0.9
	// listenDropsRate — отбросы на слушающем сокете в секунду.
	listenDropsRate = 10
	// acceptQueueShare — доля очереди accept, с которой приложение
	// считается не успевающим принимать соединения.
	acceptQueueShare = 0.9
	// conntrackShare, conntrackHigh — заполненность таблицы conntrack.
	conntrackShare = 0.8
	conntrackHigh  = 0.95
	// orphanShare — доля tcp_max_orphans.
	orphanShare = 0.5
	// udpRcvbufRate, udpNoPortsRate — UDP в секунду.
	udpRcvbufRate  = 100
	udpNoPortsRate = 1000
	// rxDropsRate — отбросы на приёме в секунду.
	rxDropsRate = 1000
	// ppsSurge, connSurge — абсолютные пороги для «наплыва».
	ppsSurge    = 50_000
	connSurge   = 1000
	subnetAddrs = 20
	// privateFactor — для частных сетей порог в четыре раза выше: это
	// обычно свой прокси или соседние контейнеры.
	privateFactor = 4
)

// Времена удержания и гистерезис (16.2): признак появляется, только
// если условие держится, и снимается после clearAfter без превышения.
const (
	holdSyn       = 30 * time.Second
	holdDrops     = time.Minute
	holdConntrack = time.Minute
	holdSurge     = 2 * time.Minute
	clearAfter    = 5 * time.Minute
	// connStreak — сколько сканирований подряд должен держаться признак
	// по соединениям (таблица читается раз в сканирование).
	connStreak = 2
)

// maxSources, maxPorts — сколько источников и портов показывать.
const (
	maxSources = 20
	maxPorts   = 6
	// maxIPs — предел размера карты агрегатов по адресам: под атакой
	// адресов бывают сотни тысяч.
	maxIPs = 50_000
)

// Config — настройки наблюдения (SSG_NET_*).
type Config struct {
	// ConnPerIP — соединений с одного адреса, после которых появляется
	// признак net_conn_flood_ip (SSG_NET_CONN_PER_IP).
	ConnPerIP int
	// SurgeFactor — во сколько раз выше обычного считается наплывом
	// (SSG_NET_SURGE_FACTOR).
	SurgeFactor float64
	// Trusted — доверенные сети (CDN, прокси, балансировщик): их
	// адреса не считаются источниками флуда (SSG_NET_TRUSTED_NETS).
	Trusted []netip.Prefix
	// TrustedRaw — те же сети в исходном виде (для интерфейса).
	TrustedRaw []string
}

// DefaultConfig — пороги по умолчанию.
func DefaultConfig() Config {
	return Config{ConnPerIP: 200, SurgeFactor: 5}
}

// ParseNets разбирает список CIDR через запятую (SSG_NET_TRUSTED_NETS).
// Возвращает разобранные сети и строки, которые разобрать не удалось.
func ParseNets(s string) ([]netip.Prefix, []string, []string) {
	var nets []netip.Prefix
	var raw, bad []string
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			nets = append(nets, p.Masked())
			raw = append(raw, part)
			continue
		}
		// Одиночный адрес без маски — тоже допустимо.
		if a, err := netip.ParseAddr(part); err == nil {
			nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
			raw = append(raw, part)
			continue
		}
		bad = append(bad, part)
	}
	return nets, raw, bad
}

// Options — параметры наблюдателя.
type Options struct {
	Config
	// ProcRoot — корень /proc (SSG_PROC_ROOT).
	ProcRoot string
	// Baseline — медиана ряда метрик за окно (metrics.Collector.Median);
	// nil — относительные пороги не применяются.
	Baseline func(key string, window time.Duration) (float64, bool)
	// Allowed — правило allowlist подавляет признак (detect.Config.Allowed
	// без процесса: признаки netload не привязаны к процессу).
	Allowed func(id string) bool
	// FastHolds — признаки появляются почти сразу, а не через 30–120
	// секунд удержания (только демо: иначе их не увидеть за время
	// показа).
	FastHolds bool
}

// Monitor хранит состояние наблюдения: прошлые значения счётчиков,
// удержание признаков и последний отчёт.
type Monitor struct {
	opt Options

	mu        sync.RWMutex
	prev      rawCounters
	counters  model.NetLoadCounters
	conntrack *model.ConntrackInfo
	holds     map[string]*holdState
	// counterFindings — признаки по счётчикам ядра: их пересчитывает
	// горутина метрик, а в снимок они попадают при сканировании.
	counterFindings []model.SystemFinding
	report          *model.NetLoadReport
	// connFindings — признаки по таблицам сокетов (пересчитываются при
	// сканировании), findings — общий список со сводным признаком.
	connFindings []model.SystemFinding
	findings     []model.SystemFinding
	streak       map[string]int
	// conns — число входящих соединений на публичные порты при
	// последних сканированиях (для «в N раз больше обычного»).
	conns []connPoint
}

type connPoint struct {
	t time.Time
	n int
}

// New создаёт наблюдателя.
func New(opt Options) *Monitor {
	if opt.ProcRoot == "" {
		opt.ProcRoot = "/proc"
	}
	if opt.ConnPerIP <= 0 {
		opt.ConnPerIP = DefaultConfig().ConnPerIP
	}
	if opt.SurgeFactor <= 0 {
		opt.SurgeFactor = DefaultConfig().SurgeFactor
	}
	return &Monitor{opt: opt, holds: map[string]*holdState{}, streak: map[string]int{}}
}

// Report возвращает последний отчёт (nil — сканирования ещё не было).
func (m *Monitor) Report() *model.NetLoadReport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.report
}

// Findings возвращает системные признаки: по счётчикам ядра и по
// таблицам сокетов, вместе со сводным net_ddos_suspected.
func (m *Monitor) Findings() []model.SystemFinding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]model.SystemFinding(nil), m.findings...)
}

// rawCounters — сырые счётчики одного чтения /proc/net/*.
type rawCounters struct {
	time time.Time
	// TcpExt и Tcp/Udp из netstat и snmp.
	tcpExt, tcp, udp map[string]uint64
	// Сокеты по состояниям из sockstat (+ sockstat6).
	tcpInuse, tcpOrphan, tcpTW, udpInuse uint64
	// Пределы ядра.
	maxSynBacklog, maxOrphans, somaxconn, synCookies int
	// conntrack: count, max и счётчики потерь.
	ctCount, ctMax                      int
	ctDrop, ctEarlyDrop, ctInsertFailed uint64
	softnetDropped, softnetSqueeze      uint64
	rxDrops, rxPackets, txPackets       uint64
}

func (m *Monitor) path(parts ...string) string {
	return filepath.Join(append([]string{m.opt.ProcRoot}, parts...)...)
}

// readFile читает файл /proc с лимитом размера.
func readFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcFile))
	return string(data), err
}

// sysctlInt — числовой параметр /proc/sys; ok = false, если файла нет.
func (m *Monitor) sysctlInt(name string) (int, bool) {
	data, err := readFile(m.path("sys", name))
	if err != nil {
		return 0, false
	}
	f := strings.Fields(data)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(f[0])
	return v, err == nil
}

// read снимает все счётчики. Отсутствие отдельного файла не ошибка:
// conntrack бывает не загружен, sockstat6 — выключен IPv6.
func (m *Monitor) read(now time.Time) rawCounters {
	r := rawCounters{time: now}
	if data, err := readFile(m.path("net", "netstat")); err == nil {
		r.tcpExt = ParsePairs(data)["TcpExt"]
	}
	if data, err := readFile(m.path("net", "snmp")); err == nil {
		p := ParsePairs(data)
		r.tcp, r.udp = p["Tcp"], p["Udp"]
	}
	for _, name := range []string{"sockstat", "sockstat6"} {
		data, err := readFile(m.path("net", name))
		if err != nil {
			continue
		}
		st := ParseSockstat(data)
		r.tcpInuse += st["TCP"]["inuse"]
		r.tcpOrphan += st["TCP"]["orphan"]
		r.tcpTW += st["TCP"]["tw"]
		r.udpInuse += st["UDP"]["inuse"]
	}
	r.maxSynBacklog, _ = m.sysctlInt("net/ipv4/tcp_max_syn_backlog")
	r.maxOrphans, _ = m.sysctlInt("net/ipv4/tcp_max_orphans")
	r.somaxconn, _ = m.sysctlInt("net/core/somaxconn")
	r.synCookies, _ = m.sysctlInt("net/ipv4/tcp_syncookies")
	if v, ok := m.sysctlInt("net/netfilter/nf_conntrack_count"); ok {
		r.ctCount = v
		r.ctMax, _ = m.sysctlInt("net/netfilter/nf_conntrack_max")
	}
	if data, err := readFile(m.path("net", "stat", "nf_conntrack")); err == nil {
		st := ParseHexStat(data)
		r.ctDrop, r.ctEarlyDrop, r.ctInsertFailed = st["drop"], st["early_drop"], st["insert_failed"]
	}
	if data, err := readFile(m.path("net", "softnet_stat")); err == nil {
		r.softnetDropped, r.softnetSqueeze = ParseSoftnet(data)
	}
	if data, err := readFile(m.path("net", "dev")); err == nil {
		for _, n := range parseNetDev(data) {
			r.rxDrops += n.rxDrop + n.rxFifo
			r.rxPackets += n.rxPackets
			r.txPackets += n.txPackets
		}
	}
	return r
}

// netDev — счётчики одного интерфейса (без lo).
type netDev struct {
	rxPackets, rxDrop, rxFifo, txPackets uint64
}

// parseNetDev разбирает /proc/net/dev. Свой разбор, а не общий с
// metrics: здесь нужны только счётчики пакетов и отбросов, зато со
// всеми интерфейсами сразу.
func parseNetDev(data string) []netDev {
	var out []netDev
	for line := range strings.SplitSeq(data, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if name = strings.TrimSpace(name); name == "" || name == "lo" || strings.Contains(name, "|") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 12 {
			continue
		}
		num := func(i int) uint64 {
			v, _ := strconv.ParseUint(f[i], 10, 64)
			return v
		}
		out = append(out, netDev{rxPackets: num(1), rxDrop: num(3), rxFifo: num(4), txPackets: num(9)})
	}
	return out
}

// Ряды, которые netload добавляет в кольцевые буферы метрик. Имена —
// публичный API /api/metrics.
const (
	KeySynRate       = "net_syn_rate"     // SYN cookies в секунду
	KeyCookiesFailed = "net_cookies_fail" // неудачных cookies в секунду
	KeyListenDrops   = "net_listen_drops" // отбросов на слушающих сокетах в секунду
	KeyConntrackPct  = "net_conntrack"    // заполненность conntrack, %
	KeyRxDrops       = "net_rx_drops"     // отбросов на приёме в секунду
	KeyUDPErrors     = "net_udp_errors"   // ошибок UDP в секунду
	KeyEstab         = "net_estab"        // установленных соединений
	KeyOrphan        = "net_orphan"       // сокетов без владельца
	KeyRetrans       = "net_retrans"      // повторных передач в секунду
)

// Sample реализует metrics.Sampler: снимает счётчики, считает скорости
// и возвращает значения рядов. Вызывается горутиной метрик.
func (m *Monitor) Sample(now time.Time, dt float64) map[string]float64 {
	r := m.read(now)
	m.mu.Lock()
	prev := m.prev
	m.prev = r
	c := counters(r, prev, dt)
	m.counters = c
	m.conntrack = conntrackInfo(r, prev, dt)
	m.counterFindings = m.checkCounters(now, c, m.conntrack)
	m.rebuildFindings()
	// rep.Active не обновляется: отчёт уже отдан снимку сканера.
	m.mu.Unlock()

	out := map[string]float64{
		KeySynRate:       c.CookiesSent,
		KeyCookiesFailed: c.CookiesFailed,
		KeyListenDrops:   c.ListenOverflows + c.ListenDrops,
		KeyRxDrops:       c.RxDrops + c.SoftnetDropped,
		KeyUDPErrors:     c.UDPRcvbufErrors + c.UDPInErrors,
		KeyEstab:         float64(c.CurrEstab),
		KeyOrphan:        float64(c.TCPOrphan),
		KeyRetrans:       c.RetransSegs,
	}
	if ct := m.conntrack; ct != nil {
		out[KeyConntrackPct] = ct.Percent
	}
	return out
}

// counters считает скорости по разнице двух чтений. Первый замер
// считается от загрузки системы — скорости в нём средние, поэтому он
// помечается Average и признаки по нему не выдаются.
func counters(r, prev rawCounters, dt float64) model.NetLoadCounters {
	c := model.NetLoadCounters{
		CurrEstab: int(r.tcp["CurrEstab"]), TCPInuse: int(r.tcpInuse), TCPOrphan: int(r.tcpOrphan),
		TCPTimeWait: int(r.tcpTW), UDPInuse: int(r.udpInuse), MaxSynBacklog: r.maxSynBacklog,
		MaxOrphans: r.maxOrphans, SomaxConn: r.somaxconn, SynCookies: r.synCookies,
	}
	if prev.time.IsZero() || dt <= 0 {
		c.Average = true
		return c
	}
	d := func(m map[string]uint64, p map[string]uint64, key string) float64 {
		return rate(m[key], p[key], dt)
	}
	c.CookiesSent = d(r.tcpExt, prev.tcpExt, "SyncookiesSent")
	c.CookiesRecv = d(r.tcpExt, prev.tcpExt, "SyncookiesRecv")
	c.CookiesFailed = d(r.tcpExt, prev.tcpExt, "SyncookiesFailed")
	c.ListenOverflows = d(r.tcpExt, prev.tcpExt, "ListenOverflows")
	c.ListenDrops = d(r.tcpExt, prev.tcpExt, "ListenDrops")
	c.ReqQFullDrop = d(r.tcpExt, prev.tcpExt, "TCPReqQFullDrop")
	c.BacklogDrop = d(r.tcpExt, prev.tcpExt, "TCPBacklogDrop")
	c.AbortOnMemory = d(r.tcpExt, prev.tcpExt, "TCPAbortOnMemory")
	c.PassiveOpens = d(r.tcp, prev.tcp, "PassiveOpens")
	c.AttemptFails = d(r.tcp, prev.tcp, "AttemptFails")
	c.RetransSegs = d(r.tcp, prev.tcp, "RetransSegs")
	c.UDPNoPorts = d(r.udp, prev.udp, "NoPorts")
	c.UDPInErrors = d(r.udp, prev.udp, "InErrors")
	c.UDPRcvbufErrors = d(r.udp, prev.udp, "RcvbufErrors")
	c.RxDrops = rate(r.rxDrops, prev.rxDrops, dt)
	c.SoftnetDropped = rate(r.softnetDropped, prev.softnetDropped, dt)
	c.TimeSqueeze = rate(r.softnetSqueeze, prev.softnetSqueeze, dt)
	c.PPSIn = rate(r.rxPackets, prev.rxPackets, dt)
	c.PPSOut = rate(r.txPackets, prev.txPackets, dt)
	return c
}

// conntrackInfo — состояние таблицы conntrack; nil, если модуль не
// загружен (файлов /proc/sys/net/netfilter нет).
func conntrackInfo(r, prev rawCounters, dt float64) *model.ConntrackInfo {
	if r.ctMax <= 0 {
		return nil
	}
	ct := &model.ConntrackInfo{Count: r.ctCount, Max: r.ctMax,
		Percent: float64(r.ctCount) / float64(r.ctMax) * 100}
	if !prev.time.IsZero() && dt > 0 {
		ct.Drop = rate(r.ctDrop, prev.ctDrop, dt)
		ct.EarlyDrop = rate(r.ctEarlyDrop, prev.ctEarlyDrop, dt)
		ct.InsertFailed = rate(r.ctInsertFailed, prev.ctInsertFailed, dt)
	}
	return ct
}

// rate — приращение счётчика в секунду. Уменьшение (перезагрузка,
// сброс) даёт 0, а не отрицательную скорость.
func rate(cur, prev uint64, dt float64) float64 {
	if dt <= 0 || cur < prev {
		return 0
	}
	return float64(cur-prev) / dt
}

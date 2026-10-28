package netload

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

const netstatText = `TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed ListenOverflows ListenDrops TCPReqQFullDrop TCPAbortOnMemory
TcpExt: 1000 500 10 100 120 7 3
IpExt: InNoRoutes InTruncatedPkts
IpExt: 0 2
`

const snmpText = `Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs
Tcp: 1 200 120000 -1 50 900 30 4 820 10000 9000 120
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
Udp: 5000 7000 40 4000 900 0
`

func TestParsePairs(t *testing.T) {
	p := ParsePairs(netstatText)
	ext := p["TcpExt"]
	if ext["SyncookiesSent"] != 1000 || ext["ListenDrops"] != 120 || ext["TCPAbortOnMemory"] != 3 {
		t.Fatalf("TcpExt: %+v", ext)
	}
	if p["IpExt"]["InTruncatedPkts"] != 2 {
		t.Errorf("IpExt: %+v", p["IpExt"])
	}
	s := ParsePairs(snmpText)
	// MaxConn = -1 печатается со знаком: он пропускается, остальные
	// значения той же строки читаются.
	if s["Tcp"]["CurrEstab"] != 820 || s["Tcp"]["RetransSegs"] != 120 {
		t.Errorf("Tcp: %+v", s["Tcp"])
	}
	if _, ok := s["Tcp"]["MaxConn"]; ok {
		t.Error("отрицательное значение попало в счётчики")
	}
	if s["Udp"]["RcvbufErrors"] != 900 || s["Udp"]["NoPorts"] != 7000 {
		t.Errorf("Udp: %+v", s["Udp"])
	}
	// Меньше столбцов значений, чем имён (старое ядро) — не паникуем.
	short := ParsePairs("Tcp: A B C\nTcp: 1 2\n")
	if short["Tcp"]["A"] != 1 || short["Tcp"]["B"] != 2 {
		t.Errorf("короткая строка: %+v", short["Tcp"])
	}
}

func TestParseSockstat(t *testing.T) {
	st := ParseSockstat("sockets: used 420\nTCP: inuse 24 orphan 180 tw 320 alloc 900 mem 48\nUDP: inuse 6 mem 2\n")
	if st["TCP"]["orphan"] != 180 || st["TCP"]["tw"] != 320 || st["UDP"]["inuse"] != 6 {
		t.Fatalf("sockstat: %+v", st)
	}
	if st["sockets"]["used"] != 420 {
		t.Errorf("строка sockets: %+v", st["sockets"])
	}
}

func TestParseHexStatAndSoftnet(t *testing.T) {
	ct := ParseHexStat("entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop\n" +
		"0000a1b2 0 0 0 5 0 0 0 0 2 1f 7\n0000a1b2 0 0 0 5 0 0 0 0 3 10 8\n")
	// Значения суммируются по процессорам: 0x1f + 0x10 = 47.
	if ct["drop"] != 47 || ct["early_drop"] != 15 || ct["insert_failed"] != 5 {
		t.Fatalf("nf_conntrack: %+v", ct)
	}
	dropped, squeeze := ParseSoftnet("0000a1b2 00001f40 00000a00 0 0 0 0 0 0\n0000a0c1 00000010 00000001 0 0 0\n")
	if dropped != 0x1f40+0x10 || squeeze != 0xa00+1 {
		t.Errorf("softnet: %d %d", dropped, squeeze)
	}
	if d, s := ParseSoftnet("мусор\n"); d != 0 || s != 0 {
		t.Errorf("мусор: %d %d", d, s)
	}
}

func TestParseNets(t *testing.T) {
	nets, raw, bad := ParseNets("10.0.0.0/8, 2001:db8::/32 ,198.51.100.7, , чепуха")
	if len(nets) != 3 || len(raw) != 3 {
		t.Fatalf("сети: %+v", nets)
	}
	if len(bad) != 1 || bad[0] != "чепуха" {
		t.Errorf("неразобранное: %+v", bad)
	}
	// Одиночный адрес превращается в /32.
	if nets[2].Bits() != 32 {
		t.Errorf("одиночный адрес: %v", nets[2])
	}
}

// fakeProc пишет поддельные файлы /proc.
func fakeProc(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, files)
	return root
}

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// counterFiles — набор файлов со счётчиками: cookies растут по 300/с,
// отбросы очереди accept по 50/с, если secs > 0.
func counterFiles(secs float64) map[string]string {
	n := func(rate float64) int { return int(rate * secs) }
	return map[string]string{
		"net/netstat": "TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed ListenOverflows ListenDrops TCPReqQFullDrop TCPAbortOnMemory\n" +
			itoaLine("TcpExt", n(300), n(120), 0, n(25), n(25), 0, 0),
		"net/snmp": "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs\n" +
			itoaLine("Tcp", 1, 200, 120000, -1, n(5), n(100), n(10), 0, 820, n(900), n(800), n(40)) +
			"Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n" +
			itoaLine("Udp", n(200), n(50), n(10), n(100), n(10), 0),
		"net/sockstat":                         "TCP: inuse 24 orphan 180 tw 320 alloc 900 mem 48\nUDP: inuse 6 mem 2\n",
		"net/dev":                              "Inter-|\n face |\n  eth0: 100 " + itoa(n(1000)) + " 0 5 0 0 0 0 200 " + itoa(n(500)) + " 0 0 0 0 0 0\n",
		"net/softnet_stat":                     "00000000 00000000 00000000 0 0 0 0 0 0\n",
		"sys/net/ipv4/tcp_max_syn_backlog":     "1024\n",
		"sys/net/ipv4/tcp_max_orphans":         "262144\n",
		"sys/net/core/somaxconn":               "4096\n",
		"sys/net/ipv4/tcp_syncookies":          "1\n",
		"sys/net/netfilter/nf_conntrack_count": "1000\n",
		"sys/net/netfilter/nf_conntrack_max":   "65536\n",
	}
}

func itoa(n int) string { return strings.TrimSpace(strings.Join([]string{intToString(n)}, "")) }

func intToString(n int) string {
	if n < 0 {
		return "-" + intToString(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return intToString(n/10) + string(rune('0'+n%10))
}

func itoaLine(prefix string, vals ...int) string {
	out := prefix + ":"
	for _, v := range vals {
		out += " " + itoa(v)
	}
	return out + "\n"
}

// TestSampleRates: скорости считаются по разнице двух чтений, первый
// замер помечается Average и признаков не даёт.
func TestSampleRates(t *testing.T) {
	root := fakeProc(t, counterFiles(1000))
	m := New(Options{ProcRoot: root, Config: DefaultConfig()})
	now := time.Now()
	series := m.Sample(now, 0)
	if !m.counters.Average {
		t.Error("первый замер должен быть средним с загрузки")
	}
	if len(m.Findings()) != 0 {
		t.Errorf("признаки на первом замере: %+v", m.Findings())
	}
	if series[KeyEstab] != 820 {
		t.Errorf("ряд соединений: %v", series[KeyEstab])
	}
	// Через 10 секунд счётчики выросли.
	write(t, root, counterFiles(1010))
	series = m.Sample(now.Add(10*time.Second), 10)
	c := m.counters
	if c.Average {
		t.Fatal("второй замер считается по разнице")
	}
	if got := round(c.CookiesSent); got != 300 {
		t.Errorf("cookies/с: %v", got)
	}
	if got := round(c.ListenOverflows + c.ListenDrops); got != 50 {
		t.Errorf("отбросы очереди accept: %v", got)
	}
	if got := round(c.UDPRcvbufErrors); got != 10 {
		t.Errorf("UDP RcvbufErrors: %v", got)
	}
	if got := round(c.PPSIn); got != 1000 {
		t.Errorf("пакетов/с: %v", got)
	}
	if series[KeySynRate] != c.CookiesSent || series[KeyConntrackPct] == 0 {
		t.Errorf("ряды: %+v", series)
	}
	if ct := m.conntrack; ct == nil || round(ct.Percent) != 2 {
		t.Errorf("conntrack: %+v", ct)
	}
	// Сброс счётчиков (перезагрузка) не даёт отрицательных скоростей.
	write(t, root, counterFiles(5))
	m.Sample(now.Add(20*time.Second), 10)
	if m.counters.CookiesSent != 0 {
		t.Errorf("после сброса счётчика: %v", m.counters.CookiesSent)
	}
}

func round(v float64) float64 { return float64(int(v + 0.5)) }

// TestNoConntrack: без модуля conntrack раздел просто отсутствует.
func TestNoConntrack(t *testing.T) {
	files := counterFiles(1000)
	delete(files, "sys/net/netfilter/nf_conntrack_count")
	delete(files, "sys/net/netfilter/nf_conntrack_max")
	m := New(Options{ProcRoot: fakeProc(t, files), Config: DefaultConfig()})
	m.Sample(time.Now(), 0)
	if m.conntrack != nil {
		t.Errorf("conntrack без модуля: %+v", m.conntrack)
	}
}

// TestCounterHold: признак появляется только после удержания и
// снимается через гистерезис, а не сразу.
func TestCounterHold(t *testing.T) {
	root := fakeProc(t, counterFiles(1000))
	m := New(Options{ProcRoot: root, Config: DefaultConfig()})
	now := time.Now()
	m.Sample(now, 0)
	// Первые 20 секунд флуда: удержание 30 с ещё не вышло.
	for i := 1; i <= 4; i++ {
		write(t, root, counterFiles(1000+float64(i)*5))
		m.Sample(now.Add(time.Duration(i)*5*time.Second), 5)
	}
	if _, ok := findingByID(m.Findings(), IDSynFlood); ok {
		t.Error("признак появился раньше удержания")
	}
	for i := 5; i <= 8; i++ {
		write(t, root, counterFiles(1000+float64(i)*5))
		m.Sample(now.Add(time.Duration(i)*5*time.Second), 5)
	}
	f, ok := findingByID(m.Findings(), IDSynFlood)
	if !ok || f.Risk != model.RiskMedium {
		t.Fatalf("после удержания: %+v %v", f, ok)
	}
	if !strings.Contains(f.Evidence[0].In(i18n.RU), "300") {
		t.Errorf("факты: %q", f.Evidence[0].In(i18n.RU))
	}
	// Флуд прекратился: признак держится ещё пять минут (гистерезис).
	base := 1000 + 8*5.0
	for i := 1; i <= 3; i++ {
		write(t, root, counterFilesCalm(base))
		m.Sample(now.Add(time.Duration(40+i*5)*time.Second), 5)
	}
	if _, ok := findingByID(m.Findings(), IDSynFlood); !ok {
		t.Error("признак снят сразу, без гистерезиса")
	}
	write(t, root, counterFilesCalm(base))
	m.Sample(now.Add(7*time.Minute), 5)
	if _, ok := findingByID(m.Findings(), IDSynFlood); ok {
		t.Error("признак не снялся через пять минут покоя")
	}
}

// counterFilesCalm — счётчики перестали расти (значения зафиксированы).
func counterFilesCalm(secs float64) map[string]string {
	return counterFiles(secs)
}

func findingByID(fs []model.SystemFinding, id string) (model.SystemFinding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return model.SystemFinding{}, false
}

// listenSock, connSock — заготовки сокетов для отчёта.
func listenSock(port int, backlog, queue uint64) model.Socket {
	return model.Socket{Proto: "tcp", LocalAddr: "0.0.0.0", LocalPort: port, State: "LISTEN",
		TxQueue: backlog, RxQueue: queue, PID: 720, ProcName: "nginx", ProcKey: "720-1"}
}

func connSock(port int, remote, state string) model.Socket {
	return model.Socket{Proto: "tcp", LocalAddr: "192.0.2.10", LocalPort: port, RemoteAddr: remote,
		RemotePort: 40000, State: state}
}

// TestBuildPortsAndSources: агрегаты по портам и источникам, признак
// флуда с одного адреса появляется со второго сканирования.
func TestBuildPortsAndSources(t *testing.T) {
	m := New(Options{ProcRoot: fakeProc(t, counterFiles(1000)), Config: Config{ConnPerIP: 100, SurgeFactor: 5}})
	socks := []model.Socket{listenSock(443, 1024, 10), listenSock(22, 128, 0)}
	for i := range 150 {
		socks = append(socks, connSock(443, "203.0.113.5", "ESTABLISHED"))
		_ = i
	}
	for i := range 3 {
		socks = append(socks, connSock(22, "198.51.100.9", "ESTABLISHED"))
		_ = i
	}
	// Исходящее соединение: локальный порт не слушающий — в источники
	// попасть не должно.
	socks = append(socks, model.Socket{Proto: "tcp", LocalAddr: "192.0.2.10", LocalPort: 51000,
		RemoteAddr: "203.0.113.200", RemotePort: 443, State: "ESTABLISHED"})
	in := Input{Now: time.Now(), Sockets: socks, Addrs: []model.IfaceAddr{{Addr: "192.0.2.10"}}}
	rep := m.Build(in)
	if len(rep.Listen) != 2 {
		t.Fatalf("порты: %+v", rep.Listen)
	}
	p443, ok := portByNum(rep.Listen, 443)
	if !ok || p443.Established != 150 || p443.Backlog != 1024 || p443.AcceptQueue != 10 || p443.Sources != 1 {
		t.Fatalf("порт 443: %+v", p443)
	}
	src, ok := sourceByAddr(rep.TopSources, "203.0.113.5")
	if !ok || src.Conns != 150 {
		t.Fatalf("источник: %+v", rep.TopSources)
	}
	if _, ok := sourceByAddr(rep.TopSources, "203.0.113.200"); ok {
		t.Error("исходящее соединение попало в источники")
	}
	// Первое сканирование: признак ждёт второго подряд.
	if _, ok := findingByID(m.Findings(), IDConnFloodIP); ok {
		t.Error("признак на первом сканировании")
	}
	rep = m.Build(Input{Now: in.Now.Add(30 * time.Second), Sockets: socks, Addrs: in.Addrs})
	f, ok := findingByID(m.Findings(), IDConnFloodIP)
	if !ok || f.Path != "203.0.113.5" || f.Risk != model.RiskLow {
		t.Fatalf("net_conn_flood_ip: %+v %v", f, ok)
	}
	if !contains(rep.Active, IDConnFloodIP) {
		t.Errorf("сработавшие признаки: %+v", rep.Active)
	}
	// Соединений стало меньше порога — признак пропадает.
	rep = m.Build(Input{Now: in.Now.Add(60 * time.Second), Sockets: socks[:5], Addrs: in.Addrs})
	if _, ok := findingByID(m.Findings(), IDConnFloodIP); ok {
		t.Errorf("признак остался: %+v", rep.Active)
	}
}

// TestTrustedAndPrivate: адреса доверенных сетей признака не дают,
// частным сетям порог поднимается.
func TestTrustedAndPrivate(t *testing.T) {
	trusted, raw, _ := ParseNets("198.51.100.0/24")
	m := New(Options{ProcRoot: fakeProc(t, counterFiles(1000)),
		Config: Config{ConnPerIP: 50, SurgeFactor: 5, Trusted: trusted, TrustedRaw: raw}})
	socks := []model.Socket{listenSock(443, 1024, 0)}
	for range 400 {
		socks = append(socks, connSock(443, "198.51.100.10", "ESTABLISHED"))
	}
	for range 120 {
		socks = append(socks, connSock(443, "10.0.0.7", "ESTABLISHED"))
	}
	in := Input{Now: time.Now(), Sockets: socks}
	m.Build(in)
	rep := m.Build(Input{Now: in.Now.Add(30 * time.Second), Sockets: socks})
	if len(rep.TrustedNets) != 1 {
		t.Errorf("доверенные сети в отчёте: %+v", rep.TrustedNets)
	}
	for _, f := range m.Findings() {
		if f.Path == "198.51.100.10" {
			t.Errorf("признак по доверенному адресу: %+v", f)
		}
	}
	// 120 соединений из частной сети при пороге 50: порог ×4 = 200, не
	// превышен.
	if _, ok := findingByID(m.Findings(), IDConnFloodIP); ok {
		t.Errorf("частная сеть дала признак: %+v", m.Findings())
	}
	src, ok := sourceByAddr(rep.TopSources, "10.0.0.7")
	if !ok || !src.Private {
		t.Errorf("частный источник: %+v", src)
	}
	tsrc, ok := sourceByAddr(rep.TopSources, "198.51.100.10")
	if !ok || !tsrc.Trusted {
		t.Errorf("доверенный источник: %+v", tsrc)
	}
}

// TestSynFloodAndSuspected: полуоткрытые соединения дают признак
// SYN-флуда, а вместе с переполнением conntrack — сводный признак.
func TestSynFloodAndSuspected(t *testing.T) {
	files := counterFiles(1000)
	files["sys/net/netfilter/nf_conntrack_count"] = "63000\n"
	root := fakeProc(t, files)
	m := New(Options{ProcRoot: root, Config: DefaultConfig()})
	now := time.Now()
	m.Sample(now, 0)
	// Счётчики не важны: conntrack заполнен — признак появится после
	// минуты удержания.
	for i := 1; i <= 14; i++ {
		files = counterFiles(1000 + float64(i)*5)
		files["sys/net/netfilter/nf_conntrack_count"] = "63000\n"
		write(t, root, files)
		m.Sample(now.Add(time.Duration(i)*5*time.Second), 5)
	}
	if _, ok := findingByID(m.Findings(), IDConntrack); !ok {
		t.Fatalf("net_conntrack_full не появился: %+v", m.Findings())
	}
	// Полуоткрытые соединения на 443: 900 при backlog 1024. Порог для
	// подсети — 4 × SSG_NET_CONN_PER_IP (800), поэтому срабатывает и
	// признак по подсети.
	socks := []model.Socket{listenSock(443, 1024, 0)}
	for i := range 900 {
		socks = append(socks, connSock(443, "203.0.113."+itoa(1+i%60), "SYN_RECV"))
	}
	in := Input{Now: now.Add(90 * time.Second), Sockets: socks}
	m.Build(in)
	rep := m.Build(Input{Now: in.Now.Add(30 * time.Second), Sockets: socks})
	f, ok := findingByID(m.Findings(), IDSynFlood)
	if !ok {
		t.Fatalf("net_syn_flood: %+v", rep.Active)
	}
	if f.Path != "tcp/443" && f.Path != "net" {
		t.Errorf("путь признака: %q", f.Path)
	}
	// Группы разные (syn и kernel) — появляется сводный признак.
	sus, ok := findingByID(m.Findings(), IDSuspected)
	if !ok || sus.Risk != model.RiskHigh {
		t.Fatalf("net_ddos_suspected: %+v %v", sus, ok)
	}
	if !strings.Contains(sus.Evidence[1].In(i18n.RU), "хостер") {
		t.Errorf("нет предупреждения про канал: %q", sus.Evidence[1].In(i18n.RU))
	}
	// Подсеть 203.0.113.0/24 с 60 адресами — отдельный признак.
	if _, ok := findingByID(m.Findings(), IDConnFloodNet); !ok {
		t.Errorf("net_conn_flood_subnet: %+v", rep.Active)
	}
}

// TestTruncated: при усечении таблицы появляется предупреждение.
func TestTruncated(t *testing.T) {
	m := New(Options{ProcRoot: fakeProc(t, counterFiles(1000)), Config: DefaultConfig()})
	rep := m.Build(Input{Now: time.Now(), Sockets: []model.Socket{listenSock(443, 1024, 0)}, Dropped: 1234})
	if !rep.Truncated || rep.Dropped != 1234 {
		t.Fatalf("усечение: %+v", rep)
	}
	f, ok := findingByID(m.Findings(), IDTruncated)
	if !ok || f.Risk != model.RiskInfo {
		t.Errorf("net_table_truncated: %+v %v", f, ok)
	}
}

// TestAllowlist: правило allowlist оставляет признак видимым, но
// подавленным — в сводку он не идёт.
func TestAllowlist(t *testing.T) {
	m := New(Options{ProcRoot: fakeProc(t, counterFiles(1000)), Config: Config{ConnPerIP: 10, SurgeFactor: 5},
		Allowed: func(id string) bool { return id == IDConnFloodIP }})
	socks := []model.Socket{listenSock(443, 1024, 0)}
	for range 50 {
		socks = append(socks, connSock(443, "203.0.113.9", "ESTABLISHED"))
	}
	in := Input{Now: time.Now(), Sockets: socks}
	m.Build(in)
	rep := m.Build(Input{Now: in.Now.Add(30 * time.Second), Sockets: socks})
	f, ok := findingByID(m.Findings(), IDConnFloodIP)
	if !ok || !f.Suppressed || f.Risk != model.RiskInfo {
		t.Fatalf("подавленный признак: %+v %v", f, ok)
	}
	if contains(rep.Active, IDConnFloodIP) {
		t.Errorf("подавленный признак в сводке: %+v", rep.Active)
	}
}

// TestSubnetOf — сеть источника: /24 для IPv4 и /64 для IPv6.
func TestSubnetOf(t *testing.T) {
	v4, _ := netip.ParseAddr("203.0.113.44")
	p, ok := subnet(v4)
	if !ok || p.String() != "203.0.113.0/24" {
		t.Errorf("IPv4: %v %v", p, ok)
	}
	v6, _ := netip.ParseAddr("2001:db8:1:2:3:4:5:6")
	p, ok = subnet(v6)
	if !ok || p.String() != "2001:db8:1:2::/64" {
		t.Errorf("IPv6: %v %v", p, ok)
	}
}

func portByNum(ports []model.PortLoad, n int) (model.PortLoad, bool) {
	for _, p := range ports {
		if p.Port == n {
			return p, true
		}
	}
	return model.PortLoad{}, false
}

func sourceByAddr(src []model.SourceLoad, addr string) (model.SourceLoad, bool) {
	for _, s := range src {
		if s.Addr == addr {
			return s, true
		}
	}
	return model.SourceLoad{}, false
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

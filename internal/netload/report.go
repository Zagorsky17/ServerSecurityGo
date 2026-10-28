package netload

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// agg — агрегат по одному источнику: адресу или подсети.
type agg struct {
	conns, half int
	ports       map[int]bool
	addrs       map[string]bool
}

// Input — данные одного сканирования для отчёта.
type Input struct {
	Now time.Time
	// Sockets — сокеты снимка (их уже прочитал сканер).
	Sockets []model.Socket
	// Dropped — сколько сокетов не вошло в предел SSG_NET_MAX_SOCKETS.
	Dropped int
	// Addrs — локальные адреса сервера: соединения с самим собой в
	// источники флуда не попадают.
	Addrs []model.IfaceAddr
}

// baselineWindow — за какое время считается «как обычно» для числа
// соединений, и сколько данных для этого нужно.
const (
	baselineWindow = 24 * time.Hour
	baselineMin    = 6 * time.Hour
	// surgeStreak — сколько сканирований подряд держится наплыв
	// соединений (≈2 минуты при интервале 30 с).
	surgeStreak = 4
)

// Build разбирает таблицы сокетов, строит отчёт и признаки по
// соединениям. Счётчики ядра в отчёт попадают те, что сняла горутина
// метрик (Sample).
func (m *Monitor) Build(in Input) *model.NetLoadReport {
	local := map[string]bool{}
	for _, a := range in.Addrs {
		local[a.Addr] = true
	}
	// Слушающие порты: по ним определяется, какое соединение входящее.
	type portKey struct {
		proto string
		port  int
	}
	listen := map[portKey]*model.PortLoad{}
	for _, s := range in.Sockets {
		proto := strings.TrimSuffix(s.Proto, "6")
		if proto != "tcp" && proto != "udp" {
			continue
		}
		listening := (proto == "tcp" && s.State == "LISTEN") ||
			(proto == "udp" && s.State == "UNCONN" && s.RemotePort == 0 && s.LocalPort != 0)
		if !listening {
			continue
		}
		k := portKey{proto, s.LocalPort}
		p := listen[k]
		if p == nil {
			p = &model.PortLoad{Proto: proto, Port: s.LocalPort, Addr: s.LocalAddr}
			listen[k] = p
		}
		// Backlog и очередь accept — из tx_queue:rx_queue слушающего
		// сокета; при нескольких сокетах на порт берётся худший случай.
		if int(s.TxQueue) > p.Backlog {
			p.Backlog = int(s.TxQueue)
		}
		if int(s.RxQueue) > p.AcceptQueue {
			p.AcceptQueue = int(s.RxQueue)
		}
		if p.PID == 0 && s.PID != 0 {
			p.PID, p.ProcName, p.ProcKey = s.PID, s.ProcName, s.ProcKey
		}
	}

	// Агрегаты по источникам и портам.
	ips := map[string]*agg{}
	nets := map[string]*agg{}
	sources := map[portKey]map[string]bool{}
	incoming := 0
	get := func(mp map[string]*agg, key string) *agg {
		a := mp[key]
		if a == nil {
			if len(mp) >= maxIPs {
				return nil // предел карты: под атакой адресов сотни тысяч
			}
			a = &agg{ports: map[int]bool{}, addrs: map[string]bool{}}
			mp[key] = a
		}
		return a
	}
	for _, s := range in.Sockets {
		proto := strings.TrimSuffix(s.Proto, "6")
		if proto != "tcp" {
			continue // соединения считаются только для TCP
		}
		half := s.State == "SYN_RECV" || s.State == "NEW_SYN_RECV"
		if !half && s.State != "ESTABLISHED" {
			continue
		}
		k := portKey{proto, s.LocalPort}
		p := listen[k]
		if p == nil {
			continue // исходящее соединение: локальный порт не слушающий
		}
		if half {
			p.HalfOpen++
		} else {
			p.Established++
		}
		incoming++
		if sources[k] == nil {
			sources[k] = map[string]bool{}
		}
		if len(sources[k]) < maxIPs {
			sources[k][s.RemoteAddr] = true
		}
		ip, err := netip.ParseAddr(s.RemoteAddr)
		if err != nil || ip.IsLoopback() || local[s.RemoteAddr] {
			continue
		}
		if a := get(ips, s.RemoteAddr); a != nil {
			a.conns++
			a.ports[s.LocalPort] = true
			if half {
				a.half++
			}
		}
		if sub, ok := subnet(ip); ok {
			if a := get(nets, sub.String()); a != nil {
				a.conns++
				a.ports[s.LocalPort] = true
				a.addrs[s.RemoteAddr] = true
				if half {
					a.half++
				}
			}
		}
	}
	for k, set := range sources {
		if p := listen[k]; p != nil {
			p.Sources = len(set)
		}
	}

	rep := &model.NetLoadReport{Time: in.Now, Listen: []model.PortLoad{}, TopSources: []model.SourceLoad{},
		Truncated: in.Dropped > 0, Dropped: in.Dropped, Active: []string{}, TrustedNets: m.opt.TrustedRaw}
	for _, p := range listen {
		rep.Listen = append(rep.Listen, *p)
	}
	sort.SliceStable(rep.Listen, func(i, j int) bool {
		a, b := rep.Listen[i], rep.Listen[j]
		if a.HalfOpen != b.HalfOpen {
			return a.HalfOpen > b.HalfOpen
		}
		if a.Established != b.Established {
			return a.Established > b.Established
		}
		return a.Port < b.Port
	})
	// Источники: отдельные адреса и подсети в одном списке по убыванию
	// числа соединений. Подсеть всегда не меньше своих адресов, поэтому
	// оказывается выше них.
	var all []model.SourceLoad
	add := func(key string, a *agg, isNet bool) {
		sl := model.SourceLoad{Addr: key, Subnet: isNet, Conns: a.conns, HalfOpen: a.half, Ports: portList(a.ports)}
		if isNet {
			sl.Addresses = len(a.addrs)
		}
		sl.Trusted, sl.Private = m.classify(key, isNet)
		all = append(all, sl)
	}
	for key, a := range ips {
		add(key, a, false)
	}
	for key, a := range nets {
		// Подсеть из одного адреса ничего не добавляет к самому адресу.
		if a.conns > 0 && len(a.addrs) > 1 {
			add(key, a, true)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Conns != b.Conns {
			return a.Conns > b.Conns
		}
		if a.Subnet != b.Subnet {
			return a.Subnet
		}
		return a.Addr < b.Addr
	})
	// В отчёт идёт только начало списка, а признаки считаются по всем
	// источникам: иначе при сотне адресов флуд с подсети не заметить.
	rep.TopSources = all
	if len(all) > maxSources {
		rep.TopSources = all[:maxSources]
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	rep.Counters, rep.Conntrack = m.counters, m.conntrack
	base, hasBase := m.connBase(in.Now, incoming)
	rep.Baseline = hasBase
	m.connFindings = m.checkConns(rep, all, incoming, base, hasBase)
	rep.Active = m.rebuildFindings()
	m.report = rep
	return rep
}

// classify — доверенный ли источник (CDN, прокси из
// SSG_NET_TRUSTED_NETS) и частная ли это сеть.
func (m *Monitor) classify(key string, isNet bool) (trusted, private bool) {
	var ip netip.Addr
	if isNet {
		p, err := netip.ParsePrefix(key)
		if err != nil {
			return false, false
		}
		ip = p.Addr()
	} else {
		a, err := netip.ParseAddr(key)
		if err != nil {
			return false, false
		}
		ip = a
	}
	for _, n := range m.opt.Trusted {
		if n.Contains(ip) {
			return true, false
		}
	}
	return false, ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// subnet — сеть источника: /24 для IPv4 и /64 для IPv6. Атакуют обычно
// не одним адресом, а диапазоном.
func subnet(ip netip.Addr) (netip.Prefix, bool) {
	bits := 24
	if ip.Unmap().Is6() {
		bits = 64
	}
	p, err := ip.Unmap().Prefix(bits)
	return p, err == nil
}

func portList(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) > maxPorts {
		out = out[:maxPorts]
	}
	return out
}

// connBase — «как обычно» для числа входящих соединений: медиана за
// сутки по самим сканированиям (метрики соединения не считают — таблицу
// сокетов дорого разбирать каждые пять секунд). ok = false, пока данных
// меньше baselineMin: иначе сравнивали бы со случайным получасом после
// запуска службы. Вызывается под m.mu.
func (m *Monitor) connBase(now time.Time, cur int) (float64, bool) {
	m.conns = append(m.conns, connPoint{t: now, n: cur})
	// Чистка окна; точек немного (одна на сканирование).
	keep := m.conns[:0]
	for _, p := range m.conns {
		if now.Sub(p.t) <= baselineWindow {
			keep = append(keep, p)
		}
	}
	m.conns = keep
	if len(m.conns) == 0 || now.Sub(m.conns[0].t) < baselineMin {
		return 0, false
	}
	vals := make([]int, 0, len(m.conns))
	for _, p := range m.conns {
		vals = append(vals, p.n)
	}
	sort.Ints(vals)
	return float64(vals[len(vals)/2]), true
}

// streakOK — условие держится нужное число сканирований подряд.
// Вызывается под m.mu.
func (m *Monitor) streakOK(key string, active bool, need int) bool {
	if !active {
		delete(m.streak, key)
		return false
	}
	m.streak[key]++
	return m.streak[key] >= need
}

// checkConns — признаки по таблицам сокетов. Вызывается под m.mu.
func (m *Monitor) checkConns(rep *model.NetLoadReport, sources []model.SourceLoad, incoming int, base float64, hasBase bool) []model.SystemFinding {
	var out []model.SystemFinding
	seen := map[string]bool{}
	// SYN-флуд и переполнение очереди accept — по портам.
	for _, p := range rep.Listen {
		path := p.Proto + "/" + strconv.Itoa(p.Port)
		backlog := p.Backlog
		if backlog <= 0 {
			backlog = m.counters.MaxSynBacklog
		}
		flood := p.HalfOpen >= halfOpenMin && backlog > 0 && float64(p.HalfOpen) >= halfOpenShare*float64(backlog)
		if m.streakOK(IDSynFlood+"|"+path, flood, m.streakNeed(connStreak)) && !seen[IDSynFlood] {
			risk := model.RiskMedium
			if backlog > 0 && float64(p.HalfOpen) >= halfOpenHigh*float64(backlog) {
				risk = model.RiskHigh
			}
			seen[IDSynFlood] = true
			out = append(out, m.newFinding(IDSynFlood, risk, path,
				i18n.T("rule.net_syn_flood.title_port", strconv.Itoa(p.Port)),
				[]i18n.Msg{i18n.T("ev.net_half_open", strconv.Itoa(p.HalfOpen), strconv.Itoa(backlog), portOwner(p)),
					i18n.T("ev.net_sources", strconv.Itoa(p.Sources))}))
		}
		over := p.Backlog > 0 && float64(p.AcceptQueue) >= acceptQueueShare*float64(p.Backlog)
		if m.streakOK(IDListenOver+"|"+path, over, m.streakNeed(connStreak)) {
			out = append(out, m.newFinding(IDListenOver, model.RiskMedium, path,
				i18n.T("rule.net_listen_overflow.title_port", strconv.Itoa(p.Port)),
				[]i18n.Msg{i18n.T("ev.net_accept_queue", strconv.Itoa(p.AcceptQueue), strconv.Itoa(p.Backlog), portOwner(p))}))
		}
	}
	// Флуд с одного адреса и с одной подсети — по всем источникам, а не
	// только по показанным в отчёте.
	for _, s := range sources {
		if s.Trusted {
			continue // CDN или прокси: все клиенты приходят с его адресов
		}
		limit := m.opt.ConnPerIP
		if s.Private {
			limit *= privateFactor
		}
		if s.Subnet {
			limit *= privateFactor // подсеть: порог в четыре раза выше
			if s.Conns <= limit || s.Addresses < subnetAddrs {
				m.streakOK(IDConnFloodNet+"|"+s.Addr, false, m.streakNeed(connStreak))
				continue
			}
			if m.streakOK(IDConnFloodNet+"|"+s.Addr, true, m.streakNeed(connStreak)) {
				out = append(out, m.newFinding(IDConnFloodNet, model.RiskMedium, s.Addr,
					i18n.T(titleKeys[IDConnFloodNet], s.Addr, strconv.Itoa(s.Conns)),
					[]i18n.Msg{i18n.T("ev.net_subnet", s.Addr, strconv.Itoa(s.Conns), strconv.Itoa(s.Addresses), portsText(s.Ports))}))
			}
			continue
		}
		if s.Conns <= limit {
			m.streakOK(IDConnFloodIP+"|"+s.Addr, false, m.streakNeed(connStreak))
			continue
		}
		if m.streakOK(IDConnFloodIP+"|"+s.Addr, true, m.streakNeed(connStreak)) {
			risk := model.RiskLow
			if s.Conns > 5*limit {
				risk = model.RiskMedium
			}
			ev := []i18n.Msg{i18n.T("ev.net_conn_ip", s.Addr, strconv.Itoa(s.Conns), strconv.Itoa(limit), portsText(s.Ports))}
			if s.HalfOpen > 0 {
				ev = append(ev, i18n.T("ev.net_conn_half", strconv.Itoa(s.HalfOpen)))
			}
			if s.Private {
				ev = append(ev, i18n.T("ev.net_private"))
			}
			ev = append(ev, i18n.T("ev.net_check_cmd", s.Addr))
			out = append(out, m.newFinding(IDConnFloodIP, risk, s.Addr,
				i18n.T(titleKeys[IDConnFloodIP], s.Addr, strconv.Itoa(s.Conns)), ev))
		}
	}
	// Наплыв соединений: абсолютный порог и «в N раз больше обычного».
	surge := hasBase && incoming >= connSurge && float64(incoming) >= m.opt.SurgeFactor*base
	if m.streakOK(IDConnSurge, surge, m.streakNeed(surgeStreak)) {
		out = append(out, m.newFinding(IDConnSurge, model.RiskLow, "net",
			i18n.T(titleKeys[IDConnSurge], strconv.Itoa(incoming)),
			[]i18n.Msg{i18n.T("ev.net_surge", strconv.Itoa(incoming), strconv.FormatFloat(base, 'f', 0, 64),
				strconv.FormatFloat(float64(incoming)/max(base, 1), 'f', 1, 64))}))
	}
	if rep.Truncated {
		out = append(out, m.newFinding(IDTruncated, model.RiskInfo, "net",
			i18n.T("rule.net_table_truncated.title"),
			[]i18n.Msg{i18n.T("ev.net_truncated", strconv.Itoa(rep.Dropped))}))
	}
	return out
}

// portOwner — «443/tcp (nginx, PID 720)» для фактов.
func portOwner(p model.PortLoad) string {
	if p.PID == 0 {
		return strconv.Itoa(p.Port) + "/" + p.Proto
	}
	return strconv.Itoa(p.Port) + "/" + p.Proto + " (" + p.ProcName + ", PID " + strconv.Itoa(p.PID) + ")"
}

func portsText(ports []int) string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, strconv.Itoa(p))
	}
	return strings.Join(out, ", ")
}

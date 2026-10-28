package netload

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// ID признаков. Литералы в одном месте: по ним работают allowlist,
// история и ключи каталога.
const (
	IDSynFlood     = "net_syn_flood"
	IDListenOver   = "net_listen_overflow"
	IDConnFloodIP  = "net_conn_flood_ip"
	IDConnFloodNet = "net_conn_flood_subnet"
	IDConnSurge    = "net_conn_surge"
	IDConntrack    = "net_conntrack_full"
	IDOrphans      = "net_orphans_high"
	IDUDPFlood     = "net_udp_flood"
	IDRxDrops      = "net_rx_drops"
	IDPPSSurge     = "net_pps_surge"
	IDSuspected    = "net_ddos_suspected"
	// IDTruncated — таблица сокетов не влезла в предел: числа занижены.
	IDTruncated = "net_table_truncated"
)

// group — группа симптомов. Сводный признак требует симптомов минимум
// из двух групп: один симптом даёт и наплыв настоящих посетителей.
var group = map[string]string{
	IDSynFlood:     "syn",
	IDListenOver:   "conn",
	IDConnFloodIP:  "conn",
	IDConnFloodNet: "conn",
	IDConnSurge:    "conn",
	IDConntrack:    "kernel",
	IDRxDrops:      "kernel",
	IDOrphans:      "kernel",
	IDUDPFlood:     "udp",
}

// titleKeys, recKeys — ключи каталога для каждого признака. Литералы,
// а не склейка «rule.» + ID: keys_test сверяет ключи из кода с
// каталогом и склейку не увидит.
var titleKeys = map[string]string{
	IDSynFlood:     "rule.net_syn_flood.title",
	IDListenOver:   "rule.net_listen_overflow.title",
	IDConnFloodIP:  "rule.net_conn_flood_ip.title",
	IDConnFloodNet: "rule.net_conn_flood_subnet.title",
	IDConnSurge:    "rule.net_conn_surge.title",
	IDConntrack:    "rule.net_conntrack_full.title",
	IDOrphans:      "rule.net_orphans_high.title",
	IDUDPFlood:     "rule.net_udp_flood.title",
	IDRxDrops:      "rule.net_rx_drops.title",
	IDPPSSurge:     "rule.net_pps_surge.title",
	IDSuspected:    "rule.net_ddos_suspected.title",
	IDTruncated:    "rule.net_table_truncated.title",
}

var recKeys = map[string]string{
	IDSynFlood:     "rule.net_syn_flood.rec",
	IDListenOver:   "rule.net_listen_overflow.rec",
	IDConnFloodIP:  "rule.net_conn_flood_ip.rec",
	IDConnFloodNet: "rule.net_conn_flood_subnet.rec",
	IDConnSurge:    "rule.net_conn_surge.rec",
	IDConntrack:    "rule.net_conntrack_full.rec",
	IDOrphans:      "rule.net_orphans_high.rec",
	IDUDPFlood:     "rule.net_udp_flood.rec",
	IDRxDrops:      "rule.net_rx_drops.rec",
	IDPPSSurge:     "rule.net_pps_surge.rec",
	IDSuspected:    "rule.net_ddos_suspected.rec",
	IDTruncated:    "rule.net_table_truncated.rec",
}

// holdState — удержание одного признака: с какого момента условие
// держится, когда оно было в последний раз и пиковое значение.
type holdState struct {
	since, last time.Time
	active      bool
	peak        float64
}

// need — сколько условие должно держаться, и через сколько признак
// снимается. В демо — несколько секунд вместо минут.
func (m *Monitor) need(d time.Duration) time.Duration {
	if m.opt.FastHolds {
		return 4 * time.Second
	}
	return d
}

// clearWindow — сколько признак держится после того, как условие
// пропало (гистерезис).
func (m *Monitor) clearWindow() time.Duration {
	if m.opt.FastHolds {
		return 20 * time.Second
	}
	return clearAfter
}

// streakNeed — сколько сканирований подряд нужно признаку по
// соединениям.
func (m *Monitor) streakNeed(n int) int {
	if m.opt.FastHolds {
		return 1
	}
	return n
}

// dropGeneric убирает общую находку («net»), если тот же признак
// нашёлся с конкретным путём: SYN-флуд виден и по счётчику cookies, и
// по полуоткрытым соединениям порта, но в истории и в «Системе» это
// одно событие, и строка с портом полезнее. Находки с разными путями
// (разные адреса флуда) остаются все.
func dropGeneric(all []model.SystemFinding) []model.SystemFinding {
	specific := map[string]bool{}
	for _, f := range all {
		if f.Path != "net" {
			specific[f.ID] = true
		}
	}
	out := make([]model.SystemFinding, 0, len(all))
	for _, f := range all {
		if f.Path == "net" && specific[f.ID] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// hold сообщает, держится ли условие достаточно долго. Признак
// снимается не сразу, а через clearAfter без превышения (гистерезис):
// иначе при атаке он мигал бы и засыпал историю событиями.
// Вызывается под m.mu.
func (m *Monitor) hold(id string, active bool, now time.Time, need time.Duration, value float64) bool {
	h := m.holds[id]
	if h == nil {
		h = &holdState{}
		m.holds[id] = h
	}
	if active {
		if h.since.IsZero() {
			h.since = now
		}
		h.last = now
		h.peak = max(h.peak, value)
		if now.Sub(h.since) >= need {
			h.active = true
		}
		return h.active
	}
	if h.active {
		if now.Sub(h.last) >= m.clearWindow() {
			*h = holdState{}
			return false
		}
		return true // гистерезис: условие пропало, но признак ещё держится
	}
	h.since = time.Time{}
	h.peak = 0
	return false
}

// peak — пиковое значение условия за время удержания (для фактов).
func (m *Monitor) peak(id string) float64 {
	if h := m.holds[id]; h != nil {
		return h.peak
	}
	return 0
}

// newFinding — заготовка системной находки. Признаки сетевой нагрузки
// не привязаны к процессу, поэтому вес нулевой: на оценку процессов
// они не влияют (категория network только для группировки в
// интерфейсе).
func (m *Monitor) newFinding(id string, risk model.Risk, path string, title i18n.Msg, ev []i18n.Msg) model.SystemFinding {
	f := model.SystemFinding{Finding: model.Finding{ID: id, Title: title, Category: model.CatNetwork,
		Recommendation: i18n.T(recKeys[id]), Evidence: ev}, Path: path, Risk: risk}
	if m.opt.Allowed != nil && m.opt.Allowed(id) {
		// Подавленная находка видна, но не влияет на сводку и историю.
		f.Suppressed, f.Risk = true, model.RiskInfo
	}
	return f
}

// checkCounters пересчитывает признаки по счётчикам ядра. Вызывается
// под m.mu из Sample (горутина метрик).
func (m *Monitor) checkCounters(now time.Time, c model.NetLoadCounters, ct *model.ConntrackInfo) []model.SystemFinding {
	if c.Average {
		return nil // первый замер: скорости средние с загрузки
	}
	var out []model.SystemFinding
	num := func(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) }
	pct := func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

	// SYN-флуд по счётчикам: cookies отправляются, когда очередь
	// полуоткрытых соединений переполнена.
	if m.hold(IDSynFlood+"|counters", c.CookiesSent > cookiesRate, now, m.need(holdSyn), c.CookiesSent) {
		risk := model.RiskMedium
		ev := []i18n.Msg{i18n.T("ev.net_cookies", num(c.CookiesSent), num(m.peak(IDSynFlood+"|counters")))}
		if c.ReqQFullDrop > 0 {
			// Cookies выключены или не справляются: SYN отбрасываются.
			risk = model.RiskHigh
			ev = append(ev, i18n.T("ev.net_reqq_drop", num(c.ReqQFullDrop)))
		}
		if c.SynCookies == 0 {
			ev = append(ev, i18n.T("ev.net_cookies_off"))
		}
		out = append(out, m.newFinding(IDSynFlood, risk, "net", i18n.T(titleKeys[IDSynFlood], num(c.CookiesSent)), ev))
	}
	// Очередь accept переполняется: приложение не успевает принимать.
	drops := c.ListenOverflows + c.ListenDrops
	if m.hold(IDListenOver+"|counters", drops > listenDropsRate, now, m.need(holdDrops), drops) {
		out = append(out, m.newFinding(IDListenOver, model.RiskMedium, "net",
			i18n.T(titleKeys[IDListenOver], num(drops)),
			[]i18n.Msg{i18n.T("ev.net_listen_drops", num(c.ListenOverflows), num(c.ListenDrops), strconv.Itoa(c.SomaxConn))}))
	}
	// Таблица conntrack: когда она полна, ядро теряет новые соединения.
	if ct != nil {
		over := ct.Percent >= conntrackShare*100
		if m.hold(IDConntrack, over, now, m.need(holdConntrack), ct.Percent) {
			risk := model.RiskMedium
			ev := []i18n.Msg{i18n.T("ev.net_conntrack", pct(ct.Percent), strconv.Itoa(ct.Count), strconv.Itoa(ct.Max))}
			if lost := ct.Drop + ct.EarlyDrop + ct.InsertFailed; lost > 0 {
				risk = model.RiskHigh
				ev = append(ev, i18n.T("ev.net_conntrack_drop", num(ct.Drop), num(ct.EarlyDrop), num(ct.InsertFailed)))
			} else if ct.Percent >= conntrackHigh*100 {
				risk = model.RiskHigh
			}
			out = append(out, m.newFinding(IDConntrack, risk, "conntrack",
				i18n.T(titleKeys[IDConntrack], pct(ct.Percent)), ev))
		}
	}
	// Сокеты без владельца: при флуде их становится столько, что ядро
	// начинает их убивать (TCPAbortOnMemory).
	orphanOver := c.MaxOrphans > 0 && float64(c.TCPOrphan) >= orphanShare*float64(c.MaxOrphans) || c.AbortOnMemory > 0
	if m.hold(IDOrphans, orphanOver, now, m.need(holdDrops), float64(c.TCPOrphan)) {
		ev := []i18n.Msg{i18n.T("ev.net_orphans", strconv.Itoa(c.TCPOrphan), strconv.Itoa(c.MaxOrphans))}
		if c.AbortOnMemory > 0 {
			ev = append(ev, i18n.T("ev.net_abort_memory", num(c.AbortOnMemory)))
		}
		out = append(out, m.newFinding(IDOrphans, model.RiskLow, "net",
			i18n.T(titleKeys[IDOrphans], strconv.Itoa(c.TCPOrphan)), ev))
	}
	// UDP: приложение не успевает читать или поток идёт на закрытые порты.
	udpBuf, udpPorts := c.UDPRcvbufErrors > udpRcvbufRate, c.UDPNoPorts > udpNoPortsRate
	if m.hold(IDUDPFlood, udpBuf || udpPorts, now, m.need(holdDrops), max(c.UDPRcvbufErrors, c.UDPNoPorts)) {
		risk := model.RiskLow
		if udpBuf {
			risk = model.RiskMedium
		}
		out = append(out, m.newFinding(IDUDPFlood, risk, "net",
			i18n.T(titleKeys[IDUDPFlood], num(c.UDPRcvbufErrors+c.UDPNoPorts)),
			[]i18n.Msg{i18n.T("ev.net_udp", num(c.UDPRcvbufErrors), num(c.UDPNoPorts), num(c.UDPInErrors))}))
	}
	// Отбросы на приёме: ядро или сетевая карта не успевают.
	rx := c.RxDrops + c.SoftnetDropped
	if m.hold(IDRxDrops, rx > rxDropsRate, now, m.need(holdDrops), rx) {
		ev := []i18n.Msg{i18n.T("ev.net_rx_drops", num(c.RxDrops), num(c.SoftnetDropped), num(c.PPSIn))}
		if c.TimeSqueeze > 0 {
			ev = append(ev, i18n.T("ev.net_time_squeeze", num(c.TimeSqueeze)))
		}
		out = append(out, m.newFinding(IDRxDrops, model.RiskMedium, "net",
			i18n.T(titleKeys[IDRxDrops], num(rx)), ev))
	}
	// Наплыв пакетов: сам по себе атаку не доказывает, но помогает
	// понять картину вместе с остальными признаками.
	if base, ok := m.base(KeyPPSIn); ok {
		surge := c.PPSIn >= ppsSurge && c.PPSIn >= m.opt.SurgeFactor*base
		if m.hold(IDPPSSurge, surge, now, m.need(holdDrops), c.PPSIn) {
			out = append(out, m.newFinding(IDPPSSurge, model.RiskLow, "net",
				i18n.T(titleKeys[IDPPSSurge], num(c.PPSIn)),
				[]i18n.Msg{i18n.T("ev.net_pps", num(c.PPSIn), num(base), pct(c.PPSIn/max(base, 1)))}))
		}
	}
	return out
}

// KeyPPSIn — ряд метрик с входящими пакетами (его ведёт раздел 15).
const KeyPPSIn = "pps_in"

// base — «как обычно» для ряда: медиана за сутки. ok = false, если
// метрик меньше шести часов или база нулевая: относительные пороги
// применять не к чему.
func (m *Monitor) base(key string) (float64, bool) {
	if m.opt.Baseline == nil {
		return 0, false
	}
	v, ok := m.opt.Baseline(key, 24*time.Hour)
	if !ok || v <= 0 {
		return 0, false
	}
	return v, true
}

// rebuildFindings собирает общий список признаков: по счётчикам, по
// соединениям и сводный. Возвращает ID сработавших признаков (по
// одному разу, без подавленных allowlist). Вызывается под m.mu.
//
// Отчёт здесь не меняется: его указатель уже лежит в снимке сканера, и
// править его из горутины метрик — гонка. Сработавшие признаки
// попадают в отчёт при следующем сканировании.
func (m *Monitor) rebuildFindings() []string {
	all := append([]model.SystemFinding(nil), m.counterFindings...)
	all = append(all, m.connFindings...)
	all = dropGeneric(all)
	// Сводный признак: симптомы минимум из двух групп.
	groups := map[string]bool{}
	var ids []string
	seen := map[string]bool{}
	for _, f := range all {
		if f.Suppressed || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		if g := group[f.ID]; g != "" {
			groups[g] = true
		}
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	if len(groups) >= 2 {
		ev := []i18n.Msg{i18n.T("ev.net_suspected", i18n.L(strings.Join(ids, ", ")), strconv.Itoa(len(groups))),
			i18n.T("ev.net_volumetric")}
		f := m.newFinding(IDSuspected, model.RiskHigh, "net", i18n.T(titleKeys[IDSuspected], strconv.Itoa(len(groups))), ev)
		all = append(all, f)
		if !f.Suppressed {
			ids = append(ids, IDSuspected)
			sort.Strings(ids)
		}
	}
	m.findings = all
	return ids
}

// Пакет exposure оценивает внешнюю поверхность атаки сервера: какие
// порты слушают, откуда они доступны (loopback, частная сеть, интернет),
// какие из них — известные опасные сервисы (Redis, Docker API, базы
// данных) и какие порты контейнеров Docker опубликованы в обход ufw.
//
// Пакет только читает: слушающие сокеты из снимка, локальные адреса из
// /proc, конфигурацию ufw и config.v2.json контейнеров. Наружу он ничего
// не отправляет и сетевых проверок не делает.
package exposure

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// maxEvidenceAddrs — сколько публичных адресов перечислять в пояснении
// к сокету на всех интерфейсах.
const maxEvidenceAddrs = 5

// maxSystemEvidence — сколько строк фактов в одной системной находке.
const maxSystemEvidence = 12

// Input — данные одного сканирования для построения отчёта.
type Input struct {
	Procs   []*model.Process
	Sockets []model.Socket
	// Addrs — локальные адреса сервера (procfs.FS.LocalAddrs).
	Addrs []model.IfaceAddr
	// HostRoot — корень хоста для /etc/ufw и данных Docker.
	HostRoot string
	// Allowed сообщает, что правило allowlist подавляет признак ruleID для
	// процесса p (detect.Config.Allowed). nil — allowlist не задан.
	Allowed func(p *model.Process, ruleID string) bool
}

// Build строит отчёт о поверхности атаки.
func Build(in Input) *model.ExposureReport {
	rep := &model.ExposureReport{Addrs: ClassifyAddrs(in.Addrs), Entries: []model.Exposure{}, Bindings: []model.PortBinding{}}
	ufw := ReadUFW(in.HostRoot)
	rep.Firewall = ufw.Info
	bindings, warns := ReadDocker(in.HostRoot)
	rep.Warnings = warns
	if bindings != nil {
		rep.Bindings = bindings
	}

	byPID := make(map[int]*model.Process, len(in.Procs))
	hostNS := ""
	for _, p := range in.Procs {
		byPID[p.PID] = p
		if p.PID == 1 {
			hostNS = p.Namespaces["net"]
		}
	}
	// Привязки из config.v2.json по протоколу, адресу и порту хоста: по
	// ним docker-proxy получает имя и образ контейнера. Адрес входит в
	// ключ — два контейнера могут опубликовать один порт на разных
	// адресах хоста (127.0.0.1:8080 и 192.0.2.10:8080).
	byHostPort := map[string]model.PortBinding{}
	byPort := map[string]model.PortBinding{} // запасной вариант: адрес не совпал
	for _, b := range rep.Bindings {
		if k := bindKey(b); byHostPort[k].HostPort == 0 {
			byHostPort[k] = b
		}
		if k := portKey(b.Proto, b.HostPort); byPort[k].HostPort == 0 {
			byPort[k] = b
		}
	}
	publicAddrs := publicList(rep.Addrs)

	covered := map[string]bool{} // порты Docker, у которых есть слушающий сокет
	for _, s := range in.Sockets {
		if !Listening(s) {
			continue
		}
		e := model.Exposure{Proto: s.Proto, Addr: s.LocalAddr, Port: s.LocalPort, NetNS: s.NetNS, Inode: s.Inode,
			PID: s.PID, ProcKey: s.ProcKey, ProcName: s.ProcName, User: s.User}
		var p *model.Process
		if q := byPID[s.PID]; q != nil && s.PID != 0 && q.Key == s.ProcKey {
			p = q
			e.Exe = p.Exe
			e.Container = containerOf(p)
		}
		scope, wildcard := Classify(s.LocalAddr)
		if hostNS != "" && s.NetNS != "" && s.NetNS != hostNS {
			// Сокет в своём сетевом пространстве имён (контейнер): снаружи
			// он доступен только через опубликованный порт.
			scope, wildcard = model.ScopeNetNS, false
		}
		e.Scope, e.AllInterfaces = scope, wildcard
		proto := baseProto(s.Proto)
		if p != nil && progName(p) == "docker-proxy" {
			if b, ok := ParseDockerProxyArgs(p.Args); ok {
				c, ok := byHostPort[bindKey(b)]
				if !ok {
					c, ok = byPort[portKey(b.Proto, b.HostPort)]
				}
				if ok {
					b.ContainerID, b.ContainerName, b.Image = c.ContainerID, c.ContainerName, c.Image
				}
				e.Docker = &b
				e.Container = containerLabel(b)
				covered[bindKey(b)] = true
				if b.HostIP == "::" {
					// Один docker-proxy на [::] принимает и IPv4.
					v4 := b
					v4.HostIP = "0.0.0.0"
					covered[bindKey(v4)] = true
				}
			}
		}
		assess(&e, p, proto, ufw, publicAddrs, in.Allowed)
		rep.Entries = append(rep.Entries, e)
	}

	// Порты контейнеров без процесса docker-proxy (userland-proxy=false):
	// трафик заворачивают правила iptables, слушающего сокета на хосте нет.
	for _, b := range rep.Bindings {
		if covered[bindKey(b)] {
			continue
		}
		proto := b.Proto
		if strings.Contains(b.HostIP, ":") {
			proto += "6"
		}
		bb := b
		e := model.Exposure{Proto: proto, Addr: b.HostIP, Port: b.HostPort, Docker: &bb, Container: containerLabel(b)}
		e.Scope, e.AllInterfaces = Classify(b.HostIP)
		assess(&e, nil, b.Proto, ufw, publicAddrs, in.Allowed)
		rep.Entries = append(rep.Entries, e)
	}

	sort.SliceStable(rep.Entries, func(i, j int) bool {
		a, b := rep.Entries[i], rep.Entries[j]
		if a.Risk != b.Risk {
			return a.Risk > b.Risk
		}
		if ra, rb := scopeRank(a.Scope), scopeRank(b.Scope); ra != rb {
			return ra < rb
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.Addr < b.Addr
	})
	return rep
}

// Listening — сокет принимает входящие: TCP в состоянии LISTEN или
// несоединённый UDP, привязанный к порту (удалённый порт 0).
func Listening(s model.Socket) bool {
	switch s.Proto {
	case "tcp", "tcp6":
		return s.State == "LISTEN"
	case "udp", "udp6":
		return s.State == "UNCONN" && s.RemotePort == 0 && s.LocalPort != 0
	}
	return false
}

// assess распознаёт сервис и оценивает опасность доступности порта.
func assess(e *model.Exposure, p *model.Process, proto string, ufw *UFW, publicAddrs string, allowed func(*model.Process, string) bool) {
	t := target{proto: proto, port: e.Port}
	if e.Docker != nil {
		// Сервис внутри контейнера узнаётся по порту контейнера и образу:
		// на хосте слушает docker-proxy (или никто).
		t.port = e.Docker.ContainerPort
		t.image = ImageBase(e.Docker.Image)
	} else if p != nil {
		t.names = []string{p.Name}
		if p.Exe != "" {
			t.names = append(t.names, filepath.Base(p.Exe))
		}
		t.text = strings.ToLower(p.Exe + " " + p.Cmdline)
	}
	svc, match, confident := recognize(t)
	if svc != nil {
		e.Service = &model.Service{ID: svc.id, Name: svc.name, Class: svc.class, Match: match}
	}
	if e.Scope == model.ScopePublic {
		e.Firewall = ufw.PortState(proto, e.Port, family(e.Proto, e.Addr))
		if e.Docker != nil && e.Firewall == model.FwFiltered {
			// Правила Docker в iptables срабатывают раньше правил ufw.
			e.Firewall = model.FwBypassed
		}
	}
	if svc == nil || e.Scope != model.ScopePublic {
		e.Risk = model.RiskInfo
		if e.Firewall == model.FwBypassed {
			// Неизвестный сервис, но владелец считает порт закрытым ufw, а
			// он открыт: уровень — как у находки fw_docker_bypass.
			e.Risk = model.RiskHigh
			b := e.Docker
			e.Evidence = []i18n.Msg{
				i18n.T("ev.exp_listen", e.Proto, Endpoint(e.Addr, e.Port), owner(e)),
				i18n.T("ev.exp_docker", containerLabel(*b), orDash(b.Image), Endpoint(b.HostIP, b.HostPort), b.ContainerPort),
				i18n.T("ev.exp_ufw_active", ufw.Info.DefaultInput, b.HostPort, b.Proto),
				i18n.T("ev.exp_fw_bypassed"),
			}
			e.Recommendation = i18n.T("rule.fw_docker_bypass.rec", b.HostPort, b.ContainerPort)
		}
		return
	}

	sev := svc.sev
	if !confident {
		sev = lower(sev)
	}
	if e.Firewall == model.FwFiltered && sev > model.RiskLow {
		sev = model.RiskLow
	}
	if e.Firewall == model.FwBypassed {
		// Обход ufw сам по себе — HIGH, даже для «тихого» сервиса.
		sev = max(sev, model.RiskHigh)
	}
	e.Risk = sev
	e.FindingID = FindingID(svc.class)
	e.Evidence = evidence(e, svc, match, confident, ufw, publicAddrs)
	e.Recommendation = recommendation(e, svc)
	if p != nil && allowed != nil && allowed(p, e.FindingID) {
		e.Suppressed = true
	}
}

func evidence(e *model.Exposure, svc *service, match string, confident bool, ufw *UFW, publicAddrs string) []i18n.Msg {
	ev := []i18n.Msg{i18n.T("ev.exp_listen", e.Proto, Endpoint(e.Addr, e.Port), owner(e))}
	switch {
	case e.AllInterfaces && publicAddrs != "":
		ev = append(ev, i18n.T("ev.exp_wildcard", e.Addr, publicAddrs))
	case e.AllInterfaces:
		ev = append(ev, i18n.T("ev.exp_wildcard_nat", e.Addr))
	default:
		ev = append(ev, i18n.T("ev.exp_public_addr", e.Addr))
	}
	ev = append(ev, i18n.T("ev.exp_service", svc.name, matchText(match)))
	if !confident {
		ev = append(ev, i18n.T("ev.exp_port_only"))
	}
	if b := e.Docker; b != nil {
		ev = append(ev, i18n.T("ev.exp_docker", containerLabel(*b), orDash(b.Image), Endpoint(b.HostIP, b.HostPort), b.ContainerPort))
	}
	switch e.Firewall {
	case model.FwFiltered:
		ev = append(ev, i18n.T("ev.exp_fw_filtered", ufw.Info.DefaultInput, e.Port, baseProto(e.Proto)))
	case model.FwOpen:
		ev = append(ev, i18n.T("ev.exp_fw_open", e.Port, baseProto(e.Proto)))
	case model.FwBypassed:
		ev = append(ev, i18n.T("ev.exp_fw_bypassed"))
	}
	return ev
}

func recommendation(e *model.Exposure, svc *service) i18n.Msg {
	parts := []i18n.Msg{}
	if b := e.Docker; b != nil {
		parts = append(parts, i18n.T("rec.exp_docker", b.HostPort, b.ContainerPort))
	} else {
		parts = append(parts, i18n.T(svc.rec))
	}
	if e.Firewall == model.FwFiltered {
		parts = append(parts, i18n.T("rec.exp_filtered"))
	}
	parts = append(parts, i18n.T(classKeys[svc.class][1]))
	return i18n.Join(" ", parts...)
}

// matchText — пояснение, как узнан сервис.
func matchText(match string) i18n.Msg {
	switch match {
	case "port+process":
		return i18n.T("ev.exp_match_port_process")
	case "port+image":
		return i18n.T("ev.exp_match_port_image")
	case "process":
		return i18n.T("ev.exp_match_process")
	case "image":
		return i18n.T("ev.exp_match_image")
	}
	return i18n.T("ev.exp_match_port")
}

// owner — кто держит сокет: «redis-server (PID 860, redis)».
func owner(e *model.Exposure) i18n.Msg {
	switch {
	case e.PID != 0:
		return i18n.T("ev.exp_owner", e.ProcName, e.PID, e.User)
	case e.Docker != nil:
		return i18n.T("ev.exp_owner_docker")
	}
	return i18n.T("ev.exp_owner_unknown")
}

// SystemFindings превращает опасные публичные порты в системные находки:
// у них свой уровень (Redis в интернете — CRITICAL, даже если сам процесс
// легитимен), они попадают в историю и журнал. Записи с одним признаком
// и одним портом (0.0.0.0 и :: одного сервиса) сводятся в одну находку;
// Path — «порт/протокол», он же ключ находки в истории.
func SystemFindings(rep *model.ExposureReport) []model.SystemFinding {
	if rep == nil {
		return nil
	}
	type group struct {
		f          model.SystemFinding
		suppressed bool
		seen       map[string]bool
	}
	groups := map[string]*group{}
	var order []string
	addEv := func(g *group, ev []i18n.Msg) {
		for _, m := range ev {
			k := m.In(i18n.RU)
			if g.seen[k] || len(g.f.Evidence) >= maxSystemEvidence {
				continue
			}
			g.seen[k] = true
			g.f.Evidence = append(g.f.Evidence, m)
		}
	}
	get := func(key, id string, title i18n.Msg, path string, risk model.Risk, rec i18n.Msg) *group {
		g := groups[key]
		if g == nil {
			g = &group{seen: map[string]bool{}, suppressed: true}
			g.f = model.SystemFinding{Finding: model.Finding{ID: id, Title: title, Category: model.CatExposure, Recommendation: rec}, Path: path, Risk: risk}
			groups[key] = g
			order = append(order, key)
		}
		if risk > g.f.Risk {
			g.f.Risk, g.f.Recommendation = risk, rec
		}
		return g
	}
	for _, e := range rep.Entries {
		path := portKey(baseProto(e.Proto), e.Port)
		if e.FindingID != "" && e.Service != nil {
			g := get(e.FindingID+"|"+path, e.FindingID, Title(&e), path, e.Risk, e.Recommendation)
			g.suppressed = g.suppressed && e.Suppressed
			addEv(g, e.Evidence)
		}
		if e.Firewall == model.FwBypassed && e.Docker != nil {
			b := e.Docker
			g := get("fw_docker_bypass|"+path, "fw_docker_bypass", i18n.T("rule.fw_docker_bypass.title"), path, model.RiskHigh,
				i18n.T("rule.fw_docker_bypass.rec", b.HostPort, b.ContainerPort))
			g.suppressed = false
			addEv(g, []i18n.Msg{
				i18n.T("ev.exp_docker", containerLabel(*b), orDash(b.Image), Endpoint(b.HostIP, b.HostPort), b.ContainerPort),
				i18n.T("ev.exp_ufw_active", rep.Firewall.DefaultInput, b.HostPort, b.Proto),
				i18n.T("ev.exp_fw_bypassed"),
			})
		}
	}
	out := make([]model.SystemFinding, 0, len(order))
	for _, k := range order {
		g := groups[k]
		if g.suppressed {
			// Подавленная allowlist находка видна, но не влияет на сводку,
			// историю и журнал.
			g.f.Suppressed = true
			g.f.Risk = model.RiskInfo
		}
		g.f.Weight = Weight(g.f.Risk)
		out = append(out, g.f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// Weight — вес признака доступности для оценки процесса. Доступность
// сервиса из сети — не признак взлома, поэтому признак не «сильный»:
// сам по себе он поднимает процесс не выше LOW, а с признаками других
// категорий (запуск из /tmp, маскировка) усиливает оценку.
func Weight(r model.Risk) int {
	switch r {
	case model.RiskCritical:
		return 25
	case model.RiskHigh:
		return 15
	case model.RiskMedium:
		return 8
	case model.RiskLow:
		return 3
	}
	return 0
}

// Stats — сводка для заголовка интерфейса: сколько публичных портов и
// сколько из них опасны (с учётом allowlist). Порт считается один раз:
// сервис на 0.0.0.0 и :: — один открытый порт, как и одна системная
// находка «порт/протокол».
func Stats(rep *model.ExposureReport) (public, dangerous int) {
	if rep == nil {
		return 0, 0
	}
	pub, danger := map[string]bool{}, map[string]bool{}
	for _, e := range rep.Entries {
		if e.Scope != model.ScopePublic {
			continue
		}
		k := portKey(baseProto(e.Proto), e.Port)
		pub[k] = true
		if e.Risk >= model.RiskLow && !e.Suppressed {
			danger[k] = true
		}
	}
	return len(pub), len(danger)
}

// Endpoint — «адрес:порт», IPv6 в квадратных скобках.
func Endpoint(addr string, port int) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]:" + strconv.Itoa(port)
	}
	return addr + ":" + strconv.Itoa(port)
}

// family — какие семейства адресов принимает сокет: tcp/udp — IPv4;
// tcp6/udp6 на :: — оба (net.ipv6.bindv6only по умолчанию 0); на
// ::ffff:a.b.c.d — IPv4; на остальных IPv6-адресах — только IPv6.
func family(proto, addr string) int {
	if !strings.HasSuffix(proto, "6") {
		return Fam4
	}
	ip, err := netip.ParseAddr(addr)
	switch {
	case err != nil:
		return FamBoth
	case ip.IsUnspecified():
		return FamBoth
	case ip.Is4In6() || ip.Is4():
		return Fam4
	}
	return Fam6
}

// bindKey — ключ привязки: протокол, адрес и порт хоста.
func bindKey(b model.PortBinding) string {
	ip := b.HostIP
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = a.Unmap().String()
	}
	return b.Proto + "|" + ip + "|" + strconv.Itoa(b.HostPort)
}

func portKey(proto string, port int) string { return fmt.Sprintf("%d/%s", port, proto) }

func baseProto(p string) string { return strings.TrimSuffix(p, "6") }

func progName(p *model.Process) string {
	if p.Exe != "" {
		return filepath.Base(p.Exe)
	}
	return p.Name
}

func containerOf(p *model.Process) string {
	if p.Container != "" {
		return strings.TrimSpace(p.ContainerRuntime + " " + p.Container)
	}
	return p.ContainerRuntime
}

func containerLabel(b model.PortBinding) string {
	switch {
	case b.ContainerName != "":
		return b.ContainerName
	case b.ContainerID != "":
		return b.ContainerID
	}
	return "docker"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// publicList — публичные адреса сервера через запятую (не больше
// maxEvidenceAddrs).
func publicList(addrs []model.IfaceAddr) string {
	var pub []string
	for _, a := range addrs {
		if a.Scope == model.ScopePublic && !slices.Contains(pub, a.Addr) {
			pub = append(pub, a.Addr)
		}
	}
	if len(pub) > maxEvidenceAddrs {
		pub = append(pub[:maxEvidenceAddrs], "…")
	}
	return strings.Join(pub, ", ")
}

func scopeRank(s string) int {
	switch s {
	case model.ScopePublic:
		return 0
	case model.ScopePrivate:
		return 1
	case model.ScopeNetNS:
		return 2
	}
	return 3
}

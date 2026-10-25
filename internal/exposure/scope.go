package exposure

import (
	"net/netip"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// cgnat — 100.64.0.0/10 (RFC 6598): адреса за NAT провайдера, из
// интернета напрямую недоступны.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Classify определяет область видимости адреса, на котором слушает
// сокет. wildcard = true для 0.0.0.0 и :: — сокет принимает соединения на
// всех интерфейсах, включая публичные. Нераспознанный адрес считается
// публичным: лучше лишний раз показать порт, чем пропустить открытый.
func Classify(addr string) (scope string, wildcard bool) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return model.ScopePublic, false
	}
	// ::ffff:a.b.c.d — IPv4 на сокете с двойным стеком.
	ip = ip.Unmap()
	switch {
	case ip.IsUnspecified():
		return model.ScopePublic, true
	case ip.IsLoopback():
		return model.ScopeLoopback, false
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), cgnat.Contains(ip):
		return model.ScopePrivate, false
	}
	return model.ScopePublic, false
}

// ClassifyAddrs заполняет Scope у локальных адресов сервера.
func ClassifyAddrs(addrs []model.IfaceAddr) []model.IfaceAddr {
	out := make([]model.IfaceAddr, len(addrs))
	for i, a := range addrs {
		a.Scope, _ = Classify(a.Addr)
		out[i] = a
	}
	return out
}

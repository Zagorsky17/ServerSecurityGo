package procfs

import (
	"bufio"
	"net/netip"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// maxNetFile — предел размера таблиц /proc/net/fib_trie и if_inet6.
// На сервере с тысячами маршрутов fib_trie бывает большим, но не больше
// нескольких мегабайт; лимит защищает память службы от неожиданностей.
const maxNetFile = 8 << 20

// maxAddrs — сколько локальных адресов сохранять (контейнерные хосты с
// сотнями veth-интерфейсов не должны раздувать снимок).
const maxAddrs = 512

// LocalAddrs возвращает локальные адреса сервера (пространства имён
// сканера) из /proc/net/fib_trie (IPv4) и /proc/net/if_inet6 (IPv6).
// netlink (net.Interfaces) не используется: в юните systemd разрешены
// только AF_INET, AF_INET6 и AF_UNIX, а /proc ещё и подменяется
// поддельным деревом в тестах. Область видимости (Scope) заполняет
// вызывающий.
func (f *FS) LocalAddrs() []model.IfaceAddr {
	var out []model.IfaceAddr
	if data, ok := readNetFile(f.path("net", "fib_trie")); ok {
		for _, a := range ParseFibTrie(data) {
			out = append(out, model.IfaceAddr{Addr: a})
		}
	}
	if data, ok := readNetFile(f.path("net", "if_inet6")); ok {
		out = append(out, ParseIfInet6(data)...)
	}
	if len(out) > maxAddrs {
		out = out[:maxAddrs]
	}
	return out
}

func readNetFile(path string) (string, bool) {
	data, _, err := readLimited(path, maxNetFile)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// ParseFibTrie извлекает локальные IPv4-адреса из /proc/net/fib_trie.
// Формат — дерево префиксов; адрес интерфейса — лист «|-- A.B.C.D», за
// которым следует строка «/32 host LOCAL». Каждый адрес встречается в
// таблицах Main и Local, поэтому результат без повторов.
func ParseFibTrie(data string) []string {
	var out []string
	seen := map[string]bool{}
	last := ""
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if a, ok := strings.CutPrefix(t, "|-- "); ok {
			last = a
			continue
		}
		if strings.HasPrefix(t, "/32 host LOCAL") && last != "" {
			if ip, err := netip.ParseAddr(last); err == nil && ip.Is4() && !seen[last] {
				seen[last] = true
				out = append(out, ip.String())
			}
		}
	}
	return out
}

// ParseIfInet6 разбирает /proc/net/if_inet6.
// Формат строки: адрес (32 hex) индекс длина-префикса scope флаги имя.
func ParseIfInet6(data string) []model.IfaceAddr {
	var out []model.IfaceAddr
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || len(f[0]) != 32 {
			continue
		}
		var b [16]byte
		ok := true
		for i := range 16 {
			hi, lo := unhex(f[0][2*i]), unhex(f[0][2*i+1])
			if hi < 0 || lo < 0 {
				ok = false
				break
			}
			b[i] = byte(hi<<4 | lo)
		}
		if !ok {
			continue
		}
		out = append(out, model.IfaceAddr{Iface: f[5], Addr: netip.AddrFrom16(b).String()})
	}
	return out
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

package procfs

import (
	"bufio"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// tcpStates — коды состояний TCP из include/net/tcp_states.h.
var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

// DefaultMaxSockets — предел числа сокетов, которые читаются из таблиц
// одного пространства имён. Во время SYN-флуда /proc/net/tcp
// разрастается до сотен тысяч строк, и без предела снимок занял бы
// сотни мегабайт. Сверх предела строки пропускаются, а их число
// возвращается: интерфейсы пишут «таблица усечена».
const DefaultMaxSockets = 100_000

// ReadNetTables читает таблицы сокетов сетевого пространства имён,
// в котором находится процесс pid (через /proc/PID/net/*). Если pid = 0,
// читаются /proc/net/* — пространство имён самого сканера.
// dropped — сколько сокетов не вошло в предел MaxSockets.
func (f *FS) ReadNetTables(pid int, netns string) (socks []model.Socket, dropped int) {
	base := f.path("net")
	if pid > 0 {
		base = f.path(strconv.Itoa(pid), "net")
	}
	limit := f.MaxSockets
	if limit <= 0 {
		limit = DefaultMaxSockets
	}
	var out []model.Socket
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile(base + "/" + proto)
		if err != nil {
			continue
		}
		t := ParseNetTable(string(data), proto, netns)
		if n := limit - len(out); len(t) > n {
			dropped += len(t) - max(n, 0)
			t = t[:max(n, 0)]
		}
		out = append(out, t...)
	}
	if data, err := os.ReadFile(base + "/unix"); err == nil {
		out = append(out, ParseUnixTable(string(data), netns)...)
	}
	return out, dropped
}

// ParseNetTable разбирает /proc/net/{tcp,tcp6,udp,udp6}.
// Формат строки: sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode ...
func ParseNetTable(data, proto, netns string) []model.Socket {
	var out []model.Socket
	sc := bufio.NewScanner(strings.NewReader(data))
	first := true
	for sc.Scan() {
		if first { // заголовок
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		la, lp, ok1 := parseHexAddr(f[1])
		ra, rp, ok2 := parseHexAddr(f[2])
		if !ok1 || !ok2 {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		// tx_queue:rx_queue — шестнадцатеричные. У слушающего сокета это
		// предел очереди accept и её текущая длина.
		var txq, rxq uint64
		if tx, rx, ok := strings.Cut(f[4], ":"); ok {
			txq, _ = strconv.ParseUint(tx, 16, 64)
			rxq, _ = strconv.ParseUint(rx, 16, 64)
		}
		state := tcpStates[strings.ToUpper(f[3])]
		if strings.HasPrefix(proto, "udp") {
			// У UDP «07» означает несоединённый сокет, «01» — connect().
			switch strings.ToUpper(f[3]) {
			case "07":
				state = "UNCONN"
			case "01":
				state = "ESTABLISHED"
			}
		}
		out = append(out, model.Socket{
			Proto: proto, LocalAddr: la, LocalPort: lp, RemoteAddr: ra, RemotePort: rp,
			State: state, UID: uid, Inode: inode, NetNS: netns, TxQueue: txq, RxQueue: rxq,
		})
	}
	return out
}

// SocketOwner возвращает UID владельца TCP-сокета с локальным адресом
// local и удалённым remote из таблиц /proc/net/tcp и tcp6 пространства
// имён самого сканера. Для TCP нет SO_PEERCRED, поэтому служба так узнаёт,
// какой пользователь подключился к ней по loopback: клиентский сокет — это
// строка, где local — адрес клиента, а remote — адрес службы.
// false — сокет не найден (соединение уже закрыто или /proc недоступен).
func (f *FS) SocketOwner(local, remote netip.AddrPort) (int, bool) {
	for _, proto := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(f.path("net", proto))
		if err != nil {
			continue
		}
		for _, s := range ParseNetTable(string(data), proto, "") {
			if sameAddrPort(s.LocalAddr, s.LocalPort, local) && sameAddrPort(s.RemoteAddr, s.RemotePort, remote) {
				return s.UID, true
			}
		}
	}
	return 0, false
}

// sameAddrPort сравнивает адрес из таблицы с ap; IPv4 в виде
// ::ffff:a.b.c.d (сокеты tcp6 с двойным стеком) равен a.b.c.d.
func sameAddrPort(addr string, port int, ap netip.AddrPort) bool {
	a, err := netip.ParseAddr(addr)
	return err == nil && port == int(ap.Port()) && a.Unmap() == ap.Addr().Unmap()
}

// ParseUnixTable разбирает /proc/net/unix.
// Формат: Num RefCount Protocol Flags Type St Inode [Path]
func ParseUnixTable(data, netns string) []model.Socket {
	var out []model.Socket
	sc := bufio.NewScanner(strings.NewReader(data))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 7 {
			continue
		}
		inode, _ := strconv.ParseUint(f[6], 10, 64)
		s := model.Socket{Proto: "unix", Inode: inode, NetNS: netns, UID: -1}
		if len(f) >= 8 {
			s.Path = f[7]
		}
		if f[3] == "00010000" {
			s.State = "LISTEN"
		}
		out = append(out, s)
	}
	return out
}

// parseHexAddr разбирает адрес вида «0100007F:1F90». IPv4 записан как
// одно 32-битное слово в порядке байтов хоста (little-endian), IPv6 —
// как четыре таких слова.
func parseHexAddr(s string) (string, int, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", 0, false
	}
	b, err := hex.DecodeString(host)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", 0, false
	}
	// Разворачиваем байты внутри каждого 32-битного слова.
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b).String(), int(p), true
}

package netload

import (
	"strconv"
	"strings"
)

// ParsePairs разбирает /proc/net/netstat и /proc/net/snmp: строки идут
// парами — сначала имена столбцов, потом значения с тем же префиксом.
// Результат: префикс («TcpExt», «Tcp») → имя → значение. Число столбцов
// у разных версий ядра разное, поэтому имена и значения сопоставляются
// по месту, а лишние игнорируются.
func ParsePairs(data string) map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	var names []string
	var prefix string
	for line := range strings.SplitSeq(data, "\n") {
		p, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if names == nil || prefix != p {
			// Строка имён: первое поле не число.
			if len(f) > 0 {
				if _, err := strconv.ParseUint(f[0], 10, 64); err != nil {
					names, prefix = f, p
					continue
				}
			}
			continue
		}
		m := out[p]
		if m == nil {
			m = map[string]uint64{}
			out[p] = m
		}
		for i, v := range f {
			if i >= len(names) {
				break
			}
			// Отрицательные значения бывают у счётчиков, которые ядро
			// печатает со знаком (MaxConn = -1): пропускаем.
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				m[names[i]] = n
			}
		}
		names, prefix = nil, ""
	}
	return out
}

// ParseSockstat разбирает /proc/net/sockstat и sockstat6: строки вида
// «TCP: inuse 12 orphan 0 tw 3 alloc 20 mem 2». Результат: раздел →
// имя → значение.
func ParseSockstat(data string) map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	for line := range strings.SplitSeq(data, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		m := out[name]
		if m == nil {
			m = map[string]uint64{}
			out[name] = m
		}
		for i := 0; i+1 < len(f); i += 2 {
			if v, err := strconv.ParseUint(f[i+1], 10, 64); err == nil {
				m[f[i]] = v
			}
		}
	}
	return out
}

// ParseHexStat разбирает /proc/net/stat/nf_conntrack: первая строка —
// имена столбцов, дальше по строке на процессор с шестнадцатеричными
// значениями. Значения суммируются по всем процессорам.
func ParseHexStat(data string) map[string]uint64 {
	out := map[string]uint64{}
	var names []string
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if names == nil {
			names = f
			continue
		}
		for i, v := range f {
			if i >= len(names) {
				break
			}
			if n, err := strconv.ParseUint(v, 16, 64); err == nil {
				out[names[i]] += n
			}
		}
	}
	return out
}

// ParseSoftnet разбирает /proc/net/softnet_stat: по строке на
// процессор, значения шестнадцатеричные. Второй столбец — отброшенные
// пакеты (очередь backlog переполнена), третий — time_squeeze (ядро не
// успело обработать пакеты за отведённое время). Столбцов у разных
// ядер от 9 до 13, нужны только первые три.
func ParseSoftnet(data string) (dropped, squeeze uint64) {
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		d, err1 := strconv.ParseUint(f[1], 16, 64)
		s, err2 := strconv.ParseUint(f[2], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		dropped += d
		squeeze += s
	}
	return dropped, squeeze
}

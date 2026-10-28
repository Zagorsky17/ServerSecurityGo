package netload

import (
	"strings"
	"testing"
)

// Фаззинг разборщиков /proc/net: формат отличается у разных версий
// ядра, а служба читает эти файлы каждые несколько секунд. go test
// выполняет только начальный корпус; долгий прогон:
// go test -fuzz=FuzzParsePairs ./internal/netload.

func FuzzParsePairs(f *testing.F) {
	for _, s := range []string{netstatText, snmpText, "A: B\nA: 1\n", "A: B\n", "A:\nA:\n", "A: B C\nA: 1 2 3\n", ":::", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		for prefix, m := range ParsePairs(data) {
			if prefix == "" {
				t.Fatal("раздел без имени")
			}
			for name := range m {
				if name == "" {
					t.Fatalf("счётчик без имени в %q", prefix)
				}
			}
		}
	})
}

func FuzzParseSockstat(f *testing.F) {
	for _, s := range []string{"TCP: inuse 1 orphan 2", "TCP:", "TCP: inuse", "x: 1 2 3", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_ = ParseSockstat(data)
	})
}

func FuzzParseHexStat(f *testing.F) {
	for _, s := range []string{"a b\n01 02\n", "a\n", "0 0\n", strings.Repeat("ff ", 50), ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_ = ParseHexStat(data)
	})
}

func FuzzParseSoftnet(f *testing.F) {
	for _, s := range []string{"00000001 00000002 00000003", "zz zz zz", "1 2", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = ParseSoftnet(data)
	})
}

func FuzzParseNets(f *testing.F) {
	for _, s := range []string{"10.0.0.0/8,2001:db8::/32", "1.2.3.4", "10.0.0.0/99", ",,,", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		nets, raw, _ := ParseNets(data)
		if len(nets) != len(raw) {
			t.Fatalf("сетей %d, исходных строк %d", len(nets), len(raw))
		}
		for _, n := range nets {
			if !n.IsValid() {
				t.Fatalf("неверная сеть: %v", n)
			}
		}
	})
}

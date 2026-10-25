package procfs

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// fibTrie — фрагмент настоящего /proc/net/fib_trie (Ubuntu 24.04).
const fibTrie = `Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 192.0.2.0/24 2 0 2
        |-- 192.0.2.0
           /24 link UNICAST
        |-- 192.0.2.10
           /32 host LOCAL
        |-- 192.0.2.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 127.0.0.1
        /32 host LOCAL
     |-- 192.0.2.10
        /32 host LOCAL
     |-- 172.17.0.1
        /32 host LOCAL
`

func TestParseFibTrie(t *testing.T) {
	got := ParseFibTrie(fibTrie)
	want := []string{"127.0.0.1", "192.0.2.10", "172.17.0.1"}
	if !slices.Equal(got, want) {
		t.Errorf("адреса %v, ожидалось %v", got, want)
	}
	if got := ParseFibTrie("/32 host LOCAL\n|-- не-адрес\n/32 host LOCAL\n|-- ::1\n/32 host LOCAL\n"); len(got) != 0 {
		t.Errorf("мусор: %v", got)
	}
}

func TestParseIfInet6(t *testing.T) {
	data := "00000000000000000000000000000001 01 80 10 80       lo\n" +
		"20010db8000000000000000000000010 02 40 00 80     eth0\n" +
		"fe80000000000000021122fffe334455 02 40 20 80     eth0\n" +
		"zz80000000000000021122fffe334455 02 40 20 80     eth0\n" + // не hex
		"fe80 02 40 20 80 eth0\n" // короткий адрес
	got := ParseIfInet6(data)
	want := []model.IfaceAddr{{Iface: "lo", Addr: "::1"}, {Iface: "eth0", Addr: "2001:db8::10"}, {Iface: "eth0", Addr: "fe80::211:22ff:fe33:4455"}}
	if !slices.Equal(got, want) {
		t.Errorf("адреса %v, ожидалось %v", got, want)
	}
}

func TestLocalAddrs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	fs := New(root, "/")
	if got := fs.LocalAddrs(); len(got) != 0 {
		t.Errorf("без файлов: %v", got)
	}
	for name, data := range map[string]string{"fib_trie": fibTrie, "if_inet6": "00000000000000000000000000000001 01 80 10 80 lo\n"} {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := fs.LocalAddrs()
	if len(got) != 4 || got[3].Addr != "::1" {
		t.Errorf("адреса: %v", got)
	}
}

func FuzzParseFibTrie(f *testing.F) {
	f.Add(fibTrie)
	f.Fuzz(func(t *testing.T, data string) {
		for _, a := range ParseFibTrie(data) {
			if a == "" {
				t.Fatal("пустой адрес")
			}
		}
	})
}

func FuzzParseIfInet6(f *testing.F) {
	f.Add("00000000000000000000000000000001 01 80 10 80 lo\n")
	f.Fuzz(func(t *testing.T, data string) {
		for _, a := range ParseIfInet6(data) {
			if a.Addr == "" || a.Iface == "" {
				t.Fatalf("неполный адрес %+v", a)
			}
		}
	})
}

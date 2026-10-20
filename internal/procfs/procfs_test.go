package procfs

import (
	"slices"
	"testing"
)

func TestParseStatCommWithParens(t *testing.T) {
	// comm может содержать пробелы и скобки — берём последнюю «)».
	line := "1234 (evil) (x) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 3 0 98765 1048576 512 18446744073709551615"
	st, err := ParseStat(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.Comm != "evil) (x" {
		t.Errorf("comm = %q", st.Comm)
	}
	if st.State != "S" || st.PPID != 1 || st.UTime != 250 || st.STime != 50 || st.Threads != 3 || st.StartTicks != 98765 || st.RSSPages != 512 {
		t.Errorf("неверный разбор: %+v", st)
	}
	if st.Flags&pfKthread != 0 {
		t.Error("пользовательский процесс помечен как поток ядра")
	}
}

func TestParseStatErrors(t *testing.T) {
	for _, s := range []string{"", "123 no parens", "1 (x) S 1"} {
		if _, err := ParseStat(s); err == nil {
			t.Errorf("ожидалась ошибка для %q", s)
		}
	}
}

func TestParseStatus(t *testing.T) {
	st := ParseStatus("Name:\tnginx\nUid:\t33\t33\t33\t33\nGid:\t33\t33\t33\t33\nVmSize:\t  10240 kB\nVmRSS:\t   2048 kB\nThreads:\t2\nNSpid:\t4321\t7\n")
	if st.Name != "nginx" || st.UID != 33 || st.EUID != 33 || st.RSSKB != 2048 || st.VMSizeKB != 10240 || st.Threads != 2 {
		t.Errorf("неверный разбор: %+v", st)
	}
	if !slices.Equal(st.NSPID, []int{4321, 7}) {
		t.Errorf("NSpid = %v", st.NSPID)
	}
	// Старое ядро без NSpid и Vm* (поток ядра).
	st = ParseStatus("Name:\tkthreadd\nUid:\t0\t0\t0\t0\n")
	if st.NSPID != nil || st.RSSKB != 0 {
		t.Errorf("лишние поля: %+v", st)
	}
}

func TestParseCmdline(t *testing.T) {
	got := ParseCmdline([]byte("python3\x00-c\x00print(1)\x00"))
	if !slices.Equal(got, []string{"python3", "-c", "print(1)"}) {
		t.Errorf("got %q", got)
	}
	if ParseCmdline([]byte{}) != nil || ParseCmdline([]byte("\x00")) != nil {
		t.Error("пустая cmdline должна давать nil")
	}
	// argv перезаписан одной строкой с пробелами.
	if got := ParseCmdline([]byte("nginx: worker process")); len(got) != 1 {
		t.Errorf("got %q", got)
	}
}

func TestParseHexAddr(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"0100007F:1F90", "127.0.0.1", 8080},
		{"00000000:0016", "0.0.0.0", 22},
		{"0A00020F:01BB", "15.2.0.10", 443},
		{"00000000000000000000000001000000:0050", "::1", 80},
		{"0000000000000000FFFF00000100007F:0035", "127.0.0.1", 53}, // IPv4-mapped
	}
	for _, c := range cases {
		ip, port, ok := parseHexAddr(c.in)
		if !ok || ip != c.ip || port != c.port {
			t.Errorf("%s: got %s:%d ok=%v, want %s:%d", c.in, ip, port, ok, c.ip, c.port)
		}
	}
	if _, _, ok := parseHexAddr("zz:1"); ok {
		t.Error("ожидалась ошибка")
	}
}

func TestParseNetTable(t *testing.T) {
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0F02000A:CC38 1764330C:115C 01 00000000:00000000 02:000A7B4C 00000000    33        0 23456 2 0000000000000000 20 4 30 10 -1
`
	socks := ParseNetTable(data, "tcp", "net:[1]")
	if len(socks) != 2 {
		t.Fatalf("сокетов %d", len(socks))
	}
	if socks[0].State != "LISTEN" || socks[0].LocalPort != 22 || socks[0].Inode != 12345 {
		t.Errorf("listen: %+v", socks[0])
	}
	s := socks[1]
	if s.State != "ESTABLISHED" || s.RemoteAddr != "12.51.100.23" || s.RemotePort != 4444 || s.UID != 33 || s.NetNS != "net:[1]" {
		t.Errorf("established: %+v", s)
	}
	udp := ParseNetTable("hdr\n 0: 00000000:0035 00000000:0000 07 0:0 0:0 0 0 0 999 2\n", "udp", "")
	if len(udp) != 1 || udp[0].State != "UNCONN" {
		t.Errorf("udp: %+v", udp)
	}
}

func TestParseUnixTable(t *testing.T) {
	data := "Num       RefCount Protocol Flags    Type St Inode Path\n" +
		"0000000000000000: 00000002 00000000 00010000 0001 01 1111 /run/systemd/notify\n" +
		"0000000000000000: 00000003 00000000 00000000 0001 03 2222\n"
	s := ParseUnixTable(data, "")
	if len(s) != 2 || s[0].Path != "/run/systemd/notify" || s[0].State != "LISTEN" || s[1].Inode != 2222 {
		t.Errorf("%+v", s)
	}
}

func TestDetectContainer(t *testing.T) {
	id := "3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e"
	cases := map[string][2]string{
		"0::/system.slice/docker-" + id + ".scope\n":                  {"docker", id[:12]},
		"12:pids:/docker/" + id + "\n":                                {"docker", id[:12]},
		"0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-" + id: {"kubernetes", id[:12]},
		"0::/machine.slice/libpod-" + id + ".scope":                   {"podman", id[:12]},
		"0::/lxc.payload.web/init.scope":                              {"lxc", ""},
		"0::/system.slice/nginx.service\n":                            {"", ""},
		"0::/user.slice/user-1000.slice/session-3.scope":              {"", ""},
	}
	for in, want := range cases {
		rt, cid := DetectContainer(in)
		if rt != want[0] || cid != want[1] {
			t.Errorf("%q: got (%q,%q), want %v", in, rt, cid, want)
		}
	}
}

func TestFDKind(t *testing.T) {
	cases := map[string]string{
		"socket:[1]": "socket", "pipe:[2]": "pipe", "anon_inode:[eventfd]": "anon",
		"/memfd:x (deleted)": "memfd", "/tmp/a (deleted)": "deleted", "/dev/null": "device", "/var/log/syslog": "file",
	}
	for in, want := range cases {
		if got := FDKind(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

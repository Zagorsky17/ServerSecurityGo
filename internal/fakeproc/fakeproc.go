// Пакет fakeproc строит поддельное дерево /proc в обычном каталоге.
//
// Оно используется в тестах и в демо-режиме: сканер читает его теми же
// функциями, что и настоящий /proc, поэтому проверяется весь конвейер
// (сбор → анализ → история → интерфейс) даже на macOS.
//
// Симлинки exe/cwd/fd указывают на пути из описания процесса — procfs
// читает их через Readlink. Цели могут случайно существовать на машине,
// где идут тесты, поэтому для поддельных деревьев в procfs.FS выставляется
// SkipExeStat (см. NewFS).
package fakeproc

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
)

// Proc — описание поддельного процесса.
type Proc struct {
	PID, PPID  int
	Comm       string
	Args       []string
	Exe        string // цель симлинка exe; "" — нет (поток ядра)
	Cwd        string
	UID        int
	State      string
	Kernel     bool
	StartTicks uint64 // тики с момента загрузки
	UTime      uint64
	STime      uint64
	RSSKB      uint64
	Threads    int
	FDs        map[int]string // номер fd → цель симлинка
	Env        []string       // KEY=VALUE
	Cgroup     string
	NetNS      string // например net:[4026531840]
	PidNS      string
}

// Sock — строка таблицы /proc/net/tcp|udp.
type Sock struct {
	Proto      string // tcp, tcp6, udp, udp6
	Local      string // IPv4 "a.b.c.d" (для простоты демо только IPv4)
	LocalPort  int
	Remote     string
	RemotePort int
	State      string // hex-код: 0A LISTEN, 01 ESTABLISHED, 07 UDP UNCONN
	Inode      uint64
	UID        int
	NetNS      string
}

// Tree — поддельная система.
type Tree struct {
	BootTime   time.Time
	MemTotalKB uint64
	Procs      []*Proc
	Socks      []Sock
	HostFiles  map[string]string // путь относительно корня хоста → содержимое
	// ProcFiles — путь относительно корня /proc → содержимое (параметры
	// ядра из /proc/sys для аудита).
	ProcFiles map[string]string
	// HostModes — права файлов хоста (по умолчанию 0644): аудит проверяет
	// права /etc/shadow, sudoers, ключей SSH.
	HostModes map[string]os.FileMode
	Kernel    string
	// Addrs — локальные адреса сервера: IPv4 пишутся в /proc/net/fib_trie,
	// IPv6 — в /proc/net/if_inet6 (интерфейс lo для ::1, иначе eth0).
	Addrs []string
}

// Write записывает дерево в dir и возвращает корни /proc и хоста.
func (t *Tree) Write(dir string) (procRoot, hostRoot string, err error) {
	procRoot = filepath.Join(dir, "proc")
	hostRoot = filepath.Join(dir, "host")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		return "", "", err
	}
	w := func(path, content string) {
		if err != nil {
			return
		}
		if e := os.MkdirAll(filepath.Dir(path), 0o755); e != nil {
			err = e
			return
		}
		err = os.WriteFile(path, []byte(content), 0o644)
	}
	w(filepath.Join(procRoot, "stat"), fmt.Sprintf("cpu  1 2 3 4\nbtime %d\n", t.BootTime.Unix()))
	w(filepath.Join(procRoot, "meminfo"), fmt.Sprintf("MemTotal:       %d kB\nMemFree:        1000 kB\n", t.MemTotalKB))
	w(filepath.Join(procRoot, "sys", "kernel", "osrelease"), t.Kernel+"\n")
	for path, content := range t.ProcFiles {
		w(filepath.Join(procRoot, path), content)
	}
	for path, content := range t.HostFiles {
		w(filepath.Join(hostRoot, path), content)
	}
	for path, mode := range t.HostModes {
		if err == nil {
			err = os.Chmod(filepath.Join(hostRoot, path), mode)
		}
	}
	if err != nil {
		return "", "", err
	}
	for _, p := range t.Procs {
		if err := t.writeProc(procRoot, p); err != nil {
			return "", "", err
		}
	}
	// Таблицы сети пространства имён сканера (/proc/net).
	if err := t.writeNet(filepath.Join(procRoot, "net"), ""); err != nil {
		return "", "", err
	}
	if err := t.writeAddrs(filepath.Join(procRoot, "net")); err != nil {
		return "", "", err
	}
	return procRoot, hostRoot, nil
}

// writeAddrs пишет локальные адреса в формате ядра: fib_trie (лист
// «|-- адрес» и строка «/32 host LOCAL») и if_inet6.
func (t *Tree) writeAddrs(dir string) error {
	var trie, inet6 strings.Builder
	trie.WriteString("Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n")
	for _, a := range t.Addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return err
		}
		if ip.Is4() {
			fmt.Fprintf(&trie, "     |-- %s\n        /32 host LOCAL\n", ip)
			continue
		}
		b := ip.As16()
		iface := "eth0"
		if ip.IsLoopback() {
			iface = "lo"
		}
		fmt.Fprintf(&inet6, "%x 02 40 00 80 %8s\n", b[:], iface)
	}
	if err := os.WriteFile(filepath.Join(dir, "fib_trie"), []byte(trie.String()), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "if_inet6"), []byte(inet6.String()), 0o644)
}

// UpdateStat перезаписывает только stat процесса (для «оживления» демо).
func (t *Tree) UpdateStat(procRoot string, p *Proc) error {
	return os.WriteFile(filepath.Join(procRoot, strconv.Itoa(p.PID), "stat"), []byte(statLine(p)), 0o644)
}

// Remove удаляет каталог процесса (процесс «завершился»).
func (t *Tree) Remove(procRoot string, pid int) error {
	for i, p := range t.Procs {
		if p.PID == pid {
			t.Procs = append(t.Procs[:i], t.Procs[i+1:]...)
			break
		}
	}
	return os.RemoveAll(filepath.Join(procRoot, strconv.Itoa(pid)))
}

// Add добавляет процесс в уже записанное дерево.
func (t *Tree) Add(procRoot string, p *Proc) error {
	t.Procs = append(t.Procs, p)
	return t.writeProc(procRoot, p)
}

func statLine(p *Proc) string {
	state := p.State
	if state == "" {
		state = "S"
	}
	var flags uint64 = 0x400000
	if p.Kernel {
		flags |= 0x00200000 // PF_KTHREAD
	}
	threads := p.Threads
	if threads == 0 {
		threads = 1
	}
	// Поля 3..24 из man proc; незначимые заполнены нулями.
	return fmt.Sprintf("%d (%s) %s %d %d %d 0 -1 %d 100 0 0 0 %d %d 0 0 20 0 %d 0 %d %d %d\n",
		p.PID, p.Comm, state, p.PPID, p.PID, p.PID, flags, p.UTime, p.STime, threads, p.StartTicks, p.RSSKB*4096, p.RSSKB/4)
}

func (t *Tree) writeProc(procRoot string, p *Proc) error {
	dir := filepath.Join(procRoot, strconv.Itoa(p.PID))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		return err
	}
	files := map[string]string{
		"stat":    statLine(p),
		"cmdline": cmdline(p.Args),
		"status":  status(p),
		"environ": strings.Join(p.Env, "\x00"),
		"cgroup":  orDefault(p.Cgroup, "0::/system.slice/demo.service\n"),
		"comm":    p.Comm + "\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	link := func(target, name string) error {
		if target == "" {
			return nil
		}
		path := filepath.Join(dir, name)
		_ = os.Remove(path)
		return os.Symlink(target, path)
	}
	if !p.Kernel {
		if err := link(p.Exe, "exe"); err != nil {
			return err
		}
		if err := link(orDefault(p.Cwd, "/"), "cwd"); err != nil {
			return err
		}
	}
	for fd, target := range p.FDs {
		if err := link(target, filepath.Join("fd", strconv.Itoa(fd))); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		return err
	}
	netns := orDefault(p.NetNS, "net:[4026531840]")
	if err := link(netns, "ns/net"); err != nil {
		return err
	}
	if err := link(orDefault(p.PidNS, "pid:[4026531836]"), "ns/pid"); err != nil {
		return err
	}
	if err := link("mnt:[4026531841]", "ns/mnt"); err != nil {
		return err
	}
	return t.writeNet(filepath.Join(dir, "net"), netns)
}

// writeNet пишет таблицы сокетов для заданного пространства имён
// (пустая строка — пространство имён по умолчанию).
func (t *Tree) writeNet(dir, netns string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tables := map[string]*strings.Builder{}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b := &strings.Builder{}
		b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
		tables[proto] = b
	}
	def := "net:[4026531840]"
	for i, s := range t.Socks {
		ns := orDefault(s.NetNS, def)
		if orDefault(netns, def) != ns {
			continue
		}
		fmt.Fprintf(tables[s.Proto], "%4d: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 20 4 30 10 -1\n",
			i, hexAddr(s.Local, s.LocalPort), hexAddr(s.Remote, s.RemotePort), s.State, s.UID, s.Inode)
	}
	for proto, b := range tables {
		if err := os.WriteFile(filepath.Join(dir, proto), []byte(b.String()), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "unix"), []byte("Num       RefCount Protocol Flags    Type St Inode Path\n"), 0o644)
}

// hexAddr кодирует IPv4-адрес так, как это делает ядро: 32-битное слово
// в little-endian и порт в hex.
func hexAddr(ip string, port int) string {
	var b [4]int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", b[3], b[2], b[1], b[0], port)
}

func cmdline(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.Join(args, "\x00") + "\x00"
}

func status(p *Proc) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Name:\t%s\nState:\t%s\nPPid:\t%d\n", p.Comm, orDefault(p.State, "S"), p.PPID)
	fmt.Fprintf(&b, "Uid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n", p.UID, p.UID, p.UID, p.UID, p.UID, p.UID, p.UID, p.UID)
	fmt.Fprintf(&b, "NSpid:\t%d\n", p.PID)
	if !p.Kernel {
		fmt.Fprintf(&b, "VmSize:\t%d kB\nVmRSS:\t%d kB\n", p.RSSKB*4, p.RSSKB)
	}
	fmt.Fprintf(&b, "Threads:\t%d\n", max(p.Threads, 1))
	return b.String()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// NewFS создаёт procfs.FS для записанного поддельного дерева.
func NewFS(procRoot, hostRoot string) *procfs.FS {
	fs := procfs.New(procRoot, hostRoot)
	fs.SkipExeStat = true
	return fs
}

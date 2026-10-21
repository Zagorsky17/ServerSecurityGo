// Пакет procfs читает сведения о процессах из файловой системы /proc.
//
// Корень /proc и корень хоста (для /etc/passwd и т. п.) настраиваются,
// поэтому тот же код работает с настоящим /proc и с поддельным деревом
// из пакета fakeproc (тесты, демо-режим).
//
// Важные свойства:
//   - нехватка прав (EACCES/EPERM) не ошибка: поле остаётся пустым,
//     а в Process.Access записывается, что именно недоступно;
//   - процесс может завершиться посреди чтения — тогда ReadProcess
//     возвращает ErrGone, и сканер его просто пропускает;
//   - отсутствие полей в старых ядрах (NSpid и др.) допустимо.
package procfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// ClockTicks — значение USER_HZ (sysconf(_SC_CLK_TCK)). На Linux для
// x86_64 и arm64 оно равно 100; без cgo получить его иначе нельзя.
const ClockTicks = 100

// pfKthread — флаг PF_KTHREAD в поле flags файла /proc/PID/stat:
// процесс является потоком ядра.
const pfKthread = 0x00200000

// ErrGone — процесс исчез во время чтения.
var ErrGone = errors.New("процесс завершился")

// FS — точка доступа к /proc.
type FS struct {
	Root     string // обычно "/proc"
	HostRoot string // обычно "/"; используется для /etc/passwd
	// MaxCmdline — сколько байт /proc/PID/cmdline читать (лимит по
	// умолчанию для ReadProcess).
	MaxCmdline int
	// MaxFiles — сколько открытых файлов сохранять в Process.Files.
	// Сокеты сопоставляются всегда, независимо от лимита.
	MaxFiles int
	// SkipExeStat отключает stat исполняемого файла. Нужно для поддельных
	// деревьев (тесты, демо): там exe — обычный симлинк, и stat попал бы
	// на настоящий файл хоста с тем же путём.
	SkipExeStat bool
}

// New создаёт FS с разумными значениями по умолчанию.
func New(root, hostRoot string) *FS {
	if root == "" {
		root = "/proc"
	}
	if hostRoot == "" {
		hostRoot = "/"
	}
	return &FS{Root: root, HostRoot: hostRoot, MaxCmdline: DefaultMaxCmdline, MaxFiles: 200}
}

func (f *FS) path(parts ...string) string {
	return filepath.Join(append([]string{f.Root}, parts...)...)
}

// HostPath возвращает путь внутри корня хоста.
func (f *FS) HostPath(p string) string {
	return filepath.Join(f.HostRoot, p)
}

// PIDs возвращает отсортированный список PID из каталога /proc.
func (f *FS) PIDs() ([]int, error) {
	entries, err := os.ReadDir(f.Root)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

// BootTime читает время загрузки системы (строка btime в /proc/stat).
func (f *FS) BootTime() (time.Time, error) {
	data, err := os.ReadFile(f.path("stat"))
	if err != nil {
		return time.Time{}, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(sec, 0), nil
		}
	}
	return time.Time{}, errors.New("в /proc/stat нет btime")
}

// MemTotal возвращает объём ОЗУ в байтах из /proc/meminfo.
func (f *FS) MemTotal() uint64 {
	data, err := os.ReadFile(f.path("meminfo"))
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			return parseKB(v) * 1024 // в meminfo значение в килобайтах
		}
	}
	return 0
}

// KernelRelease возвращает версию ядра из /proc/sys/kernel/osrelease.
func (f *FS) KernelRelease() string {
	data, _ := os.ReadFile(f.path("sys", "kernel", "osrelease"))
	return strings.TrimSpace(string(data))
}

// Users читает /etc/passwd и возвращает отображение UID → имя.
func (f *FS) Users() map[int]string {
	users := map[int]string{}
	data, err := os.ReadFile(f.HostPath("etc/passwd"))
	if err != nil {
		return users
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 || strings.HasPrefix(line, "#") {
			continue
		}
		if uid, err := strconv.Atoi(parts[2]); err == nil {
			if _, dup := users[uid]; !dup {
				users[uid] = parts[0]
			}
		}
	}
	return users
}

// Raw — процесс в «сыром» виде: заполненный model.Process плюс
// служебные данные для сопоставления сокетов.
type Raw struct {
	Proc *model.Process
	// SocketInodes — inode сокетов из /proc/PID/fd, с номерами fd.
	SocketInodes map[uint64][]int
	// RawArgs — аргументы до маскирования секретов. Используются только
	// внутри сканера и никуда не сохраняются (но и не затираются в
	// памяти — см. комментарий в scanner.collect).
	RawArgs []string
}

// Ограничения объёма данных одного процесса. Содержимое /proc/PID/*
// задаёт сам процесс: без лимитов несколько процессов с командной строкой
// в мегабайты (ARG_MAX — четверть лимита стека, пользователь его
// поднимает) или с сотнями длинных путей в fd исчерпывали память службы
// (MemoryMax) и роняли её при каждом сканировании.
const (
	// DefaultMaxCmdline — лимит командной строки (32 КБ хватает даже для
	// длинных classpath Java; обрезка отмечается признаком cmdline_truncated).
	DefaultMaxCmdline = 32 << 10
	// MaxFDTarget — максимальная длина пути открытого файла в Files.
	MaxFDTarget = 1024
)

// Limits — лимиты для одного вызова ReadProcessLimits.
type Limits struct {
	Cmdline int // байт cmdline; 0 — DefaultMaxCmdline
	Files   int // записей в Process.Files
}

// ReadProcess собирает сведения о процессе pid. bootTime нужен для
// вычисления абсолютного времени старта.
func (f *FS) ReadProcess(pid int, bootTime time.Time) (*Raw, error) {
	return f.ReadProcessLimits(pid, bootTime, Limits{Cmdline: f.MaxCmdline, Files: f.MaxFiles})
}

// ReadProcessLimits — ReadProcess с явными лимитами: сканер уменьшает
// их, когда общий бюджет сканирования на исходе.
func (f *FS) ReadProcessLimits(pid int, bootTime time.Time, lim Limits) (*Raw, error) {
	if lim.Cmdline <= 0 {
		lim.Cmdline = DefaultMaxCmdline
	}
	p := &model.Process{PID: pid}
	raw := &Raw{Proc: p, SocketInodes: map[uint64][]int{}}
	pidStr := strconv.Itoa(pid)

	// stat обязателен: без него нет ни PPID, ни времени старта.
	statData, err := os.ReadFile(f.path(pidStr, "stat"))
	if err != nil {
		if isGone(err) {
			return nil, ErrGone
		}
		return nil, fmt.Errorf("stat: %w", err)
	}
	st, err := ParseStat(string(statData))
	if err != nil {
		return nil, err
	}
	p.Name = st.Comm
	p.State = st.State
	p.PPID = st.PPID
	p.CPUTicks = st.UTime + st.STime
	p.Threads = st.Threads
	p.StartTicks = st.StartTicks
	p.VMSBytes = st.VSize
	p.Kernel = st.Flags&pfKthread != 0
	if !bootTime.IsZero() {
		p.StartTime = bootTime.Add(time.Duration(st.StartTicks) * time.Second / ClockTicks)
	}
	p.Key = fmt.Sprintf("%d-%d", pid, st.StartTicks)

	// status: UID/GID, RSS, NSpid. При отсутствии — терпим.
	if data, err := os.ReadFile(f.path(pidStr, "status")); err == nil {
		s := ParseStatus(string(data))
		if s.Name != "" {
			p.Name = s.Name
		}
		p.UID, p.EUID, p.GID = s.UID, s.EUID, s.GID
		p.RSSBytes = s.RSSKB * 1024
		if s.VMSizeKB > 0 {
			p.VMSBytes = s.VMSizeKB * 1024
		}
		p.NSPID = s.NSPID
		if s.Threads > 0 {
			p.Threads = s.Threads
		}
	} else if isGone(err) {
		return nil, ErrGone
	}
	if p.RSSBytes == 0 && st.RSSPages > 0 {
		p.RSSBytes = st.RSSPages * uint64(os.Getpagesize())
	}

	// cmdline: аргументы разделены NUL. У потоков ядра пусто.
	if data, truncated, err := readLimited(f.path(pidStr, "cmdline"), lim.Cmdline); err == nil {
		raw.RawArgs = ParseCmdline(data)
		p.CmdlineTruncated = truncated
		clear(data)
	} else if isPerm(err) {
		p.Access = append(p.Access, "cmdline")
	}

	// exe и cwd — симлинки; для чужих процессов нужен ptrace-доступ.
	if !p.Kernel {
		if target, err := os.Readlink(f.path(pidStr, "exe")); err == nil {
			p.Exe, p.ExeDeleted = splitDeleted(target)
			if !f.SkipExeStat {
				p.ExeInfo = f.statExe(pidStr)
			}
		} else if isPerm(err) {
			p.Access = append(p.Access, "exe")
		}
		if target, err := os.Readlink(f.path(pidStr, "cwd")); err == nil {
			p.Cwd = target
		} else if isPerm(err) {
			p.Access = append(p.Access, "cwd")
		}
		f.readFDs(pidStr, raw, lim.Files)
		p.EnvFlags = f.readEnvFlags(pidStr, p)
	}

	p.Namespaces = f.readNamespaces(pidStr)
	if data, err := os.ReadFile(f.path(pidStr, "cgroup")); err == nil {
		p.ContainerRuntime, p.Container = DetectContainer(string(data))
	}
	return raw, nil
}

// statExe делает stat через симлинк /proc/PID/exe. Это работает даже
// для удалённого файла: ядро держит ссылку на inode.
func (f *FS) statExe(pidStr string) *model.FileInfo {
	fi, err := os.Stat(f.path(pidStr, "exe"))
	if err != nil {
		return nil
	}
	info := &model.FileInfo{
		Mode:          fi.Mode().String(),
		Size:          fi.Size(),
		ModTime:       fi.ModTime(),
		WorldWritable: fi.Mode().Perm()&0o002 != 0,
		SetUID:        fi.Mode()&fs.ModeSetuid != 0,
		SetGID:        fi.Mode()&fs.ModeSetgid != 0,
		UID:           -1,
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		info.UID = int(sys.Uid)
	}
	return info
}

// readFDs перечисляет /proc/PID/fd, сохраняет первые MaxFiles записей и
// все inode сокетов.
func (f *FS) readFDs(pidStr string, raw *Raw, maxFiles int) {
	p := raw.Proc
	dir := f.path(pidStr, "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if isPerm(err) {
			p.Access = append(p.Access, "fd")
		}
		return
	}
	p.FDCount = len(entries)
	fds := make([]int, 0, len(entries))
	for _, e := range entries {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			fds = append(fds, n)
		}
	}
	sort.Ints(fds)
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(dir, strconv.Itoa(fd)))
		if err != nil {
			continue
		}
		kind := FDKind(target)
		if kind == "socket" {
			if inode, ok := parseBracketInode(target); ok {
				raw.SocketInodes[inode] = append(raw.SocketInodes[inode], fd)
			}
		}
		if len(p.Files) < maxFiles {
			if len(target) > MaxFDTarget {
				target = target[:MaxFDTarget] + "…"
			}
			p.Files = append(p.Files, model.OpenFile{FD: fd, Target: target, Kind: kind})
		}
	}
}

// dangerousEnv — переменные окружения, наличие которых проверяется.
// Значения никогда не сохраняются: в окружении бывают пароли и токены.
var dangerousEnv = []string{"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}

// readEnvFlags возвращает имена опасных переменных, заданных у процесса
// (с непустым значением). Окружение читается потоком через небольшой
// буфер: от каждой записи хранится только начало (имя и первый байт
// значения), поэтому память не зависит от размера окружения, а сами
// значения не задерживаются в памяти — буферы затираются.
func (f *FS) readEnvFlags(pidStr string, p *model.Process) []string {
	file, err := os.Open(f.path(pidStr, "environ"))
	if err != nil {
		if isPerm(err) {
			p.Access = append(p.Access, "environ")
		}
		return nil
	}
	defer file.Close()
	buf := make([]byte, 4096)
	head := make([]byte, 0, 32) // длиннее самого длинного «ИМЯ=» + 1 байт
	defer clear(buf)
	defer clear(head[:cap(head)])
	var flags []string
	check := func() {
		for _, name := range dangerousEnv {
			prefix := name + "="
			if len(head) > len(prefix) && string(head[:len(prefix)]) == prefix && !slices.Contains(flags, name) {
				flags = append(flags, name)
			}
		}
		head = head[:0]
	}
	for {
		n, err := file.Read(buf)
		for _, b := range buf[:n] {
			if b == 0 {
				check()
			} else if len(head) < cap(head) {
				head = append(head, b)
			}
		}
		if err != nil {
			// Ядро проверяет права и при чтении, а не только при открытии.
			if isPerm(err) {
				p.Access = append(p.Access, "environ")
			}
			break
		}
	}
	check() // последняя запись без завершающего NUL
	return flags
}

// readLimited читает не больше max байт и сообщает, был ли файл длиннее.
func readLimited(path string, max int) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > max {
		clear(data[max:])
		return data[:max], true, nil
	}
	return data, false, nil
}

var nsNames = []string{"pid", "net", "mnt", "user", "uts", "ipc", "cgroup"}

// readNamespaces читает идентификаторы пространств имён (вида net:[4026531840]).
func (f *FS) readNamespaces(pidStr string) map[string]string {
	ns := map[string]string{}
	for _, n := range nsNames {
		if target, err := os.Readlink(f.path(pidStr, "ns", n)); err == nil {
			ns[n] = target
		}
	}
	if len(ns) == 0 {
		return nil
	}
	return ns
}

// Stat — разобранные поля /proc/PID/stat.
type Stat struct {
	Comm       string
	State      string
	PPID       int
	Flags      uint64
	UTime      uint64
	STime      uint64
	Threads    int
	StartTicks uint64
	VSize      uint64
	RSSPages   uint64
}

// ParseStat разбирает /proc/PID/stat. Имя процесса (comm) заключено в
// скобки и само может содержать пробелы и «)», поэтому ищется последняя
// закрывающая скобка.
func ParseStat(s string) (Stat, error) {
	var st Stat
	open := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < open {
		return st, errors.New("неверный формат stat")
	}
	st.Comm = s[open+1 : closeIdx]
	fields := strings.Fields(s[closeIdx+1:])
	// Индексы ниже — номер поля из man proc минус 3.
	if len(fields) < 22 {
		return st, fmt.Errorf("в stat мало полей: %d", len(fields))
	}
	u := func(i int) uint64 {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		return v
	}
	st.State = fields[0]
	st.PPID = int(u(1))
	st.Flags = u(6)
	st.UTime = u(11)
	st.STime = u(12)
	st.Threads = int(u(17))
	st.StartTicks = u(19)
	st.VSize = u(20)
	st.RSSPages = u(21)
	return st, nil
}

// Status — нужные поля /proc/PID/status.
type Status struct {
	Name      string
	UID, EUID int
	GID       int
	RSSKB     uint64
	VMSizeKB  uint64
	Threads   int
	NSPID     []int
}

// ParseStatus разбирает /proc/PID/status (формат «Ключ:\tзначение»).
func ParseStatus(s string) Status {
	var st Status
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "Name":
			st.Name = val
		case "Uid":
			ids := atoiFields(val)
			if len(ids) >= 2 {
				st.UID, st.EUID = ids[0], ids[1]
			}
		case "Gid":
			if ids := atoiFields(val); len(ids) >= 1 {
				st.GID = ids[0]
			}
		case "VmRSS":
			st.RSSKB = parseKB(val)
		case "VmSize":
			st.VMSizeKB = parseKB(val)
		case "Threads":
			st.Threads, _ = strconv.Atoi(val)
		case "NSpid":
			st.NSPID = atoiFields(val)
		}
	}
	return st
}

// ParseCmdline делит содержимое /proc/PID/cmdline по NUL.
// Некоторые программы перезаписывают argv одной строкой с пробелами —
// это сохраняется как один аргумент.
func ParseCmdline(data []byte) []string {
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return nil
	}
	parts := bytes.Split(data, []byte{0})
	args := make([]string, len(parts))
	for i, p := range parts {
		args[i] = string(p)
	}
	return args
}

// FDKind классифицирует цель симлинка дескриптора.
func FDKind(target string) string {
	switch {
	case strings.HasPrefix(target, "socket:["):
		return "socket"
	case strings.HasPrefix(target, "pipe:["):
		return "pipe"
	case strings.HasPrefix(target, "anon_inode:"):
		return "anon"
	case strings.HasPrefix(target, "/memfd:"):
		return "memfd"
	case strings.HasSuffix(target, " (deleted)"):
		return "deleted"
	case strings.HasPrefix(target, "/dev/"):
		return "device"
	default:
		return "file"
	}
}

// DetectContainer определяет по /proc/PID/cgroup, запущен ли процесс в
// контейнере. Возвращает среду (docker, containerd, kubernetes, podman,
// lxc) и короткий идентификатор контейнера, если он есть.
func DetectContainer(cgroup string) (runtime, id string) {
	for line := range strings.SplitSeq(cgroup, "\n") {
		// Формат строки: иерархия:контроллеры:путь
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		switch {
		case strings.Contains(path, "kubepods"):
			runtime = "kubernetes"
		case strings.Contains(path, "docker"):
			runtime = "docker"
		case strings.Contains(path, "libpod"):
			runtime = "podman"
		case strings.Contains(path, "containerd") || strings.Contains(path, "cri-containerd"):
			runtime = "containerd"
		case strings.Contains(path, "/lxc") || strings.Contains(path, "lxc.payload"):
			runtime = "lxc"
		default:
			continue
		}
		id = findContainerID(path)
		// Сами службы docker.service/containerd.service тоже лежат в cgroup
		// со словом docker/containerd, но контейнерами не являются. Для
		// этих сред контейнер признаётся только при наличии идентификатора.
		if id == "" && runtime != "kubernetes" && runtime != "lxc" {
			continue
		}
		return runtime, id
	}
	return "", ""
}

// findContainerID ищет в пути cgroup 64-символьный hex-идентификатор и
// возвращает первые 12 символов, как принято в docker ps.
func findContainerID(path string) string {
	for seg := range strings.FieldsFuncSeq(path, func(r rune) bool { return r == '/' || r == '-' || r == '.' || r == ':' }) {
		if len(seg) == 64 && isHex(seg) {
			return seg[:12]
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// splitDeleted отделяет суффикс " (deleted)", который ядро добавляет к
// пути удалённого файла.
func splitDeleted(target string) (string, bool) {
	if p, ok := strings.CutSuffix(target, " (deleted)"); ok {
		return p, true
	}
	return target, false
}

// parseBracketInode извлекает число из записи вида socket:[12345].
func parseBracketInode(s string) (uint64, bool) {
	l := strings.IndexByte(s, '[')
	r := strings.IndexByte(s, ']')
	if l < 0 || r <= l {
		return 0, false
	}
	v, err := strconv.ParseUint(s[l+1:r], 10, 64)
	return v, err == nil
}

func parseKB(s string) uint64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "kB"))
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func atoiFields(s string) []int {
	var out []int
	for f := range strings.FieldsSeq(s) {
		if v, err := strconv.Atoi(f); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// isGone — файл исчез (процесс завершился) или процесс стал зомби.
func isGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

// isPerm — отказано в доступе.
func isPerm(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

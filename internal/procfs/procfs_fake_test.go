package procfs_test

// Внешний тестовый пакет: fakeproc сам импортирует procfs, поэтому тест
// на поддельном дереве не может жить во внутреннем пакете procfs.

import (
	"slices"
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

	socks := fs.ReadNetTables(3101, "net:[4026531840]")
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

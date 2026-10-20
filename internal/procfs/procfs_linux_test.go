//go:build linux

package procfs

import (
	"os"
	"testing"
)

// TestRealProc проверяет чтение настоящего /proc (выполняется только на
// Linux, например в CI): сканер видит себя, PID 1 и правильного родителя.
func TestRealProc(t *testing.T) {
	fs := New("/proc", "/")
	boot, err := fs.BootTime()
	if err != nil {
		t.Fatalf("btime: %v", err)
	}
	pids, err := fs.PIDs()
	if err != nil || len(pids) == 0 {
		t.Fatalf("PIDs: %v %v", len(pids), err)
	}
	self, err := fs.ReadProcess(os.Getpid(), boot)
	if err != nil {
		t.Fatalf("собственный процесс: %v", err)
	}
	p := self.Proc
	if p.PPID != os.Getppid() {
		t.Errorf("PPID = %d, ожидался %d", p.PPID, os.Getppid())
	}
	if p.UID != os.Getuid() {
		t.Errorf("UID = %d, ожидался %d", p.UID, os.Getuid())
	}
	if p.Exe == "" || len(self.RawArgs) == 0 || p.RSSBytes == 0 {
		t.Errorf("пустые поля: exe=%q args=%v rss=%d", p.Exe, self.RawArgs, p.RSSBytes)
	}
	if p.Kernel {
		t.Error("тестовый процесс помечен как поток ядра")
	}
	if p.Namespaces["pid"] == "" {
		t.Error("не прочитано пространство имён pid")
	}
	if _, err := fs.ReadProcess(1, boot); err != nil {
		t.Errorf("PID 1: %v", err)
	}
	if fs.MemTotal() == 0 {
		t.Error("MemTotal = 0")
	}
	if len(fs.ReadNetTables(0, "")) == 0 {
		t.Log("таблицы сокетов пусты (возможно, нет сети в песочнице)")
	}
}

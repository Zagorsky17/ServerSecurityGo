//go:build unix

package safefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRootedFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if f, _, err := OpenRooted(root, "pipe"); err == nil {
		f.Close()
		t.Fatal("FIFO accepted")
	}
	if _, err := ReadDir(filepath.Join(dir, "pipe"), 10); err == nil {
		t.Fatal("FIFO accepted as directory")
	}
}

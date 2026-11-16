//go:build unix

package selfcheck

import (
	"errors"
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSpecialFilesNeverBlock(t *testing.T) {
	for _, target := range []string{"allowlist", "unit", "baseline", "binary"} {
		t.Run(target, func(t *testing.T) {
			f := setup(t)
			path := map[string]string{"allowlist": f.opt.Allowlist, "unit": f.unit, "baseline": f.baseline, "binary": f.binary}[target]
			os.Remove(path)
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan *Monitor, 1)
			go func() { done <- New(f.opt) }()
			select {
			case m := <-done:
				wantID(t, m, "self_check_unavailable", true)
			case <-time.After(time.Second):
				t.Fatal("FIFO blocked self-check")
			}
		})
	}
}

func TestDropInLinksAndLimit(t *testing.T) {
	f := setup(t)
	dir := f.unit + ".d"
	os.Mkdir(dir, 0700)
	if err := os.Symlink("/dev/null", filepath.Join(dir, "masked.conf")); err != nil {
		t.Fatal(err)
	}
	hashes, err := unitHashes(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if hashes["/etc/systemd/system/"+unitName+".d/masked.conf"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("mask not represented")
	}
	os.Symlink(f.unit, filepath.Join(dir, "linked.conf"))
	if _, err := unitHashes(f.root); err != nil {
		t.Fatal(err)
	}
	os.Symlink("/dev/zero", filepath.Join(dir, "device.conf"))
	if _, err := unitHashes(f.root); err == nil {
		t.Fatal("device accepted")
	}
}

func TestDropInDirectoryCannotBeFIFO(t *testing.T) {
	f := setup(t)
	if err := syscall.Mkfifo(f.unit+".d", 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := unitHashes(f.root); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO directory accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO directory blocked monitor")
	}
}

func TestUnitReadBudgets(t *testing.T) {
	for _, kind := range []string{"count", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			dir := f.unit + ".d"
			count, body := maxFiles+1, ""
			if kind == "bytes" {
				count = 9
				body = strings.Repeat("x", 1<<20)
			}
			for i := 0; i < count; i++ {
				write(t, filepath.Join(dir, fmt.Sprintf("%04d.conf", i)), body)
			}
			if _, err := unitHashes(f.root); !errors.Is(err, safefile.ErrTooLarge) {
				t.Fatalf("budget not enforced: %v", err)
			}
		})
	}
}

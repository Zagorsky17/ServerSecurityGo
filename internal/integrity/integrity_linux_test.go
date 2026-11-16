//go:build linux

package integrity

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRealDpkgCriticalFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root check runs separately in CI")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := packageLocks(root); err != nil {
		t.Fatal(err)
	}
	db, err := loadDatabase(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	b := readerBudget{start: time.Now(), rate: 16 << 20}
	for _, p := range []string{"usr/bin/ls", "usr/bin/ssh", "usr/bin/sudo", "usr/bin/su", "usr/sbin/sshd"} {
		exp, ok := db.files[p]
		if !ok {
			continue
		}
		got, err := b.hash(context.Background(), root, p)
		if err != nil {
			t.Fatal(err)
		}
		if got.MD5 != exp.MD5 {
			t.Fatalf("%s: %s != %s", p, got.MD5, exp.MD5)
		}
		output, err := exec.Command("sha256sum", "/"+p).Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Fields(string(output))[0] != got.SHA256 {
			t.Fatal("sha256sum disagrees", p)
		}
		count++
	}
	if count < 3 {
		t.Fatalf("too few reference binaries checked: %d", count)
	}
	t.Logf("loaded %d selected dpkg hashes, independently checked %d critical files", len(db.files), count)
}
func TestDpkgLockHelper(t *testing.T) {
	path := os.Getenv("SSG_TEST_LOCK")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lock); err != nil {
		t.Fatal(err)
	}
	os.Stdout.Write([]byte("locked\n"))
	buf := make([]byte, 1)
	os.Stdin.Read(buf)
}
func TestConcurrentDpkgLockIsReadOnly(t *testing.T) {
	h, state := fixture(t)
	write(t, h, "var/lib/dpkg/lock", "unchanged")
	cmd := exec.Command(os.Args[0], "-test.run=^TestDpkgLockHelper$")
	cmd.Env = append(os.Environ(), "SSG_TEST_LOCK="+filepath.Join(h, "var/lib/dpkg/lock"))
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		in.Close()
		if err := cmd.Wait(); err != nil {
			t.Error(err)
		}
	}()
	ready := make([]byte, 7)
	if n, err := io.ReadFull(out, ready); err != nil || n != 7 || string(ready) != "locked\n" {
		t.Fatalf("lock helper: %q %v", ready, err)
	}
	r := runner(h, state)
	if err := r.Check(context.Background()); err == nil {
		t.Fatal("locked database accepted")
	}
	if len(find(r, "bin_modified")) != 0 || len(find(r, "integrity_unavailable")) != 1 {
		t.Fatalf("%+v", r.Findings())
	}
	data, _ := os.ReadFile(filepath.Join(h, "var/lib/dpkg/lock"))
	if string(data) != "unchanged" {
		t.Fatal("lock file was changed")
	}
}

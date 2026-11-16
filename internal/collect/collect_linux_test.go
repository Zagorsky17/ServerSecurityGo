package collect

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectHelperProcess(t *testing.T) {
	if os.Getenv("SSG_COLLECT_HELPER") != "1" {
		return
	}
	fmt.Println("ready")
	time.Sleep(time.Minute)
	os.Exit(0)
}
func TestRealDeletedExecutable(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(self)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(d, "helper")
	if e = os.WriteFile(p, data, 0700); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(p, "-test.run=^TestCollectHelperProcess$")
	cmd.Env = append(os.Environ(), "SSG_COLLECT_HELPER=1", "SSG_TEST_TOKEN=canary-collect-secret")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	ready := make([]byte, 6)
	if _, e = io.ReadFull(stdout, ready); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	fs := procfs.New("/proc", "/")
	raw, e := fs.ReadProcess(cmd.Process.Pid, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if !raw.Proc.ExeDeleted {
		t.Fatal("not deleted")
	}
	root := t.TempDir()
	out := filepath.Join(d, "evidence.tar.gz")
	_, e = Create(context.Background(), Options{HostRoot: root, ProcRoot: "/proc", Output: out, MaxBytes: 100 << 20, MaxBinaryBytes: 50 << 20}, &model.Snapshot{Processes: []*model.Process{raw.Proc}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := os.Open(out)
	defer f.Close()
	z, _ := gzip.NewReader(f)
	defer z.Close()
	tr := tar.NewReader(z)
	found := false
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(tr)
		if strings.HasPrefix(h.Name, "binaries/") {
			if sha256.Sum256(b) != sha256.Sum256(data) {
				t.Fatal("binary bytes differ")
			}
			found = true
		} else if strings.Contains(string(b), "canary-collect-secret") {
			t.Fatalf("environment secret leaked in %s", h.Name)
		}
	}
	if !found {
		t.Fatal("deleted binary not collected")
	}
}

package collect

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArchivePermissionsManifestSecrets(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	os.Chmod(out, 0700)
	for p, s := range map[string]string{"etc/crontab": "TOKEN='canary secret'\nrun --password canary\n", "etc/shadow": "canary", "etc/cron.d/.env": "canary", "root/.ssh/id_ed25519": "canary", "root/.ssh/authorized_keys": "ssh-ed25519 public-key", "var/log/auth.log": "sudo: COMMAND=/bin/app --password 'canary secret'"} {
		f := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(f), 0700)
		os.WriteFile(f, []byte(s), 0600)
	}
	os.Symlink("/etc/passwd", filepath.Join(root, "etc/cron.d/link"))
	p := filepath.Join(out, "evidence.tar.gz")
	res, e := Create(context.Background(), Options{HostRoot: root, ProcRoot: filepath.Join(root, "proc"), Output: p, MaxBytes: 2 << 20, MaxBinaryBytes: 1 << 20, Now: time.Now(), Version: "test"}, &model.Snapshot{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if !res.Incomplete {
		t.Fatal("missing proc not reported")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0600 {
		t.Fatal(fi.Mode())
	}
	raw, _ := os.ReadFile(p)
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != res.SHA256 {
		t.Fatal("archive digest")
	}
	f, _ := os.Open(p)
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	tr := tar.NewReader(z)
	entries := map[string][]byte{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if h.Mode != 0600 || h.Typeflag != tar.TypeReg {
			t.Fatal(h)
		}
		b, _ := io.ReadAll(tr)
		entries[h.Name] = b
		if strings.Contains(string(b), "canary") || strings.Contains(h.Name, "shadow") || strings.Contains(h.Name, ".env") || strings.Contains(h.Name, "id_ed25519") || strings.HasSuffix(h.Name, "/link") {
			t.Fatalf("secret or link: %s %s", h.Name, b)
		}
	}
	manifest := string(entries["MANIFEST.sha256"])
	for n, b := range entries {
		if n == "MANIFEST.sha256" {
			continue
		}
		sum := sha256.Sum256(b)
		if !strings.Contains(manifest, hex.EncodeToString(sum[:])+"  "+n+"\n") {
			t.Fatalf("manifest missing %s", n)
		}
	}
	if _, e = Create(context.Background(), Options{HostRoot: root, Output: p, MaxBytes: 2 << 20, MaxBinaryBytes: 1 << 20}, &model.Snapshot{}, nil); e == nil {
		t.Fatal("archive overwritten")
	}
}
func TestFailedCollectionRemoved(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	p := filepath.Join(d, "x.tar.gz")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := Create(ctx, Options{HostRoot: d, Output: p, MaxBytes: 1 << 20, MaxBinaryBytes: 1 << 20}, &model.Snapshot{}, nil)
	if e == nil {
		t.Fatal("cancel ignored")
	}
	if _, e = os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("partial file retained")
	}
}
func TestRedactText(t *testing.T) {
	for _, s := range []string{`PASSWORD="canary value"`, `--password 'canary value'`, `TOKEN=canary`, `-----BEGIN OPENSSH PRIVATE KEY----- canary`} {
		if strings.Contains(string(cleanText([]byte(s))), "canary") {
			t.Fatal(s)
		}
	}
}
func TestCustomHomePersistence(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	os.Chmod(out, 0700)
	for p, s := range map[string]string{"etc/passwd": "custom:x:1001:1001::/srv/custom:/bin/bash\n", "srv/custom/.bashrc": "echo profile-marker", "srv/custom/.ssh/authorized_keys": "public-key-marker", "srv/custom/.ssh/id_rsa": "PRIVATE-SECRET", "usr/lib/systemd/system/test.service": "ExecStart=/bin/true"} {
		f := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(f), 0700)
		os.WriteFile(f, []byte(s), 0600)
	}
	archive := filepath.Join(out, "a.tar.gz")
	_, e := Create(context.Background(), Options{HostRoot: root, ProcRoot: filepath.Join(root, "proc"), Output: archive, MaxBytes: 2 << 20, MaxBinaryBytes: 1 << 20}, &model.Snapshot{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := os.Open(archive)
	defer f.Close()
	z, _ := gzip.NewReader(f)
	defer z.Close()
	tr := tar.NewReader(z)
	names := map[string]bool{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		names[h.Name] = true
	}
	for _, p := range []string{"srv/custom/.bashrc", "srv/custom/.ssh/authorized_keys", "usr/lib/systemd/system/test.service"} {
		if !names["persistence/"+p] {
			t.Fatal("missing", p)
		}
	}
	if names["persistence/srv/custom/.ssh/id_rsa"] {
		t.Fatal("private key collected")
	}
}

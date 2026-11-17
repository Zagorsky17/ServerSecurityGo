package advanced

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func elfFixture(dynamic bool) []byte {
	b := make([]byte, 8192)
	copy(b, "\x7fELF")
	b[4] = 2
	b[5] = 1
	b[6] = 1
	o := binary.LittleEndian
	o.PutUint16(b[16:], 2)
	o.PutUint16(b[18:], 62)
	o.PutUint32(b[20:], 1)
	o.PutUint64(b[32:], 64)
	o.PutUint16(b[52:], 64)
	o.PutUint16(b[54:], 56)
	o.PutUint16(b[56:], 1)
	o.PutUint32(b[64:], 1)
	o.PutUint32(b[68:], 5)
	o.PutUint64(b[72:], 4096)
	o.PutUint64(b[96:], 4096)
	if dynamic {
		o.PutUint16(b[56:], 2)
		o.PutUint32(b[120:], 3)
	}
	return b
}
func TestELFBoundsPackingAndEntropy(t *testing.T) {
	b := elfFixture(false)
	x, e := InspectELF(b)
	if e != nil || !x.ELF || !x.Static || x.Packing != "" {
		t.Fatal(x, e)
	}
	copy(b[1000:], "UPX!")
	x, e = InspectELF(b)
	if e != nil || x.Packing != "upx-marker" {
		t.Fatal(x, e)
	}
	b = elfFixture(true)
	for i := 4096; i < len(b); i++ {
		b[i] = byte(i)
	}
	x, e = InspectELF(b)
	if e != nil || x.Static || x.Packing != "entropy" || x.Entropy < 7.99 {
		t.Fatal(x, e)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 65535) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[40:], 100); binary.LittleEndian.PutUint16(b[60:], 0) },
		func(b []byte) {
			binary.LittleEndian.PutUint64(b[40:], 256)
			binary.LittleEndian.PutUint16(b[58:], 64)
			binary.LittleEndian.PutUint16(b[60:], 2)
			binary.LittleEndian.PutUint16(b[62:], 1)
			binary.LittleEndian.PutUint64(b[328:], 0x800)
			binary.LittleEndian.PutUint64(b[352:], 1<<40)
		},
		func(b []byte) { binary.LittleEndian.PutUint64(b[32:], ^uint64(0)) },
	} {
		b = elfFixture(false)
		mutate(b)
		if _, e = InspectELF(b); e == nil {
			t.Fatal("malformed ELF accepted")
		}
	}
	if x, e = InspectELF([]byte("script")); e != nil || x.ELF {
		t.Fatal(x, e)
	}
}
func writeFixture(t *testing.T, root, p string, data []byte) {
	t.Helper()
	p = filepath.Join(root, p)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, data, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestWebshellScopeSecretsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	payload := []byte("<?php system($_GET['SECRET_CANARY']);")
	writeFixture(t, root, "etc/nginx/nginx.conf", []byte("server {root /var/www/html;}"))
	writeFixture(t, root, "var/www/html/current.php", payload)
	writeFixture(t, root, "var/www/html/old.php", payload)
	old := time.Now().Add(-30 * 24 * time.Hour)
	os.Chtimes(filepath.Join(root, "var/www/html/old.php"), old, old)
	outside := t.TempDir()
	writeFixture(t, outside, "escaped.php", payload)
	os.Symlink(outside, filepath.Join(root, "var/www/escape"))
	ps := []*model.Process{{Exe: "/usr/sbin/nginx"}}
	got, complete := webshells(context.Background(), root, ps, 7)
	if !complete || len(got) != 1 || got[0].Risk != model.RiskMedium || got[0].Path != "/var/www/html/current.php" {
		t.Fatal(got, complete)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET_CANARY") {
		t.Fatal("content leaked")
	}
	if got, _ := webshells(context.Background(), root, nil, 7); len(got) != 0 {
		t.Fatal("enabled without web process")
	}
	writeFixture(t, root, "etc/nginx/nginx.conf", []byte("root $document_root;"))
	if _, complete = webshells(context.Background(), root, ps, 7); complete {
		t.Fatal("unsupported root hidden")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, complete = webshells(ctx, root, ps, 7); complete {
		t.Fatal("cancelled scan complete")
	}
}
func TestWebRootsAndPatterns(t *testing.T) {
	got := WebRoots("root /srv/a; DocumentRoot \"/srv/b c\"\nroot /;\nroot $x;\nroot /a/../b;")
	if strings.Join(got, ",") != "srv/a,srv/b c" {
		t.Fatal(got)
	}
	for _, s := range []string{"eval(base64_decode('x'))", "assert($_REQUEST['x'])", "Runtime.getRuntime().exec(x)", "Process.Start(x)", "preg_replace('/x/e', x, y)"} {
		if len(WebshellSignals([]byte(s))) == 0 {
			t.Fatal(s)
		}
	}
	if got := WebshellSignals([]byte("<?php echo 'hello';")); len(got) != 0 {
		t.Fatal(got)
	}
}
func TestRunnerGenerationAndCancellation(t *testing.T) {
	root := t.TempDir()
	b := elfFixture(false)
	copy(b[1000:], "UPX!")
	writeFixture(t, root, "opt/app", b)
	fi, _ := os.Stat(filepath.Join(root, "opt/app"))
	p := &model.Process{Key: "12-1", PID: 12, Exe: "/opt/app", ExeInfo: &model.FileInfo{Size: fi.Size(), ModTime: fi.ModTime()}}
	r := New(Options{HostRoot: root, ProcRoot: filepath.Join(root, "proc")})
	if len(r.Findings()) != 1 {
		t.Fatal("missing pending")
	}
	r.Scan(context.Background(), &model.Snapshot{Processes: []*model.Process{p}})
	r.Apply([]*model.Process{p})
	if p.Executable == nil || p.Executable.Packing != "upx-marker" {
		t.Fatal(p.Executable)
	}
	previous := p.Executable
	p.Key = "12-2"
	p.Executable = nil
	r.Apply([]*model.Process{p})
	if p.Executable != nil {
		t.Fatal("PID reused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Scan(ctx, &model.Snapshot{Processes: []*model.Process{p}})
	if len(r.Findings()) == 0 || previous.Packing != "upx-marker" {
		t.Fatal("cancel/result mutation")
	}
}
func FuzzELF(f *testing.F) {
	f.Add(elfFixture(false))
	f.Add([]byte("\x7fELF"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		InspectELF(b)
	})
}

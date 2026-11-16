package integrity

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func write(t *testing.T, root, p, s string) {
	t.Helper()
	p = filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0700); err != nil {
		t.Fatal(err)
	}
}
func md(s string) string { d := md5.Sum([]byte(s)); return hex.EncodeToString(d[:]) }
func fixture(t *testing.T) (string, string) {
	t.Helper()
	h, state := t.TempDir(), t.TempDir()
	write(t, h, "var/lib/dpkg/status", "Package: tools\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n\n")
	write(t, h, "var/lib/dpkg/info/tools.list", "/.\n/usr\n/usr/bin\n/usr/bin/ssh\n/usr/bin/helper\n")
	write(t, h, "var/lib/dpkg/info/tools.md5sums", md("ssh good")+"  usr/bin/ssh\n"+md("helper good")+"  usr/bin/helper\n")
	write(t, h, "usr/bin/ssh", "ssh good")
	write(t, h, "usr/bin/helper", "helper good")
	return h, state
}
func runner(h, state string) *Runner {
	r := New(Options{HostRoot: h, StateDir: state})
	r.rate = 0
	return r
}
func find(r *Runner, id string) []model.SystemFinding {
	var out []model.SystemFinding
	for _, f := range r.Findings() {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}
func TestBaselineAndModifiedFiles(t *testing.T) {
	h, state := fixture(t)
	r := runner(h, state)
	ctx := context.Background()
	if len(find(r, "integrity_pending")) != 1 {
		t.Fatal("missing pending")
	}
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 0 || len(find(r, "integrity_complete")) != 1 {
		t.Fatalf("%+v", r.Findings())
	}
	fi, err := os.Stat(filepath.Join(state, "integrity.json"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("%v %v", fi, err)
	}
	write(t, h, "usr/bin/ssh", "ssh bad")
	write(t, h, "usr/bin/helper", "helper bad")
	r = runner(h, state)
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	f := find(r, "bin_modified")
	if len(f) != 2 {
		t.Fatalf("%+v", r.Findings())
	}
	for _, v := range f {
		expected := model.RiskHigh
		if strings.HasSuffix(v.Path, "/ssh") {
			expected = model.RiskCritical
		}
		if v.Risk != expected {
			t.Fatalf("%+v", v)
		}
	}
	if r.base.Files["usr/bin/ssh"].MD5 != md("ssh good") {
		t.Fatal("mismatch accepted into baseline")
	}
	// Подмена и файла, и MD5 при прежней версии выявляется сохранённым SHA-256.
	write(t, h, "var/lib/dpkg/info/tools.md5sums", md("ssh bad")+"  usr/bin/ssh\n"+md("helper bad")+"  usr/bin/helper\n")
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 2 {
		t.Fatal("database tampering trusted")
	}
	// Штатное обновление версии и согласованные суммы создают новый эталон.
	write(t, h, "var/lib/dpkg/status", "Package: tools\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.0\n\n")
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 0 {
		t.Fatal("upgrade false positive")
	}
}
func TestExclusionsUsrmergeAndUnpackagedAcceptance(t *testing.T) {
	h, state := fixture(t)
	if err := os.Symlink("usr/bin", filepath.Join(h, "bin")); err != nil {
		t.Fatal(err)
	}
	write(t, h, "var/lib/dpkg/info/tools.list", "/bin/ssh\n/usr/bin/helper\n/usr/bin/config\n/usr/bin/diverted\n/usr/bin/alt\n")
	write(t, h, "var/lib/dpkg/info/tools.md5sums", md("ssh good")+"  bin/ssh\n"+md("helper good")+"  usr/bin/helper\n"+md("original")+"  usr/bin/config\n"+md("original")+"  usr/bin/diverted\n")
	write(t, h, "var/lib/dpkg/info/tools.conffiles", "/usr/bin/config\n")
	write(t, h, "var/lib/dpkg/diversions", "/usr/bin/diverted\n/usr/bin/diverted.real\n:\n")
	write(t, h, "usr/bin/config", "local")
	write(t, h, "usr/bin/diverted", "local")
	write(t, h, "usr/bin/diverted.real", "original")
	write(t, h, "usr/bin/manual", "manual good")
	os.Symlink("helper", filepath.Join(h, "usr/bin/alt"))
	os.Symlink("helper", filepath.Join(h, "usr/bin/unowned-link"))
	r := runner(h, state)
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 0 || len(find(r, "bin_unpackaged")) != 1 {
		t.Fatalf("%+v", r.Findings())
	}
	r.opt.Allowed = func(p string) bool { return p == "/usr/bin/manual" }
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !find(r, "bin_unpackaged")[0].Suppressed {
		t.Fatal("acceptance missing")
	}
	r = runner(h, state)
	r.opt.Allowed = func(string) bool { return true }
	write(t, h, "usr/bin/manual", "manual changed")
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 1 || find(r, "bin_modified")[0].Suppressed {
		t.Fatal("accepted file change suppressed")
	}
}
func TestDpkgMutationDiscardsMismatches(t *testing.T) {
	h, state := fixture(t)
	r := runner(h, state)
	ctx := context.Background()
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(state, "integrity.json"))
	write(t, h, "usr/bin/ssh", "during update")
	r.afterHash = func() {
		write(t, h, "var/lib/dpkg/info/tools.md5sums", md("during update")+"  usr/bin/ssh\n"+md("helper good")+"  usr/bin/helper\n")
	}
	if err := r.Check(ctx); err == nil {
		t.Fatal("racing metadata accepted")
	}
	if len(find(r, "bin_modified")) != 0 || len(find(r, "integrity_unavailable")) != 1 {
		t.Fatalf("%+v", r.Findings())
	}
	after, _ := os.ReadFile(filepath.Join(state, "integrity.json"))
	if string(before) != string(after) {
		t.Fatal("baseline changed on failed check")
	}
}
func TestFailuresPreserveBaselineAndEvidence(t *testing.T) {
	for _, kind := range []string{"corrupt", "missing", "directory", "symlink", "updates", "state-write", "cancelled", "status", "md5", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			h, state := fixture(t)
			r := runner(h, state)
			ctx := context.Background()
			if err := r.Check(ctx); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(state, "integrity.json"))
			switch kind {
			case "corrupt":
				write(t, state, "integrity.json", "broken")
				r = runner(h, state)
				before = []byte("broken")
			case "missing":
				os.Remove(filepath.Join(h, "usr/bin/ssh"))
			case "directory":
				os.Remove(filepath.Join(h, "usr/bin/ssh"))
				os.Mkdir(filepath.Join(h, "usr/bin/ssh"), 0700)
			case "symlink":
				os.Remove(filepath.Join(h, "usr/bin/ssh"))
				os.Symlink("helper", filepath.Join(h, "usr/bin/ssh"))
			case "updates":
				write(t, h, "var/lib/dpkg/updates/0000", "pending")
			case "state-write":
				os.Remove(filepath.Join(state, "integrity.json"))
				os.Mkdir(filepath.Join(state, "integrity.json"), 0700)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "status":
				write(t, h, "var/lib/dpkg/status", "Package: tools\nStatus: install ok unpacked\nArchitecture: amd64\nVersion: 1\n")
			case "md5":
				write(t, h, "var/lib/dpkg/info/tools.md5sums", "bad")
			case "oversize":
				f, err := os.OpenFile(filepath.Join(h, "usr/bin/ssh"), os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				f.Truncate((1 << 30) + 1)
				f.Close()
			}
			if err := r.Check(ctx); err == nil {
				t.Fatal("failure not reported")
			}
			if len(find(r, "integrity_unavailable")) != 1 || len(find(r, "integrity_complete")) != 0 {
				t.Fatalf("%+v", r.Findings())
			}
			if kind != "state-write" {
				after, _ := os.ReadFile(filepath.Join(state, "integrity.json"))
				if string(before) != string(after) {
					t.Fatal("failed check changed baseline")
				}
			}
		})
	}
}
func TestReadOnlyAndConcurrency(t *testing.T) {
	h, state := fixture(t)
	r := runner(h, state)
	r.opt.ReadOnly = true
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Check(context.Background()); err != nil {
				t.Error(err)
			}
			r.Findings()
		}()
	}
	wg.Wait()
	if _, err := os.Stat(filepath.Join(state, "integrity.json")); !os.IsNotExist(err) {
		t.Fatal("read-only check wrote baseline")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	r.Run(ctx)
}
func TestParsersAndScope(t *testing.T) {
	for _, p := range []string{"usr/bin/ssh", "bin/ls", "usr/lib/aarch64-linux-gnu/security/pam_test.so", "lib/x86_64-linux-gnu/libc.so.6", "usr/lib/systemd/systemd", "usr/lib/openssh/sftp-server", "lib/aarch64-linux-gnu/libaudit.so.1"} {
		if !selected(p) {
			t.Fatal("excluded", p)
		}
	}
	for _, p := range []string{"etc/passwd", "usr/share/data", "usr/local/bin/tool", "var/lib/libc.so.6"} {
		if selected(p) {
			t.Fatal("included", p)
		}
	}
	for _, p := range []string{"/usr/bin/x", "../x", "usr/../x", "./x", "usr//x", "usr/bin/x\n"} {
		if validPath(p) {
			t.Fatal("unsafe path", p)
		}
	}
	for _, line := range []string{"bad", strings.Repeat("g", 32) + "  usr/bin/x", md("x") + "  ../x"} {
		db := &database{files: map[string]expected{}}
		if db.parseSums(line, "test") == nil {
			t.Fatal("accepted", line)
		}
	}
	for _, s := range []string{"", "Package: x\nStatus: install ok installed\n", "Package: ../x\nStatus: install ok installed\nArchitecture: all\nVersion: 1", "Package: x\nPackage: x\n"} {
		if _, err := installedPackages(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if err := validateBaseline(baseline{Version: 1, Files: map[string]baselineEntry{"../x": {SHA256: strings.Repeat("a", 64)}}}); err == nil {
		t.Fatal("unsafe baseline")
	}
}
func TestHashCancellationAndContent(t *testing.T) {
	h := t.TempDir()
	write(t, h, "file", "known")
	root, err := os.OpenRoot(h)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	b := readerBudget{start: time.Now()}
	sum, err := b.hash(context.Background(), root, "file")
	if err != nil || sum.MD5 != md("known") || len(sum.SHA256) != 64 {
		t.Fatalf("%+v %v", sum, err)
	}
	b.rate = 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := b.hash(ctx, root, "file"); err == nil {
		t.Fatal("rate-limited read ignored cancellation")
	}
}
func FuzzMetadata(f *testing.F) {
	f.Add(md("x") + "  usr/bin/x\n")
	f.Add("../escape")
	f.Fuzz(func(t *testing.T, s string) {
		db := &database{files: map[string]expected{}}
		_ = db.parseSums(s, "test")
		_, _ = installedPackages(s)
		_ = validPath(s)
	})
}

func TestStatusConffilesAndMissingChecksums(t *testing.T) {
	h, state := fixture(t)
	write(t, h, "usr/bin/config file", "locally changed")
	write(t, h, "var/lib/dpkg/status", "Package: tools\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\nConffiles:\n /usr/bin/config file "+md("original")+" obsolete\n\n")
	write(t, h, "var/lib/dpkg/info/tools.list", "/usr/bin/ssh\n/usr/bin/helper\n/usr/bin/config file\n/usr/bin/generated\n")
	write(t, h, "var/lib/dpkg/info/tools.md5sums", md("ssh good")+"  usr/bin/ssh\n"+md("helper good")+"  usr/bin/helper\n"+md("original")+"  usr/bin/config file\n")
	write(t, h, "usr/bin/generated", "generated by maintainer script")
	r := runner(h, state)
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 0 || len(find(r, "bin_unpackaged")) != 0 || len(find(r, "integrity_unverified")) != 1 {
		t.Fatalf("%+v", r.Findings())
	}
}
func TestAcceptedFileDisappearanceIsIncomplete(t *testing.T) {
	h, state := fixture(t)
	write(t, h, "usr/bin/manual", "manual")
	r := runner(h, state)
	r.opt.Allowed = func(string) bool { return true }
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(h, "usr/bin/manual"))
	if err := r.Check(context.Background()); err == nil {
		t.Fatal("missing accepted file ignored")
	}
	if r.base.Files["usr/bin/manual"].SHA256 == "" {
		t.Fatal("lost reference")
	}
}

func TestRemovedOwnershipCannotHideModifiedTrustedFile(t *testing.T) {
	h, state := fixture(t)
	r := runner(h, state)
	ctx := context.Background()
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	write(t, h, "var/lib/dpkg/info/tools.list", "/usr/bin/helper\n")
	write(t, h, "var/lib/dpkg/info/tools.md5sums", md("helper good")+"  usr/bin/helper\n")
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if r.base.Files["usr/bin/ssh"].SHA256 == "" {
		t.Fatal("lost existing trusted hash when ownership disappeared")
	}
	write(t, h, "usr/bin/ssh", "changed after ownership disappeared")
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	f := find(r, "bin_modified")
	if len(f) != 1 || f[0].Risk != model.RiskCritical {
		t.Fatalf("%+v", r.Findings())
	}
}

func TestDpkgConffileMarkersAndFlags(t *testing.T) {
	for _, value := range []string{md("old") + " remove-on-upgrade", md("old") + " obsolete remove-on-upgrade", "newconffile remove-on-upgrade", "nonexistent", "-"} {
		t.Run(value, func(t *testing.T) {
			h, state := fixture(t)
			write(t, h, "var/lib/dpkg/status", "Package: tools\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\nConffiles:\n /usr/bin/ssh "+value+"\n\n")
			write(t, h, "usr/bin/ssh", "local config change")
			r := runner(h, state)
			if err := r.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(find(r, "bin_modified")) != 0 {
				t.Fatal("configuration file was checked as a binary")
			}
		})
	}
}

func TestExplicitRelativeChecksumPaths(t *testing.T) {
	db := &database{files: map[string]expected{}}
	if err := db.parseSums(md("gh")+"  ./usr/bin/gh\n", "gh=1"); err != nil {
		t.Fatal(err)
	}
	if db.files["usr/bin/gh"].MD5 != md("gh") {
		t.Fatal("explicit relative path not normalized")
	}
	for _, p := range []string{"./../etc/passwd", ".//etc/passwd", "./usr/../../etc/passwd", "/usr/bin/gh"} {
		if db.parseSums(md("bad")+"  "+p, "bad") == nil {
			t.Fatal("unsafe path accepted", p)
		}
	}
}

func TestStatusCRLFDoesNotLoseConffiles(t *testing.T) {
	h, state := fixture(t)
	write(t, h, "var/lib/dpkg/status", "Package: tools\r\nStatus: install ok installed\r\nArchitecture: amd64\r\nVersion: 1.0\r\nConffiles:\r\n /usr/bin/ssh "+md("old")+"\r\n\r\n")
	write(t, h, "usr/bin/ssh", "local config change")
	r := runner(h, state)
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 0 {
		t.Fatal("CRLF lost conffile exclusion")
	}
}

func TestPackageDiversionAllowsDifferentChecksumsForOriginalPath(t *testing.T) {
	h, state := fixture(t)
	status, _ := os.ReadFile(filepath.Join(h, "var/lib/dpkg/status"))
	for _, pkg := range []string{"libpq-dev", "postgresql-common"} {
		status = append(status, []byte("Package: "+pkg+"\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n")...)
		write(t, h, "var/lib/dpkg/info/"+pkg+".list", "/usr/bin/pg_config\n")
		write(t, h, "var/lib/dpkg/info/"+pkg+".md5sums", md(pkg)+"  usr/bin/pg_config\n")
	}
	write(t, h, "var/lib/dpkg/status", string(status))
	write(t, h, "var/lib/dpkg/diversions", "/usr/bin/pg_config\n/usr/bin/pg_config.libpq-dev\npostgresql-common\n")
	write(t, h, "usr/bin/pg_config", "postgresql-common")
	write(t, h, "usr/bin/pg_config.libpq-dev", "libpq-dev")
	r := runner(h, state)
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 0 || len(find(r, "bin_unpackaged")) != 0 {
		t.Fatalf("%+v", r.Findings())
	}
}

func TestSystemdEscapedUnitFilename(t *testing.T) {
	h, state := fixture(t)
	p := `usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice`
	write(t, h, "var/lib/dpkg/info/tools.list", "/usr/bin/ssh\n/usr/bin/helper\n/"+p+"\n")
	write(t, h, "var/lib/dpkg/info/tools.md5sums", md("ssh good")+"  usr/bin/ssh\n"+md("helper good")+"  usr/bin/helper\n\\"+md("unit")+"  "+strings.ReplaceAll(p, `\`, `\\`)+"\n")
	write(t, h, p, "unit")
	r := runner(h, state)
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(find(r, "bin_modified")) != 0 || r.base.Files[p].SHA256 == "" {
		t.Fatal("escaped systemd unit not verified")
	}
}

func TestChecksumEscapingAndBinaryMode(t *testing.T) {
	db := &database{files: map[string]expected{}}
	if err := db.parseSums(md("x")+" *usr/bin/x", "test"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{`usr/bin/bad\`, `usr/bin/bad\q`, `usr/bin/bad\n`, `usr/bin/bad\r`} {
		if err := db.parseSums("\\"+md("x")+"  "+p, "test"); err == nil {
			t.Fatal("malformed/unsupported path accepted", p)
		}
	}
}

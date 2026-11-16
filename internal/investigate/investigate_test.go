package investigate

import (
	"context"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuoteAndCommands(t *testing.T) {
	p := "/tmp/'; touch /tmp/owned; '"
	q := Quote(p)
	if q != "'/tmp/'\\''; touch /tmp/owned; '\\'''" {
		t.Fatal(q)
	}
	for _, c := range Commands("x", 0, p) {
		if !strings.Contains(c, q) {
			t.Fatal(c)
		}
	}
	for _, c := range Commands("exe_deleted", 42, "") {
		if strings.Contains(c, "cp ") || strings.Contains(c, "rm ") {
			t.Fatal("mutating verification")
		}
	}
}
func TestRecentBoundedNoLinks(t *testing.T) {
	r := t.TempDir()
	os.MkdirAll(filepath.Join(r, "etc"), 0700)
	os.WriteFile(filepath.Join(r, "etc/visible"), []byte("hello"), 0600)
	os.Symlink("/", filepath.Join(r, "etc/outside"))
	now := time.Now()
	rep := Recent(context.Background(), r, now.Add(-time.Hour), now)
	if len(rep.Files) != 1 || rep.Files[0].Path != "/etc/visible" || rep.Files[0].ChangeTime.IsZero() {
		t.Fatal(rep)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !Recent(ctx, r, now.Add(-time.Hour), now).Incomplete {
		t.Fatal("cancelled traversal complete")
	}
	root, _ := os.OpenRoot(r)
	defer root.Close()
	if Walk(context.Background(), root, []string{"etc"}, 1, func(string, os.FileInfo) {}) {
		t.Fatal("path budget")
	}
}
func TestTimelineOrderAndSources(t *testing.T) {
	now := time.Now()
	snap := &model.Snapshot{Auth: &model.AuthReport{Events: []model.LoginEvent{{Time: now.Add(-time.Minute), Kind: "login", User: "root", IP: "192.0.2.1", Source: "auth", Risk: model.RiskHigh}}}}
	events := []model.Event{{Time: now, Type: model.EvStarted, Details: i18n.L("process"), Risk: model.RiskCritical}}
	files := &model.RecentReport{Files: []model.RecentFile{{Path: "/etc/crontab", ChangeTime: now.Add(-2 * time.Minute), ModTime: now.Add(-time.Hour)}}}
	out := Timeline(snap, events, files, now.Add(-time.Hour))
	if len(out) != 3 || out[0].Kind != model.EvStarted || out[1].Kind != "login" || out[2].Kind != "file" {
		t.Fatal(out)
	}
}
func TestReadHistoryReadOnly(t *testing.T) {
	r := t.TempDir()
	p := filepath.Join(r, "events.jsonl")
	os.WriteFile(p, []byte("broken\n"), 0600)
	_, ok := ReadEvents(r, time.Time{})
	if ok {
		t.Fatal("corrupt history accepted")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "broken\n" {
		t.Fatal("history modified")
	}
}
func TestPackageWindowsAndOfflineTimezone(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "var/log/apt"), 0700)
	os.MkdirAll(filepath.Join(root, "etc"), 0700)
	now := time.Now().UTC()
	os.WriteFile(filepath.Join(root, "etc/timezone"), []byte("UTC\n"), 0600)
	os.WriteFile(filepath.Join(root, "etc/changed"), []byte("x"), 0600)
	log := "Start-Date: " + now.Add(-time.Minute).Format("2006-01-02  15:04:05") + "\nEnd-Date: " + now.Add(time.Minute).Format("2006-01-02  15:04:05") + "\n"
	os.WriteFile(filepath.Join(root, "var/log/apt/history.log"), []byte(log), 0600)
	rep := Recent(context.Background(), root, now.Add(-time.Hour), now)
	found := false
	for _, f := range rep.Files {
		if f.Path == "/etc/changed" {
			found = f.PackageWindow
		}
	}
	if !found {
		t.Fatal("update window not matched")
	}
	os.Remove(filepath.Join(root, "etc/timezone"))
	rep = Recent(context.Background(), root, now.Add(-time.Hour), now)
	for _, f := range rep.Files {
		if f.PackageWindow {
			t.Fatal("unknown image timezone guessed")
		}
	}
}
func TestVerificationCommandsMatchEvidence(t *testing.T) {
	cases := []struct{ id, path, want string }{{"bin_modified", "/usr/bin/example", "sha256sum -- '/usr/bin/example'"}, {"hidden_process", "/proc/42", "ps -p 42"}, {"login_password_root", "/var/log/auth.log", "grep -nE"}, {"login_after_bruteforce", "/var/log/auth.log.2.gz", "gzip -cd -- '/var/log/auth.log.2.gz'"}, {"log_utmp_missing", "/run/utmp", "who -a"}, {"log_journal_vacuum", "/var/log/journal", "journalctl --disk-usage"}}
	for _, c := range cases {
		cmd := strings.Join(Commands(c.id, 0, c.path), "\n")
		if !strings.Contains(cmd, c.want) {
			t.Fatal(c.id, cmd)
		}
		if strings.Contains(cmd, "rm ") || strings.Contains(cmd, "cp ") || strings.Contains(cmd, "apt-get") {
			t.Fatal("mutating verification", cmd)
		}
	}
}

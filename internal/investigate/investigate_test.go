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

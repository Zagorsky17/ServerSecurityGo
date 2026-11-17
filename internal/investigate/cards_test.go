package investigate

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
	"testing"
	"time"
)

func TestCardsMappingAndHistoryIsolation(t *testing.T) {
	p := &model.Process{PID: 42, Key: "42-100", Exe: "/bin/sh", Findings: []model.Finding{{ID: "exe_deleted", Category: model.CatIntegrity}}}
	snap := &model.Snapshot{Processes: []*model.Process{p}, System: []model.SystemFinding{{Path: "/etc/cron.d/task", Finding: model.Finding{ID: "autostart_suspicious", Category: model.CatPersistence}}, {Path: "/etc/systemd/system/task.service", Finding: model.Finding{ID: "autostart_temp", Category: model.CatPersistence}}}}
	var events []model.Event
	for i := 0; i < 15; i++ {
		events = append(events, model.Event{Time: time.Unix(int64(i), 0), Key: "42-100", Exe: "/bin/sh", Details: i18n.L("right")})
	}
	events = append(events, model.Event{Key: "42-101", PID: 42, Exe: "/bin/sh", Details: i18n.L("wrong generation")}, model.Event{Exe: "/etc/cron.d/task", Details: i18n.L("path event")})
	Attach(snap, events...)
	f := p.Findings[0]
	if len(f.RelatedEvents) != 8 || f.RelatedEvents[0].Time.Unix() != 14 || len(f.Attack) != 1 || f.Attack[0] != "T1070.004" || f.Why.IsZero() || f.Legitimate.IsZero() {
		t.Fatalf("%+v", f)
	}
	if snap.System[0].Attack[0] != "T1053.003" || snap.System[1].Attack[0] != "T1543.002" || len(snap.System[0].RelatedEvents) != 1 {
		t.Fatal(snap.System)
	}
	if len(contextFor("autostart_recent", model.CatPersistence, "/etc/profile").Attack) != 0 {
		t.Fatal("incorrect cron mapping")
	}
	for _, id := range []string{"exe_in_temp", "exe_hidden_path", "exe_memfd", "kthread_masquerade", "web_spawns_shell", "stdio_socket", "pool_port", "download_exec", "ld_preload", "ssh_key_command", "exe_setuid_nonstd", "unicode_control"} {
		c := contextFor(id, "", "")
		if len(c.Attack) == 0 || !validTechnique(c.Attack[0]) {
			t.Fatal(id)
		}
	}
	before, _ := json.Marshal(f)
	Attach(snap)
	after, _ := json.Marshal(f)
	if string(before) != string(after) {
		t.Fatal("mutated published context")
	}
}
func TestAuditCardsAndQuotedCommands(t *testing.T) {
	checks := []model.AuditCheck{{ID: "ssh_test", References: []string{"T1098.004", "https://example.com", "T1234/<script>"}}}
	AttachAudit(checks, []model.Event{{Type: model.EvAudit, Name: "ssh_test"}, {Type: model.EvAudit, Name: "other"}})
	c := checks[0]
	if len(c.Attack) != 1 || len(c.RelatedEvents) != 1 || len(c.VerifyCommands) != 1 || c.Why.IsZero() {
		t.Fatal(c)
	}
	for _, bad := range []string{"", "T", "T123", "T12345", "T1234.1234", "javascript:alert(1)"} {
		if validTechnique(bad) {
			t.Fatal(bad)
		}
	}
	cmd := Commands("unknown", 0, "/tmp/a'; touch /tmp/should-not-exist; '")[0]
	if !strings.Contains(cmd, `'\''`) {
		t.Fatal(cmd)
	}
}

package authlog

import (
	"encoding/base64"
	"encoding/binary"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHAndRedaction(t *testing.T) {
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	for _, line := range []string{"Dec 31 23:59:59 host sshd[12]: Accepted password for root from 192.0.2.1 port 22 ssh2", "2025-12-31T23:59:59Z host sshd-session[12]: Accepted password for root from 192.0.2.1 port 22 ssh2"} {
		e, ok := ParseLine(line, "auth", now, time.UTC)
		if !ok || e.User != "root" || e.IP != "192.0.2.1" || e.Time.Year() != 2025 {
			t.Fatalf("%+v %v", e, ok)
		}
	}
	e, ok := ParseLine("2026-01-01T00:00:00Z host sudo: user : TTY=pts/0 ; COMMAND=/bin/app --password 'canary secret' TOKEN=canary", "auth", now, time.UTC)
	if !ok || strings.Contains(e.Detail, "canary") {
		t.Fatalf("secret leak: %+v", e)
	}
	if _, ok := ParseLine("2026-01-01T00:00:00Z host sshd[1]: Accepted password for root from bad port 22 ssh2", "", now, time.UTC); ok {
		t.Fatal("invalid IP accepted")
	}
}
func TestAuthorizedKeyOptions(t *testing.T) {
	typ := "ssh-ed25519"
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(typ)))
	b = append(b, typ...)
	b = append(b, make([]byte, 36)...)
	line := `command="echo words",no-pty ` + typ + " " + base64.StdEncoding.EncodeToString(b) + " deploy@laptop"
	keys := Keys([]byte(line), "root", "keys")
	if len(keys) != 1 || keys[0].Comment != "deploy@laptop" || !strings.HasPrefix(keys[0].Fingerprint, "SHA256:") {
		t.Fatal(keys)
	}
	if len(Keys([]byte("ssh-rsa "+base64.StdEncoding.EncodeToString(b)), "", "")) != 0 {
		t.Fatal("type mismatch")
	}
}
func utRecord(arm bool, typ uint16, sec int64) []byte {
	size, off := 384, 340
	if arm {
		size, off = 400, 344
	}
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b, typ)
	binary.LittleEndian.PutUint32(b[4:], 42)
	copy(b[8:], "pts/0")
	copy(b[44:], "root")
	copy(b[76:], "192.0.2.1")
	if arm {
		binary.LittleEndian.PutUint64(b[off:], uint64(sec))
	} else {
		binary.LittleEndian.PutUint32(b[off:], uint32(sec))
	}
	return b
}
func TestUtmpArchitectures(t *testing.T) {
	for _, arm := range []bool{false, true} {
		b := utRecord(arm, 7, 1780000000)
		e, bad := Utmp(b, "wtmp", arm)
		if bad || len(e) != 1 || e[0].PID != 42 || e[0].Time.Unix() != 1780000000 {
			t.Fatalf("arm=%v %+v %v", arm, e, bad)
		}
		_, bad = Utmp(b[:len(b)-1], "wtmp", arm)
		if !bad {
			t.Fatal("partial record")
		}
		_, bad = Utmp(utRecord(arm, 7, 0), "wtmp", arm)
		if !bad {
			t.Fatal("zero time")
		}
	}
}
func put(t *testing.T, root, p string, b []byte) {
	t.Helper()
	f := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(f), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, b, 0600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(f, time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC), time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
}
func fixture(t *testing.T) string {
	r := t.TempDir()
	elf := make([]byte, 20)
	copy(elf, "\x7fELF")
	elf[4] = 2
	elf[5] = 1
	binary.LittleEndian.PutUint16(elf[18:], 62)
	put(t, r, "usr/bin/bash", elf)
	put(t, r, "etc/passwd", []byte("root:x:0:0::/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n"))
	for _, p := range []string{"var/log/wtmp", "var/log/btmp", "var/log/lastlog", "run/utmp"} {
		put(t, r, p, nil)
	}
	return r
}
func TestCollectorAnomaliesRotationState(t *testing.T) {
	r := fixture(t)
	stateDir := t.TempDir()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("2026-11-16T11:55:00Z host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2\n")
	}
	b.WriteString("2026-11-16T11:59:00Z host sshd[1]: Accepted password for root from 192.0.2.1 port 22 ssh2\n")
	put(t, r, "var/log/auth.log", []byte(b.String()))
	c := New(Options{Root: r, StateDir: stateDir})
	rep := c.Build(now, nil)
	found := false
	for _, f := range rep.Findings {
		if f.ID == "login_after_bruteforce" {
			found = true
		}
		if f.ID == "login_new_ip" {
			t.Fatal("backfill is not a new IP")
		}
	}
	if !found || rep.FailedIPs[0].Count != 10 {
		t.Fatal(rep)
	}
	// Preserve old inode in .1: normal rename rotation must not be called truncation.
	if e := os.Rename(filepath.Join(r, "var/log/auth.log"), filepath.Join(r, "var/log/auth.log.1")); e != nil {
		t.Fatal(e)
	}
	put(t, r, "var/log/auth.log", []byte("2026-11-16T12:01:00Z host sshd[2]: Accepted publickey for root from 192.0.2.2 port 22 ssh2\n"))
	rep = c.Build(now.Add(2*time.Minute), nil)
	found = false
	for _, f := range rep.Findings {
		if f.ID == "log_authlog_truncated" {
			t.Fatal("rotation false positive")
		}
		if f.ID == "login_new_ip" {
			found = true
		}
	}
	if !found {
		t.Fatal("new IP missing")
	}
	c = New(Options{Root: r, StateDir: stateDir})
	rep = c.Build(now.Add(3*time.Minute), nil)
	found = false
	for _, f := range rep.Findings {
		found = found || f.ID == "login_new_ip"
	}
	if !found {
		t.Fatal("new IP lost after restart")
	}
	put(t, r, "var/log/auth.log", nil)
	rep = c.Build(now.Add(5*time.Minute), nil)
	found = false
	for _, f := range rep.Findings {
		found = found || f.ID == "log_authlog_truncated"
	}
	if !found {
		t.Fatal("same inode truncation missing")
	}
}
func TestMissingAndUntrustedSources(t *testing.T) {
	r := fixture(t)
	if err := os.Symlink("/dev/zero", filepath.Join(r, "var/log/auth.log")); err != nil {
		t.Fatal(err)
	}
	rep := New(Options{Root: r}).Build(time.Now(), []*model.Process{})
	if !rep.Incomplete || len(rep.Warnings) == 0 {
		t.Fatal(rep)
	}
}
func FuzzAuthLine(f *testing.F) {
	f.Add("Nov 16 12:00:00 host sshd[1]: Accepted password for root from 192.0.2.1 port 22 ssh2")
	f.Fuzz(func(t *testing.T, s string) {
		ParseLine(s, "test", time.Date(2026, 11, 16, 13, 0, 0, 0, time.UTC), time.UTC)
		Keys([]byte(s), "root", "keys")
	})
}
func FuzzUtmp(f *testing.F) {
	f.Add(utRecord(false, 7, 1780000000))
	f.Fuzz(func(t *testing.T, b []byte) { Utmp(b, "wtmp", false); Utmp(b, "btmp", true) })
}
func TestLargeLogKeepsRecentTail(t *testing.T) {
	root := fixture(t)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	b := strings.Repeat("ignored line\n", 800000) + "2026-11-16T11:59:00Z host sshd[1]: Accepted password for root from 192.0.2.1 port 22 ssh2\n"
	put(t, root, "var/log/auth.log", []byte(b))
	rep := New(Options{Root: root}).Build(now, nil)
	if !rep.Incomplete || len(rep.Events) != 1 || rep.Events[0].User != "root" {
		t.Fatal(rep.Incomplete, len(rep.Events))
	}
}
func TestJournalShrinkAndHistoryNull(t *testing.T) {
	root := fixture(t)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	put(t, root, "var/log/auth.log", nil)
	put(t, root, "var/log/journal/machine/system.journal", make([]byte, 2<<20))
	os.MkdirAll(filepath.Join(root, "root"), 0700)
	os.Symlink("/dev/null", filepath.Join(root, "root/.bash_history"))
	c := New(Options{Root: root})
	rep := c.Build(now, nil)
	null := false
	for _, f := range rep.Findings {
		null = null || f.ID == "log_history_null"
		if f.ID == "log_journal_vacuum" {
			t.Fatal("initial journal flagged")
		}
	}
	if !null {
		t.Fatal("history null missing")
	}
	put(t, root, "var/log/journal/machine/system.journal", []byte("small"))
	rep = c.Build(now.Add(time.Minute), nil)
	found := false
	for _, f := range rep.Findings {
		found = found || f.ID == "log_journal_vacuum"
	}
	if !found {
		t.Fatal("journal shrink missing")
	}
}
func TestCopyTruncateRotation(t *testing.T) {
	root := fixture(t)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	line := []byte("2026-11-16T11:59:00Z host sshd[1]: Accepted password for root from 192.0.2.1 port 22 ssh2\n")
	put(t, root, "var/log/auth.log", line)
	c := New(Options{Root: root})
	c.Build(now, nil)
	put(t, root, "var/log/auth.log.1", line)
	put(t, root, "var/log/auth.log", nil)
	rep := c.Build(now.Add(time.Minute), nil)
	for _, f := range rep.Findings {
		if f.ID == "log_authlog_truncated" {
			t.Fatal("copytruncate treated as erasure")
		}
	}
	// An unrelated old rotation is not evidence for a copy of the current contents.
	put(t, root, "var/log/auth.log", []byte("different content\n"))
	c.Build(now.Add(2*time.Minute), nil)
	put(t, root, "var/log/auth.log", nil)
	rep = c.Build(now.Add(3*time.Minute), nil)
	found := false
	for _, f := range rep.Findings {
		found = found || f.ID == "log_authlog_truncated"
	}
	if !found {
		t.Fatal("unrelated rotation hid truncation")
	}
}
func TestSparseLastlogBothArchitectures(t *testing.T) {
	for _, arm := range []bool{false, true} {
		t.Run(map[bool]string{false: "amd64", true: "arm64"}[arm], func(t *testing.T) {
			root := fixture(t)
			now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
			put(t, root, "var/log/auth.log", nil)
			put(t, root, "etc/passwd", []byte("user:x:65534:65534::/home/user:/bin/bash\n"))
			size, ts := 292, 4
			if arm {
				size, ts = 296, 8
				elf := make([]byte, 20)
				copy(elf, "\x7fELF")
				elf[4] = 2
				elf[5] = 1
				binary.LittleEndian.PutUint16(elf[18:], 183)
				put(t, root, "usr/bin/bash", elf)
			}
			b := make([]byte, size)
			if arm {
				binary.LittleEndian.PutUint64(b, uint64(now.Add(-time.Hour).Unix()))
			} else {
				binary.LittleEndian.PutUint32(b, uint32(now.Add(-time.Hour).Unix()))
			}
			copy(b[ts:], "pts/1")
			copy(b[ts+32:], "192.0.2.4")
			f, e := os.OpenFile(filepath.Join(root, "var/log/lastlog"), os.O_WRONLY, 0600)
			if e != nil {
				t.Fatal(e)
			}
			_, e = f.WriteAt(b, int64(65534*size))
			f.Close()
			if e != nil {
				t.Fatal(e)
			}
			rep := New(Options{Root: root}).Build(now, nil)
			if len(rep.Events) != 1 || rep.Events[0].Kind != "lastlogin" || rep.Events[0].User != "user" || rep.Events[0].IP != "192.0.2.4" {
				t.Fatal(rep.Events)
			}
		})
	}
}
func TestSessionPairAndKeyMatch(t *testing.T) {
	root := fixture(t)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	typ := "ssh-ed25519"
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(typ)))
	b = append(b, []byte(typ)...)
	b = append(b, 0, 0, 0, 32)
	b = append(b, make([]byte, 32)...)
	key := typ + " " + base64.StdEncoding.EncodeToString(b) + " laptop"
	put(t, root, "root/.ssh/authorized_keys", []byte(key))
	fp := Keys([]byte(key), "root", "")[0].Fingerprint
	put(t, root, "var/log/auth.log", []byte("2026-11-16T11:00:00Z host sshd[42]: Accepted publickey for root from 192.0.2.1 port 22 ssh2: ED25519 "+fp+"\n"))
	start := utRecord(false, 7, now.Add(-time.Hour).Unix())
	end := utRecord(false, 8, now.Add(-30*time.Minute).Unix())
	put(t, root, "var/log/wtmp", append(start, end...))
	rep := New(Options{Root: root}).Build(now, nil)
	if len(rep.Keys) != 1 || !rep.Keys[0].Used {
		t.Fatal(rep.Keys)
	}
	found := false
	for _, e := range rep.Events {
		if e.Kind == "login" {
			found = true
			if e.End == nil || e.End.Sub(e.Time) != 30*time.Minute || e.KeyComment != "laptop" || e.TTY != "pts/0" {
				t.Fatal(e)
			}
		}
	}
	if !found {
		t.Fatal("login missing")
	}
}
func TestServiceLoginUnusualHourAndCorruptState(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	c := New(Options{})
	r := &model.AuthReport{Time: now, Since: now.Add(-48 * time.Hour)}
	for i := 0; i < 20; i++ {
		r.Events = append(r.Events, model.LoginEvent{Time: now.Add(-time.Hour), Kind: "login", User: "svc", IP: "192.0.2.1"})
	}
	r.Events = append(r.Events, model.LoginEvent{Time: now, Kind: "login", User: "svc", IP: "192.0.2.1"})
	c.assess(r, map[string][]string{"svc": {"svc", "x", "10", "10", "", "/svc", "/sbin/nologin"}})
	ids := strings.Join(r.Events[len(r.Events)-1].Findings, ",")
	if !strings.Contains(ids, "login_unusual_time") || !strings.Contains(ids, "login_service_account") {
		t.Fatal(ids)
	}
	root := fixture(t)
	state := t.TempDir()
	put(t, root, "var/log/auth.log", nil)
	os.WriteFile(filepath.Join(state, "auth-state.json"), []byte("broken"), 0600)
	rep := New(Options{Root: root, StateDir: state, ReadOnly: true}).Build(now, nil)
	if !rep.Incomplete {
		t.Fatal("bad baseline hidden")
	}
}
func TestSudoSessionIsNotCommandOrUsername(t *testing.T) {
	now := time.Now()
	prefix := now.UTC().Format(time.RFC3339) + " host sudo: "
	if _, ok := ParseLine(prefix+"pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)", "auth", now, time.UTC); ok {
		t.Fatal("PAM session invented sudo command")
	}
	e, ok := ParseLine(prefix+"pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 user=root", "auth", now, time.UTC)
	if !ok || e.Kind != "sudo_failed" || strings.Contains(e.User, "pam_unix") {
		t.Fatal(e)
	}
	e, ok = ParseLine(now.UTC().Format(time.RFC3339)+" host passwd[1]: password changed for alice", "auth", now, time.UTC)
	if !ok || e.User != "alice" {
		t.Fatal(e)
	}
}

package fail2ban

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Фаззинг разборщиков журнала и конфигурации fail2ban. go test выполняет
// только начальный корпус; долгий прогон: go test -fuzz=FuzzX ./internal/fail2ban.

// FuzzLogLine — произвольные строки журнала: разбор не паникует, а в
// счётчики и события попадают только корректные IP и короткие имена jail.
func FuzzLogLine(f *testing.F) {
	for _, s := range []string{
		"2026-10-25 10:00:00,123 fail2ban.filter  [812]: INFO    [sshd] Found 203.0.113.5 - 2026-10-25 10:00:00",
		"2026-10-25 10:00:00,123 fail2ban.actions [812]: NOTICE  [sshd] Ban 2001:db8::1",
		"2026-10-25 10:00:00,123 fail2ban.observer [812]: NOTICE [sshd] Increase Ban 203.0.113.5 (2 # 2:00:00 -> 2026-10-25 12:00:00)",
		"2026-10-25 10:00:00,123 fail2ban.actions: WARNING [ssh] Ban ::ffff:192.0.2.1",
		"2026-10-25 10:00:00,123 fail2ban.server  [812]: INFO    Starting Fail2ban v1.0.2",
		"2026-10-25 10:00:00,123 fail2ban.jail    [812]: INFO    Jail 'sshd' stopped",
		"2026-10-25 10:00:00,123 fail2ban.x [1]: INFO [] Ban 1.1.1.1",
		"2026-10-25 10:00:00,123 fail2ban: INFO [a] Increase Ban 1.1.1.1 -> ",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		fd := newFileData()
		fd.consume(strings.NewReader(line+"\n"+line), 1<<20, true, time.UTC)
		check := func(ip, jail string) {
			if _, err := netip.ParseAddr(ip); err != nil && ip != "" {
				t.Fatalf("некорректный IP %q из строки %q", ip, line)
			}
			if len(jail) > 64 || strings.ContainsAny(jail, "]\n") {
				t.Fatalf("некорректный jail %q из строки %q", jail, line)
			}
		}
		for k := range fd.byIP {
			check(k.ip, k.jail)
		}
		for _, e := range fd.events {
			check(e.ip, e.jail)
		}
		for ip := range fd.ignored {
			check(ip, "")
		}
		if c := unbanCommand(func() (string, string) {
			for _, e := range fd.events {
				return e.jail, e.ip
			}
			return "", ""
		}()); c != "" && strings.ContainsAny(c, ";|&$`'\"\n<>()") {
			t.Fatalf("опасные символы в команде: %q", c)
		}
	})
}

// FuzzJailConfig — произвольная конфигурация jail: разбор, интерполяция и
// чтение параметров не паникуют и не зацикливаются.
func FuzzJailConfig(f *testing.F) {
	f.Add("[DEFAULT]\nbantime = 10m\nenabled = false\n[sshd]\nenabled = true\nfilter = %(__name__)s[mode=%(mode)s]\n")
	f.Add("[a]\nx = %(y)s\ny = %(x)s\nenabled = %(x)s\n")
	f.Add("[a\n]\n=\n:\n  cont\n[b]\nignoreip = 1.2.3.4,\n\t::1 ; c\nbantime = 1h 2zz\n")
	f.Add("[DEFAULT]\nv = %(v)s%(v)s%(v)s%(v)s\n[j]\nenabled = 1\nbantime = %(v)s\n")
	f.Fuzz(func(t *testing.T, data string) {
		c := newINI()
		c.parse(data, "/etc/fail2ban/jail.local")
		for _, sec := range c.order {
			for k := range c.vals[sec] {
				if v, ok := c.get(sec, k); ok && len(v) > 1<<22 {
					t.Fatalf("интерполяция раздула значение до %d байт", len(v))
				}
			}
		}
	})
}

func FuzzParseDuration(f *testing.F) {
	for _, s := range []string{"10m", "1h 30m", "-1", "1.5d", "99999999999999999999y", "1e308", "NaN", "Inf"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if n, ok := parseDuration(s); ok && n < -1 {
			t.Fatalf("parseDuration(%q) = %d", s, n)
		}
	})
}

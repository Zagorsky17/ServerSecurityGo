package fakeproc

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Демо fail2ban: установлен и запущен, jail sshd и recidive, журнал за
// 14 дней с фоновым перебором, двумя всплесками и рецидивистом. Адреса —
// из диапазонов для документации (RFC 5737, RFC 3849).

const demoF2BLog = "var/log/fail2ban.log"

// demoAttackers — адреса перебора; первые пять — из одной /24.
var demoAttackers = []string{
	"203.0.113.7", "203.0.113.19", "203.0.113.44", "203.0.113.45", "203.0.113.200",
	"198.51.100.31", "198.51.100.88", "192.0.2.77", "2001:db8:5::1", "2001:db8:5::2", "198.51.100.140", "203.0.113.91",
}

// demoFail2banFiles — конфигурация и журнал fail2ban для демо-дерева.
func demoFail2banFiles(now time.Time) map[string]string {
	files := map[string]string{
		"usr/bin/fail2ban-server": "#!/usr/bin/python3\n",
		"etc/fail2ban/fail2ban.conf": "[Definition]\nloglevel = INFO\nlogtarget = /var/log/fail2ban.log\n" +
			"dbfile = /var/lib/fail2ban/fail2ban.sqlite3\n",
		"etc/fail2ban/jail.conf": "[DEFAULT]\nbantime = 10m\nfindtime = 10m\nmaxretry = 5\nenabled = false\n" +
			"filter = %(__name__)s[mode=%(mode)s]\nmode = normal\n\n[sshd]\nport = ssh\nlogpath = %(sshd_log)s\n\n" +
			"[recidive]\nlogpath = /var/log/fail2ban.log\nbantime = 1w\nfindtime = 1d\n\n[nginx-http-auth]\nport = http,https\n",
		"etc/fail2ban/jail.d/defaults-debian.conf": "[sshd]\nenabled = true\n",
		"etc/fail2ban/jail.local": "[DEFAULT]\nbantime = 1h\nignoreip = 127.0.0.1/8 ::1\n           192.0.2.200\n\n" +
			"[sshd]\nbackend = systemd\nbantime.increment = true\n\n[recidive]\nenabled = true\n",
	}
	old, cur := demoFail2banLog(now)
	files[demoF2BLog+".1"] = old
	files[demoF2BLog] = cur
	return files
}

// f2bLine — строка журнала в формате fail2ban 1.x.
func f2bLine(t time.Time, module, level, msg string) string {
	return fmt.Sprintf("%s,%03d fail2ban.%-12s [640]: %-8s%s\n", t.Format("2006-01-02 15:04:05"), t.Nanosecond()/1e6, module, level, msg)
}

// demoFail2banLog строит журнал: возвращает ротированную часть (старше
// семи дней) и текущую.
func demoFail2banLog(now time.Time) (old, cur string) {
	type line struct {
		t time.Time
		s string
	}
	var lines []line
	add := func(t time.Time, module, level, msg string) {
		if t.Before(now) {
			lines = append(lines, line{t, f2bLine(t, module, level, msg)})
		}
	}
	// Детерминированный генератор: демо выглядит одинаково при каждом запуске.
	seed := uint32(20261025)
	rnd := func(n int) int {
		seed = seed*1664525 + 1013904223
		return int(seed>>8) % n
	}
	start := now.Add(-14 * 24 * time.Hour).Truncate(time.Hour)
	add(start.Add(time.Minute), "server", "INFO", "Starting Fail2ban v1.0.2")
	add(start.Add(time.Minute+time.Second), "jail", "INFO", "Jail 'sshd' started")
	add(start.Add(time.Minute+time.Second), "jail", "INFO", "Jail 'recidive' started")

	hits := map[string]int{}
	bans := map[string]int{}
	for h := 0; start.Add(time.Duration(h) * time.Hour).Before(now); h++ {
		hour := start.Add(time.Duration(h) * time.Hour)
		n := 2 + rnd(6)
		// Ночной фон выше дневного, плюс два всплеска.
		if hh := hour.Hour(); hh >= 1 && hh <= 5 {
			n += 4
		}
		ago := now.Sub(hour)
		if ago > 30*time.Hour && ago <= 31*time.Hour || ago > 3*time.Hour && ago <= 4*time.Hour {
			n += 40
		}
		for i := 0; i < n; i++ {
			ip := demoAttackers[rnd(len(demoAttackers))]
			if i%3 == 0 {
				ip = demoAttackers[0] // главный источник
			}
			t := hour.Add(time.Duration(rnd(3600)) * time.Second)
			add(t, "filter", "INFO", "[sshd] Found "+ip+" - "+t.Format("2006-01-02 15:04:05"))
			hits[ip]++
			if hits[ip]%5 != 0 {
				continue
			}
			bt := t.Add(time.Second)
			add(bt, "actions", "NOTICE", "[sshd] Ban "+ip)
			bans[ip]++
			add(bt.Add(time.Hour), "actions", "NOTICE", "[sshd] Unban "+ip)
			if bans[ip]%5 == 0 {
				add(bt.Add(2*time.Second), "filter", "INFO", "[recidive] Found "+ip+" - "+bt.Format("2006-01-02 15:04:05"))
				add(bt.Add(3*time.Second), "actions", "NOTICE", "[recidive] Ban "+ip)
				add(bt.Add(7*24*time.Hour), "actions", "NOTICE", "[recidive] Unban "+ip)
			}
		}
	}
	// Адрес из ignoreip тоже перебирает пароли.
	for i := 0; i < 4; i++ {
		add(now.Add(-time.Duration(20+i*7)*time.Minute), "filter", "INFO", "[sshd] Ignore 192.0.2.200 by ip")
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].t.Before(lines[j].t) })
	var o, c strings.Builder
	rot := now.Add(-7 * 24 * time.Hour)
	for _, l := range lines {
		if l.t.Before(rot) {
			o.WriteString(l.s)
		} else {
			c.WriteString(l.s)
		}
	}
	return o.String(), c.String()
}

// appendFail2ban дописывает в демо-журнал попытку (и иногда бан), чтобы
// в интерфейсе было видно, как растут счётчики.
func appendFail2ban(hostRoot string, step int, now time.Time) {
	f, err := os.OpenFile(filepath.Join(hostRoot, demoF2BLog), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	ip := "203.0.113.66"
	_, _ = f.WriteString(f2bLine(now, "filter", "INFO", "[sshd] Found "+ip+" - "+now.Format("2006-01-02 15:04:05")))
	if step%5 == 0 {
		_, _ = f.WriteString(f2bLine(now.Add(time.Millisecond), "actions", "NOTICE", "[sshd] Ban "+ip))
	}
}

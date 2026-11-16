package authlog

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

const maxEvents = 5000
const maxRead = 8 << 20

type Options struct {
	Root, StateDir string
	Days           int
	Retention      time.Duration
	ReadOnly       bool
}
type state struct {
	NewIPs map[string]time.Time `json:"newIPs"`
	Seen   map[string]time.Time `json:"seen"`
	Last   time.Time            `json:"last"`
}
type Collector struct {
	fileHeads    map[string][32]byte
	journalBytes int64
	journalFiles int
	journalKnown bool
	opt          Options
	state        state
	files        map[string]os.FileInfo
	report       *model.AuthReport
	loadErr      error
}

func New(opt Options) *Collector {
	if opt.Root == "" {
		opt.Root = "/"
	}
	if opt.Days <= 0 {
		opt.Days = 14
	}
	if opt.Retention <= 0 {
		opt.Retention = 7 * 24 * time.Hour
	}
	c := &Collector{opt: opt, state: state{Seen: map[string]time.Time{}}, files: map[string]os.FileInfo{}, fileHeads: map[string][32]byte{}}
	if opt.StateDir != "" {
		b, _, err := safefile.ReadRegular(filepath.Join(opt.StateDir, "auth-state.json"), 2<<20, false)
		if err == nil {
			err = json.Unmarshal(b, &c.state)
			if len(c.state.Seen) > maxEvents || len(c.state.NewIPs) > maxEvents {
				err = safefile.ErrTooLarge
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			c.loadErr = err
			c.state = state{}
		}
		if c.state.Seen == nil {
			c.state.Seen = map[string]time.Time{}
		}
	}
	if c.state.NewIPs == nil {
		c.state.NewIPs = map[string]time.Time{}
	}
	return c
}
func (c *Collector) Build(now time.Time, procs []*model.Process) *model.AuthReport {
	if c.report != nil && now.Sub(c.report.Time) >= 0 && now.Sub(c.report.Time) < time.Minute {
		return c.report
	}
	window := time.Duration(c.opt.Days) * 24 * time.Hour
	if c.opt.Retention < window {
		window = c.opt.Retention
	}
	r := &model.AuthReport{Time: now, Since: now.Add(-window), Events: []model.LoginEvent{}, Keys: []model.SSHKey{}}
	warn := func(path string) {
		r.Incomplete = true
		r.Warnings = append(r.Warnings, i18n.T("warn.auth_source", path))
	}
	if c.loadErr != nil {
		warn("auth-state.json")
		c.loadErr = nil
	}
	root, err := os.OpenRoot(c.opt.Root)
	if err != nil {
		warn(c.opt.Root)
		c.report = r
		return r
	}
	defer root.Close()
	readBudget := int64(64 << 20)
	read := func(path string, limit int64) ([]byte, error) {
		if readBudget <= 0 {
			return nil, safefile.ErrTooLarge
		}
		limit = min(limit, readBudget)
		f, fi, e := safefile.OpenRooted(root, path)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		if fi.Size() > limit {
			return nil, safefile.ErrTooLarge
		}
		b, e := io.ReadAll(io.LimitReader(f, limit+1))
		readBudget -= int64(len(b))
		if int64(len(b)) > limit {
			e = safefile.ErrTooLarge
		}
		return b, e
	}
	loc := time.Local
	if c.opt.Root != "/" {
		loc = time.UTC
		r.Warnings = append(r.Warnings, i18n.T("warn.auth_timezone"))
	}
	if b, e := read("etc/timezone", 4096); e == nil {
		if l, e := time.LoadLocation(strings.TrimSpace(string(b))); e == nil {
			loc = l
		}
	}
	accounts := map[string][]string{}
	if b, e := read("etc/passwd", 1<<20); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			v := strings.Split(line, ":")
			if len(v) == 7 {
				accounts[v[0]] = v
			}
		}
	} else {
		warn("/etc/passwd")
	}
	users := make([]string, 0, len(accounts))
	for u := range accounts {
		users = append(users, u)
	}
	sort.Strings(users)
	if len(users) > 4096 {
		users = users[:4096]
		warn("/etc/passwd: limit")
	}
	for _, u := range users {
		a := accounts[u]
		home := filepath.Clean(a[5])
		if !filepath.IsAbs(home) || home == "/" {
			continue
		}
		path := strings.TrimPrefix(home, "/") + "/.ssh/authorized_keys"
		if b, e := read(path, 1<<20); e == nil {
			r.Keys = append(r.Keys, Keys(b, u, "/"+path)...)
			if len(r.Keys) > maxEvents {
				r.Keys = r.Keys[:maxEvents]
				warn("authorized_keys: limit")
				break
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			warn("/" + path)
		}
		hp := strings.TrimPrefix(home, "/") + "/.bash_history"
		if fi, e := root.Lstat(hp); e == nil {
			null := false
			if fi.Mode()&os.ModeSymlink != 0 {
				target, e := os.Readlink(filepath.Join(c.opt.Root, hp))
				null = e == nil && target == "/dev/null"
			}
			if null || fi.Mode().IsRegular() && fi.Mode().Perm() == 0 {
				r.Findings = append(r.Findings, finding("log_history_null", "/"+hp, model.RiskMedium))
			}
		}
	}
	if len(r.Keys) > maxEvents {
		r.Keys = r.Keys[:maxEvents]
		warn("authorized_keys: limit")
	}
	// Фиксированный набор ротаций ограничивает чтение и распаковку.
	authFound := false
	budget := int64(32 << 20)
	for _, path := range []string{"var/log/auth.log.2.gz", "var/log/auth.log.1", "var/log/auth.log"} {
		f, fi, e := safefile.OpenRooted(root, path)
		if e != nil {
			if !errors.Is(e, os.ErrNotExist) || path == "var/log/auth.log" {
				warn("/" + path)
			}
			continue
		}
		authFound = true
		if path == "var/log/auth.log" {
			c.changed(root, path, fi, r)
		}
		if fi.ModTime().After(now.Add(5 * time.Minute)) {
			r.Findings = append(r.Findings, finding("log_authlog_truncated", "/"+path, model.RiskHigh))
		}
		var rd io.Reader = f
		var gz *gzip.Reader
		if strings.HasSuffix(path, ".gz") {
			gz, e = gzip.NewReader(f)
			if e != nil {
				f.Close()
				warn("/" + path)
				continue
			}
			rd = gz
		}
		limit := int64(maxRead)
		if budget < limit {
			limit = budget
		}
		if limit <= 0 {
			f.Close()
			warn("auth.log: budget")
			break
		}
		skipFirst := false
		if gz == nil && fi.Size() > limit {
			if _, e = f.Seek(fi.Size()-limit, io.SeekStart); e != nil {
				f.Close()
				warn("/" + path)
				continue
			}
			skipFirst = true
			warn("/" + path + ": tail only")
		}
		lr := &io.LimitedReader{R: rd, N: limit + 1}
		sc := bufio.NewScanner(lr)
		sc.Buffer(make([]byte, 4096), 64<<10)
		for sc.Scan() {
			if skipFirst {
				skipFirst = false
				continue
			}
			if e, ok := ParseLine(sc.Text(), "/"+path, fi.ModTime(), loc); ok && !e.Time.Before(r.Since) && !e.Time.After(now.Add(5*time.Minute)) {
				r.Events = append(r.Events, e)
				if len(r.Events) > 10000 {
					r.Events = boundEvents(r.Events)
					warn("events: limit")
				}
			}
		}
		if sc.Err() != nil || lr.N <= 0 {
			warn("/" + path)
		}
		budget -= limit + 1 - lr.N
		if gz != nil {
			gz.Close()
		}
		f.Close()
		if len(r.Events) > maxEvents {
			warn("events: limit")
		}
		r.Events = boundEvents(r.Events)
	}
	if !authFound {
		warn("/var/log/auth.log; journalctl -u ssh (journald not parsed)")
	}
	arm, known := architecture(root, c.opt.Root)
	if !known {
		warn("utmp/lastlog: unknown architecture")
	}
	if known {
		for _, path := range []string{"var/log/wtmp.1", "var/log/wtmp", "var/log/btmp.1", "var/log/btmp", "run/utmp"} {
			b, e := read(path, maxRead)
			if e != nil {
				if !errors.Is(e, os.ErrNotExist) || !strings.HasSuffix(path, ".1") {
					warn("/" + path)
				}
				continue
			}
			if fi, e := root.Lstat(path); e == nil {
				c.changed(root, path, fi, r)
			}
			events, bad := Utmp(b, "/"+path, arm)
			if bad {
				warn("/" + path)
				if strings.Contains(path, "wtmp") {
					r.Findings = append(r.Findings, finding("log_wtmp_gap", "/"+path, model.RiskMedium))
				}
			}
			for _, e := range events {
				if !e.Time.Before(r.Since) && !e.Time.After(now.Add(5*time.Minute)) {
					r.Events = append(r.Events, e)
				}
			}
		}
		f, _, e := safefile.OpenRooted(root, "var/log/lastlog")
		if e == nil {
			size, ts := 292, 4
			if arm {
				size, ts = 296, 8
			}
			b := make([]byte, size)
			for _, u := range users {
				uid, e := strconv.ParseUint(accounts[u][2], 10, 32)
				if e != nil {
					continue
				}
				n, e := f.ReadAt(b, int64(uid)*int64(size))
				if e == io.EOF && n == 0 {
					continue
				}
				if e != nil {
					warn("/var/log/lastlog")
					break
				}
				sec := int64(binary.LittleEndian.Uint32(b))
				if arm {
					sec = int64(binary.LittleEndian.Uint64(b))
				}
				t := time.Unix(sec, 0)
				if sec > 0 && !t.Before(r.Since) && !t.After(now) {
					r.Events = append(r.Events, model.LoginEvent{Time: t, Kind: "lastlogin", User: u, TTY: strings.TrimRight(string(b[ts:ts+32]), "\x00"), IP: strings.TrimRight(string(b[ts+32:]), "\x00"), Source: "/var/log/lastlog"})
				}
			}
			f.Close()
		} else {
			warn("/var/log/lastlog")
		}
	}
	sort.SliceStable(r.Events, func(i, j int) bool { return r.Events[i].Time.Before(r.Events[j].Time) })
	// Перекрывающиеся ротации не должны удваивать события из разных источников.
	origins := map[string]string{}
	unique := r.Events[:0]
	for _, e := range r.Events {
		k := eventKey(e)
		if old, ok := origins[k]; ok && old != e.Source {
			continue
		}
		origins[k] = e.Source
		unique = append(unique, e)
	}
	r.Events = unique
	// Выход связывается только с теми же TTY, PID и периодом между перезагрузками.
	active := map[string]int{}
	for i := range r.Events {
		e := &r.Events[i]
		k := strconv.Itoa(e.PID) + "|" + e.TTY
		switch e.Kind {
		case "boot":
			clear(active)
		case "session":
			active[k] = i
		case "logout":
			if j, ok := active[k]; ok {
				end := e.Time
				r.Events[j].End = &end
				delete(active, k)
			}
		}
	}
	if len(r.Events) > maxEvents {
		warn("events: limit")
	}
	r.Events = boundEvents(r.Events)
	for i := range r.Events {
		e := &r.Events[i]
		if e.Kind != "login" {
			continue
		}
		match := -1
		for j, s := range r.Events {
			if s.Kind == "session" && s.User == e.User && s.IP == e.IP && s.Time.Sub(e.Time) >= 0 && s.Time.Sub(e.Time) <= 2*time.Minute {
				if match >= 0 {
					match = -1
					break
				}
				match = j
			}
		}
		if match >= 0 {
			e.TTY = r.Events[match].TTY
			e.End = r.Events[match].End
		}
	}
	c.assess(r, accounts)
	// Отсутствие utmp не доказывает подмену: сравниваем только успешно прочитанный файл.
	utmp, ue := read("run/utmp", maxRead)
	if known && ue == nil {
		sessions, bad := Utmp(utmp, "/run/utmp", arm)
		if !bad {
			for _, p := range procs {
				if !strings.HasPrefix(p.Cmdline, "sshd: ") || !strings.Contains(p.Cmdline, "@pts/") {
					continue
				}
				user, tty, ok := strings.Cut(strings.TrimPrefix(p.Cmdline, "sshd: "), "@")
				if !ok {
					continue
				}
				tty = strings.Fields(tty)[0]
				found := false
				for _, s := range sessions {
					if s.Kind == "session" && s.User == user && s.TTY == tty {
						found = true
					}
				}
				if !found {
					r.Findings = append(r.Findings, finding("log_utmp_missing", "/run/utmp", model.RiskHigh))
				}
			}
		}
	}
	// Уменьшение объёма — наблюдение, а не доказательство удаления следов.
	var journalBytes int64
	journalFiles := 0
	journalRoot, je := root.Open("var/log/journal")
	if je == nil {
		dirs, de := journalRoot.ReadDir(65)
		journalRoot.Close()
		if de == nil || de == io.EOF {
			if len(dirs) > 64 {
				warn("journal: directory limit")
			} else {
				for _, d := range dirs {
					if !d.IsDir() {
						continue
					}
					dir, e := root.Open("var/log/journal/" + d.Name())
					if e != nil {
						continue
					}
					files, e := dir.ReadDir(4097)
					dir.Close()
					if e != nil && e != io.EOF || len(files) > 4096 {
						warn("journal: file limit")
						continue
					}
					for _, f := range files {
						if !strings.HasSuffix(f.Name(), ".journal") {
							continue
						}
						fi, e := root.Lstat("var/log/journal/" + d.Name() + "/" + f.Name())
						if e == nil && fi.Mode().IsRegular() {
							journalBytes += fi.Size()
							journalFiles++
						}
					}
				}
			}
		}
	}
	if c.journalKnown && c.journalBytes > 1<<20 && journalBytes < c.journalBytes/2 && journalFiles == c.journalFiles && journalFiles > 0 {
		r.Findings = append(r.Findings, finding("log_journal_vacuum", "/var/log/journal", model.RiskMedium))
	}
	c.journalBytes, c.journalFiles, c.journalKnown = journalBytes, journalFiles, je == nil
	c.state.Last = now
	if c.opt.StateDir != "" && !c.opt.ReadOnly {
		if e := safefile.WriteJSON(filepath.Join(c.opt.StateDir, "auth-state.json"), c.state, 2<<20); e != nil {
			warn("auth-state.json")
		}
	}
	c.report = r
	return r
}
func boundEvents(e []model.LoginEvent) []model.LoginEvent {
	if len(e) <= maxEvents {
		return e
	}
	sort.SliceStable(e, func(i, j int) bool { return e[i].Time.Before(e[j].Time) })
	return append([]model.LoginEvent(nil), e[len(e)-maxEvents:]...)
}
func (c *Collector) changed(root *os.Root, path string, fi os.FileInfo, r *model.AuthReport) {
	head := func(p string, size int64) ([32]byte, bool) {
		f, _, e := safefile.OpenRooted(root, p)
		if e != nil {
			return [32]byte{}, false
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, min(size, 4096)))
		return sha256.Sum256(b), e == nil && int64(len(b)) == min(size, 4096)
	}
	if old := c.files[path]; old != nil && os.SameFile(old, fi) && fi.Size() < old.Size() {
		rotated := false
		if rot, e := root.Lstat(path + ".1"); e == nil {
			rotated = os.SameFile(old, rot)
			if !rotated && rot.Size() >= old.Size() && !rot.ModTime().Before(old.ModTime()) {
				if oldHead, ok := c.fileHeads[path]; ok {
					h, read := head(path+".1", old.Size())
					rotated = read && h == oldHead
				}
			}
		}
		if !rotated && (path == "var/log/wtmp" || path == "var/log/auth.log") {
			id := "log_wtmp_truncated"
			if strings.Contains(path, "auth.log") {
				id = "log_authlog_truncated"
			}
			r.Findings = append(r.Findings, finding(id, "/"+path, model.RiskHigh))
		}
	}
	c.files[path] = fi
	if h, ok := head(path, fi.Size()); ok {
		c.fileHeads[path] = h
	} else {
		delete(c.fileHeads, path)
	}
}

func finding(id, path string, risk model.Risk) model.SystemFinding {
	return model.SystemFinding{Finding: model.Finding{ID: id, Title: i18n.T(authTitles[id]), Category: model.CatBehavior, Recommendation: i18n.T("rec.auth_review")}, Path: path, Risk: risk}
}
func architecture(root *os.Root, host string) (bool, bool) {
	if host == "/" && runtime.GOOS == "linux" {
		return runtime.GOARCH == "arm64", runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
	}
	for _, p := range []string{"usr/bin/bash", "bin/bash", "usr/bin/dash", "bin/dash"} {
		f, _, e := safefile.OpenRooted(root, p)
		if e != nil {
			continue
		}
		b := make([]byte, 20)
		_, e = io.ReadFull(f, b)
		f.Close()
		if e == nil && string(b[:4]) == "\x7fELF" && b[4] == 2 && b[5] == 1 {
			m := binary.LittleEndian.Uint16(b[18:])
			if m == 62 || m == 183 {
				return m == 183, true
			}
		}
	}
	return false, false
}
func (c *Collector) assess(r *model.AuthReport, accounts map[string][]string) {
	ipCount, userCount, hourCount := map[string]int{}, map[string]int{}, map[string]int{}
	failures := map[string][]time.Time{}
	hours := map[string][24]int{}
	totals := map[string]int{}
	for ip, t := range c.state.Seen {
		if t.Before(r.Since) {
			delete(c.state.Seen, ip)
			delete(c.state.NewIPs, ip)
		}
	}
	for i := range r.Events {
		e := &r.Events[i]
		if e.Kind == "failed" {
			ipCount[e.IP]++
			userCount[e.User]++
			hourCount[e.Time.UTC().Format("2006-01-02T15:00Z")]++
			failures[e.IP] = append(failures[e.IP], e.Time)
			continue
		}
		if e.Kind != "login" {
			continue
		}
		add := func(id string, risk model.Risk) {
			e.Findings = append(e.Findings, id)
			if risk > e.Risk {
				e.Risk = risk
			}
			f := finding(id, e.Source, risk)
			f.Evidence = []i18n.Msg{i18n.L(e.Time.Format(time.RFC3339) + " " + e.User + " " + e.IP)}
			r.Findings = append(r.Findings, f)
		}
		if e.User == "root" && e.Method == "password" {
			add("login_password_root", model.RiskHigh)
		}
		if a, ok := accounts[e.User]; ok && (strings.HasSuffix(a[6], "/nologin") || strings.HasSuffix(a[6], "/false") || e.User == "www-data" || e.User == "postgres" || e.User == "nobody") {
			add("login_service_account", model.RiskHigh)
		}
		n := 0
		for _, t := range failures[e.IP] {
			if e.Time.Sub(t) <= 10*time.Minute {
				n++
			}
		}
		if n >= 10 {
			add("login_after_bruteforce", model.RiskCritical)
		}
		if _, ok := c.state.Seen[e.IP]; !ok && !c.state.Last.IsZero() && e.Time.After(c.state.Last) {
			c.state.NewIPs[e.IP] = e.Time
		}
		if t, ok := c.state.NewIPs[e.IP]; ok && e.Time.Equal(t) {
			add("login_new_ip", model.RiskLow)
		}
		if old := c.state.Seen[e.IP]; e.Time.After(old) && (!old.IsZero() || len(c.state.Seen) < maxEvents) {
			c.state.Seen[e.IP] = e.Time
		}
		h := hours[e.User]
		if totals[e.User] >= 20 && h[e.Time.Hour()] == 0 {
			add("login_unusual_time", model.RiskInfo)
		}
		h[e.Time.Hour()]++
		hours[e.User] = h
		totals[e.User]++
		for j := range r.Keys {
			k := &r.Keys[j]
			if k.User == e.User && k.Fingerprint == e.Fingerprint && e.Fingerprint != "" {
				e.KeyComment = k.Comment
				k.Used = true
			}
		}
	}
	if len(ipCount) == 0 {
		for _, e := range r.Events {
			if e.Kind == "failed_session" {
				ipCount[e.IP]++
				userCount[e.User]++
				hourCount[e.Time.UTC().Format("2006-01-02T15:00Z")]++
			}
		}
	}
	r.FailedIPs = counts(ipCount)
	r.FailedUsers = counts(userCount)
	r.FailedHours = counts(hourCount)
	sort.Slice(r.FailedHours, func(i, j int) bool { return r.FailedHours[i].Name < r.FailedHours[j].Name })
}
func counts(m map[string]int) []model.AuthCount {
	out := make([]model.AuthCount, 0, len(m))
	for n, c := range m {
		out = append(out, model.AuthCount{Name: n, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	return out
}

var authTitles = map[string]string{
	"log_journal_vacuum":     "rule.log_journal_vacuum.title",
	"login_new_ip":           "rule.login_new_ip.title",
	"login_password_root":    "rule.login_password_root.title",
	"login_after_bruteforce": "rule.login_after_bruteforce.title",
	"login_unusual_time":     "rule.login_unusual_time.title",
	"login_service_account":  "rule.login_service_account.title",
	"log_wtmp_truncated":     "rule.log_wtmp_truncated.title",
	"log_wtmp_gap":           "rule.log_wtmp_gap.title",
	"log_authlog_truncated":  "rule.log_authlog_truncated.title",
	"log_history_null":       "rule.log_history_null.title",
	"log_utmp_missing":       "rule.log_utmp_missing.title",
}

func eventKey(e model.LoginEvent) string {
	return e.Time.Format(time.RFC3339Nano) + "|" + e.Kind + "|" + e.User + "|" + e.IP + "|" + strconv.Itoa(e.PID) + "|" + e.Method + "|" + e.TTY
}

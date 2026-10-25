// Пакет fail2ban показывает состояние fail2ban и интенсивность перебора
// паролей: включённые jail, текущие баны, попытки и баны по часам,
// самые активные адреса.
//
// Всё только читается: конфигурация /etc/fail2ban и журнал
// /var/log/fail2ban.log (с ротированными файлами, в том числе .gz).
// fail2ban-client не запускается, команды бана и разбана лишь
// предлагаются текстом. Раздел существует, только если fail2ban
// установлен (Installed): иначе интерфейсы его не показывают.
//
// IP-адреса — персональные данные: отчёт строится заново из журнала и
// живёт только в памяти службы, в историю и state.json адреса не пишутся.
package fail2ban

import (
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/exposure"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// Пределы чтения журнала за одно построение отчёта.
const (
	maxLogFiles   = 60        // ротированных файлов
	maxFileBytes  = 256 << 20 // байт (после распаковки) из одного файла
	maxTotalBytes = 1 << 30   // байт за одно построение
)

// Пределы отчёта.
const (
	maxTop    = 20
	maxNets   = 10
	maxRecent = 100
	maxBans   = 2000
)

// DefaultDays — глубина анализа журнала по умолчанию (SSG_AUTH_LOG_DAYS).
const DefaultDays = 14

// Input — данные одного сканирования.
type Input struct {
	HostRoot string
	Procs    []*model.Process
	// Exposure — открытые порты: виден ли SSH из интернета.
	Exposure *model.ExposureReport
	Now      time.Time
	Days     int
	// Allowed — allowlist (detect.Config.Allowed): подавляет находку
	// fail2ban_sshd_disabled для процесса, который держит порт SSH.
	Allowed func(p *model.Process, ruleID string) bool
	// Loc — часовой пояс журнала (fail2ban пишет местное время). nil —
	// time.Local.
	Loc *time.Location
}

// Collector строит отчёт при каждом сканировании. Разобранные файлы
// журнала кешируются по inode: ротированные файлы читаются один раз,
// текущий — дочитывается с места, где остановились.
type Collector struct {
	mu    sync.Mutex
	files map[fileID]*fileData
}

// NewCollector создаёт сборщик с пустым кешем.
func NewCollector() *Collector { return &Collector{files: map[fileID]*fileData{}} }

// Build строит отчёт и системные находки (fail2ban_not_running,
// fail2ban_sshd_disabled, fail2ban_log_unavailable). Если fail2ban не
// установлен, отчёт с Installed = false и находок нет.
func (c *Collector) Build(in Input) (*model.Fail2banReport, []model.SystemFinding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if in.Days <= 0 {
		in.Days = DefaultDays
	}
	if in.Loc == nil {
		in.Loc = time.Local
	}
	how, pid := detect(in.HostRoot, in.Procs)
	if how == "" {
		// fail2ban удалили — кеш больше не нужен.
		clear(c.files)
		return &model.Fail2banReport{}, nil
	}
	from := in.Now.Add(-time.Duration(in.Days) * 24 * time.Hour).Truncate(time.Hour)
	rep := &model.Fail2banReport{Installed: true, Running: pid != 0, PID: pid, Days: in.Days, From: from}
	sc := readServerConfig(in.HostRoot)
	rep.LogTarget = sc.LogTarget
	jc := readJails(in.HostRoot)

	var files []*fileData
	var logErr error
	if path, ok := sc.logFile(); ok {
		var names []string
		files, names, logErr = c.readLogs(in.HostRoot, path, from, in.Loc)
		rep.LogFiles = names
		rep.LogAvailable = logErr == nil
	}
	aggregate(rep, files, jc, in.Now, in.Loc)
	if !sc.verbose() {
		rep.Warnings = append(rep.Warnings, i18n.T("warn.f2b_loglevel", sc.LogLevel))
	}
	for _, fd := range files {
		if fd.cut {
			rep.Warnings = append(rep.Warnings, i18n.T("warn.f2b_log_cut", maxFileBytes>>20))
			break
		}
	}
	for _, fd := range files {
		if fd.overflow > 0 || fd.dropped {
			rep.Warnings = append(rep.Warnings, i18n.T("warn.f2b_log_limits"))
			break
		}
	}
	return rep, findings(rep, in, how, sc, jc, logErr)
}

// detect — как узнали, что fail2ban установлен ("" — не установлен), и
// PID процесса fail2ban-server (0 — не запущен).
func detect(hostRoot string, procs []*model.Process) (string, int) {
	pid := 0
	for _, p := range procs {
		if !p.Kernel && isServer(p) {
			pid = p.PID
			break
		}
	}
	h := func(p string) string { return filepath.Join(hostRoot, p) }
	if fi, err := os.Stat(h("etc/fail2ban")); err == nil && fi.IsDir() {
		for _, p := range []string{"usr/bin/fail2ban-server", "usr/local/bin/fail2ban-server", "var/lib/dpkg/info/fail2ban.list"} {
			if _, err := os.Stat(h(p)); err == nil {
				return "/" + p, pid
			}
		}
	}
	if pid != 0 {
		return "fail2ban-server (PID " + strconv.Itoa(pid) + ")", pid
	}
	return "", 0
}

// isServer — процесс fail2ban-server. Это скрипт Python: comm совпадает с
// именем скрипта, а в cmdline первым идёт интерпретатор.
func isServer(p *model.Process) bool {
	if p.Name == "fail2ban-server" {
		return true
	}
	if len(p.Args) >= 2 && strings.HasPrefix(filepath.Base(p.Args[0]), "python") {
		return filepath.Base(p.Args[1]) == "fail2ban-server"
	}
	return false
}

// rotatedName — имя ротированного журнала: fail2ban.log.1, fail2ban.log.2.gz,
// fail2ban.log-20240115(.gz).
var rotatedName = regexp.MustCompile(`^[.-][0-9]{1,8}(\.gz)?$`)

// readLogs читает текущий журнал и ротированные файлы, изменённые после
// from. Возвращает разобранные файлы от старых к новым и их пути на хосте.
func (c *Collector) readLogs(hostRoot, logPath string, from time.Time, loc *time.Location) ([]*fileData, []string, error) {
	full := filepath.Join(hostRoot, logPath)
	dir, base := filepath.Split(full)
	type cand struct {
		path   string
		mtime  time.Time
		active bool
	}
	var cands []cand
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, base) || !rotatedName.MatchString(name[len(base):]) {
				continue
			}
			fi, err := e.Info()
			if err != nil || !fi.Mode().IsRegular() || fi.ModTime().Before(from) {
				continue
			}
			cands = append(cands, cand{path: filepath.Join(dir, name), mtime: fi.ModTime()})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mtime.Before(cands[j].mtime) })
	if len(cands) > maxLogFiles {
		cands = cands[len(cands)-maxLogFiles:]
	}
	cands = append(cands, cand{path: full, active: true})

	seen := map[fileID]bool{}
	var out []*fileData
	var names []string
	var mainErr error
	budget := int64(maxTotalBytes)
	for _, cd := range cands {
		fd, err := c.load(cd.path, !cd.active, loc, &budget)
		if err != nil {
			if cd.active {
				mainErr = err
			}
			continue
		}
		if seen[fd.id] {
			continue // тот же файл под двумя именами (жёсткая ссылка)
		}
		seen[fd.id] = true
		out = append(out, fd)
		names = append(names, hostPath(hostRoot, cd.path))
	}
	// Файлы, которых больше нет (удалены при ротации), забываются.
	for id := range c.files {
		if !seen[id] {
			delete(c.files, id)
		}
	}
	return out, names, mainErr
}

// load возвращает разобранный файл: из кеша, дочитанный или прочитанный
// заново. Журнал в /var/log может подменить пользователь группы syslog,
// поэтому симлинк не открывается, FIFO и устройства — тоже.
func (c *Collector) load(path string, final bool, loc *time.Location, budget *int64) (*fileData, error) {
	f, fi, err := safefile.Open(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	id := idOf(path, fi)
	gz := strings.HasSuffix(path, ".gz")
	fd := c.files[id]
	switch {
	case fd != nil && fd.gz == gz && gz && fd.size == fi.Size() && fd.mtime.Equal(fi.ModTime()):
		return fd, nil // сжатый файл не меняется
	case fd != nil && fd.gz == gz && fd.cut && fi.Size() >= fd.offset:
		// Файл больше предела: прочитанная часть остаётся, остальное не
		// читается, пока файл не ротируют.
		return fd, nil
	case fd != nil && fd.gz == gz && !gz && fi.Size() >= fd.offset:
		if fi.Size() == fd.offset {
			fd.size, fd.mtime = fi.Size(), fi.ModTime()
			return fd, nil
		}
		// Файл дописан: читаем только новое.
		if _, err := f.Seek(fd.offset, io.SeekStart); err != nil {
			return nil, err
		}
	default:
		// Новый файл, его усекли (copytruncate) или сжали.
		fd = newFileData()
		fd.id, fd.gz = id, gz
	}
	// Бюджет памяти — общий на все файлы: этому достаётся то, что не
	// заняли остальные (ротированные файлы разобраны раньше и уже в кеше).
	usedIP, usedEv := 0, 0
	for oid, o := range c.files {
		if oid != id {
			usedIP += len(o.byIP) + len(o.ignored)
			usedEv += len(o.events)
		}
	}
	fd.ipCap, fd.evCap = max(maxTotalIPs-usedIP, 0), max(maxTotalEvts-usedEv, 0)
	limit := min(int64(maxFileBytes)-fd.offset, *budget)
	if limit <= 0 {
		if fd.offset >= maxFileBytes {
			fd.cut = true
			c.files[id] = fd
		}
		// Иначе исчерпан общий бюджет: недочитанное прочитается при
		// следующем построении.
		return fd, nil
	}
	var r io.Reader = f
	if gz {
		zr, err := gzipReader(f)
		if err != nil {
			return nil, err
		}
		r = zr
	}
	n := fd.consume(r, limit, final || gz, loc)
	*budget -= n
	fd.offset += n
	fd.size, fd.mtime = fi.Size(), fi.ModTime()
	c.files[id] = fd
	return fd, nil
}

// aggregate сводит разобранные файлы в отчёт за окно [rep.From, now].
func aggregate(rep *model.Fail2banReport, files []*fileData, jc jailConfig, now time.Time, loc *time.Location) {
	from := rep.From
	fromHour := from.Unix() / 3600
	nh := int(now.Unix()/3600-fromHour) + 1
	rep.Hourly = make([]model.Fail2banBucket, max(nh, 1))
	for i := range rep.Hourly {
		rep.Hourly[i].Time = from.Add(time.Duration(i) * time.Hour)
	}
	hourIdx := func(ts int64) int {
		i := int(ts/3600 - fromHour)
		if i < 0 || i >= len(rep.Hourly) {
			return -1
		}
		return i
	}

	jails := map[string]*model.Fail2banJail{}
	banTimes := map[string]int64{}
	var ignore []netip.Prefix
	for _, j := range jc.Jails {
		jj := &model.Fail2banJail{Name: j.Name, Filter: j.Filter, Port: j.Port, MaxRetry: j.MaxRetry, FindTime: j.FindTime, BanTime: j.BanTime,
			Increment: j.Increment, IgnoreIP: j.IgnoreIP, Source: j.Source, SSH: j.SSH()}
		jails[j.Name] = jj
		banTimes[j.Name] = j.BanTime
		for _, s := range j.IgnoreIP {
			if p, err := netip.ParsePrefix(s); err == nil {
				ignore = append(ignore, p.Masked())
			} else if a, err := netip.ParseAddr(s); err == nil {
				ignore = append(ignore, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			}
		}
	}
	jailOf := func(name string) *model.Fail2banJail {
		if j := jails[name]; j != nil {
			return j
		}
		// Jail из журнала, которого нет среди включённых (выключили или
		// конфигурация не прочиталась): показываем его счётчики.
		j := &model.Fail2banJail{Name: name}
		jails[name] = j
		return j
	}

	type src struct {
		found, bans int
		jails       map[string]bool
		ignored     bool
	}
	srcs := map[string]*src{}
	getSrc := func(ip string) *src {
		s := srcs[ip]
		if s == nil {
			s = &src{jails: map[string]bool{}}
			srcs[ip] = s
		}
		return s
	}
	fromDay := from.Unix() / 86400
	var events []event
	for _, fd := range files {
		if fd.version != "" {
			rep.Version = fd.version
		}
		for k, n := range fd.found {
			if i := hourIdx(k.hour * 3600); i >= 0 {
				rep.Hourly[i].Found += n
				jailOf(k.jail).Found += n
			}
		}
		for k, n := range fd.byIP {
			if k.day >= fromDay {
				s := getSrc(k.ip)
				s.found += n
				s.jails[k.jail] = true
			}
		}
		// Адрес из ignoreip fail2ban пишет строкой «Ignore», а не «Found»: в
		// почасовую статистику такие попытки не входят (fail2ban их не
		// считает), а у источника видны с пометкой.
		for ip, n := range fd.ignored {
			s := getSrc(ip)
			s.ignored = true
			s.found += n
		}
		events = append(events, fd.events...)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].t < events[j].t })

	// Текущие баны: проигрываем события по порядку.
	type banState struct {
		since, until   int64
		perm, restored bool
	}
	type bk struct{ jail, ip string }
	active := map[bk]*banState{}
	banCount := map[string]int{}
	banTime := func(jail string) int64 {
		if t, ok := banTimes[jail]; ok {
			return t
		}
		return defaultBanTime
	}
	var recent []model.Fail2banEvent
	for _, e := range events {
		k := bk{e.jail, e.ip}
		switch e.act {
		case actBan, actRestore:
			st := &banState{since: e.t, restored: e.act == actRestore}
			if bt := banTime(e.jail); bt < 0 {
				st.perm = true
			} else {
				st.until = e.t + bt
			}
			// Продление (Increase Ban) приходит до строки Ban — не теряем его.
			if old := active[k]; old != nil && (old.perm || old.until > e.t) {
				st.perm = st.perm || old.perm
				st.until = max(st.until, old.until)
			}
			active[k] = st
			if e.act == actBan && e.t >= from.Unix() {
				banCount[e.ip]++
				jailOf(e.jail).Bans++
				getSrc(e.ip).bans++
				getSrc(e.ip).jails[e.jail] = true
				if i := hourIdx(e.t); i >= 0 {
					rep.Hourly[i].Bans++
				}
			}
		case actIncrease:
			st := active[k]
			if st == nil {
				st = &banState{since: e.t, until: e.t + max(banTime(e.jail), 0)}
				active[k] = st
			}
			if e.until > 0 {
				st.until = e.until
			}
		case actUnban:
			delete(active, k)
		case actStart, actStop:
			// При запуске и остановке fail2ban снимает все блокировки; после
			// запуска действующие баны восстанавливаются строками Restore Ban.
			clear(active)
		case actJailStart, actJailStop:
			for key := range active {
				if key.jail == e.jail {
					delete(active, key)
				}
			}
		}
		if e.act != actIgnore && e.act != actFound {
			recent = append(recent, model.Fail2banEvent{Time: time.Unix(e.t, 0).In(loc), Action: actionName(e.act), Jail: e.jail, IP: e.ip})
		}
	}
	if len(recent) > maxRecent {
		recent = recent[len(recent)-maxRecent:]
	}
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	rep.Recent = recent

	// Остановленный fail2ban снял свои правила: банов сейчас нет.
	nowU := now.Unix()
	rep.Bans = []model.Fail2banBan{}
	if rep.Running {
		for k, st := range active {
			if !st.perm && st.until <= nowU {
				continue
			}
			b := model.Fail2banBan{IP: k.ip, Jail: k.jail, Since: time.Unix(st.since, 0).In(loc), Permanent: st.perm, Restored: st.restored,
				Count: banCount[k.ip], UnbanCommand: unbanCommand(k.jail, k.ip)}
			if !st.perm {
				b.Until = time.Unix(st.until, 0).In(loc)
			}
			rep.Bans = append(rep.Bans, b)
			jailOf(k.jail).Banned++
		}
	}
	sort.Slice(rep.Bans, func(i, j int) bool {
		if !rep.Bans[i].Since.Equal(rep.Bans[j].Since) {
			return rep.Bans[i].Since.After(rep.Bans[j].Since)
		}
		return rep.Bans[i].IP < rep.Bans[j].IP
	})
	if len(rep.Bans) > maxBans {
		rep.Bans = rep.Bans[:maxBans]
	}

	// Итоги, сутки и пик.
	day24 := now.Add(-24 * time.Hour)
	for _, b := range rep.Hourly {
		rep.Found += b.Found
		rep.BanCount += b.Bans
		if !b.Time.Add(time.Hour).Before(day24) {
			rep.Found24h += b.Found
			rep.Bans24h += b.Bans
		}
		if b.Found > rep.Peak.Found {
			rep.Peak = b
		}
		t := b.Time.In(loc)
		d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
		if n := len(rep.Daily); n == 0 || !rep.Daily[n-1].Time.Equal(d) {
			rep.Daily = append(rep.Daily, model.Fail2banBucket{Time: d})
		}
		rep.Daily[len(rep.Daily)-1].Found += b.Found
		rep.Daily[len(rep.Daily)-1].Bans += b.Bans
	}

	// Самые активные адреса и подсети.
	type netAgg struct {
		found, bans int
		ips         int
	}
	nets := map[netip.Prefix]*netAgg{}
	rep.Top = []model.Fail2banSource{}
	for ip, s := range srcs {
		if s.found == 0 && s.bans == 0 {
			continue
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		ignored := s.ignored
		for _, p := range ignore {
			if p.Contains(a) {
				ignored = true
			}
		}
		js := make([]string, 0, len(s.jails))
		for j := range s.jails {
			js = append(js, j)
		}
		sort.Strings(js)
		rep.Top = append(rep.Top, model.Fail2banSource{Addr: ip, Found: s.found, Bans: s.bans, Jails: js, Ignored: ignored})
		bits := 24
		if a.Is6() {
			bits = 64
		}
		p, _ := a.Prefix(bits)
		n := nets[p]
		if n == nil {
			n = &netAgg{}
			nets[p] = n
		}
		n.found += s.found
		n.bans += s.bans
		n.ips++
	}
	sortSources(rep.Top)
	if len(rep.Top) > maxTop {
		rep.Top = rep.Top[:maxTop]
	}
	rep.TopNets = []model.Fail2banSource{}
	for p, n := range nets {
		// Подсеть с одним адресом повторяла бы строку из Top.
		if n.ips >= 2 {
			rep.TopNets = append(rep.TopNets, model.Fail2banSource{Addr: p.String(), Found: n.found, Bans: n.bans, IPs: n.ips})
		}
	}
	sortSources(rep.TopNets)
	if len(rep.TopNets) > maxNets {
		rep.TopNets = rep.TopNets[:maxNets]
	}

	rep.Jails = make([]model.Fail2banJail, 0, len(jails))
	for _, j := range jails {
		rep.Jails = append(rep.Jails, *j)
	}
	sort.Slice(rep.Jails, func(i, k int) bool {
		// Сначала включённые (с параметрами из конфигурации), затем по имени.
		if (rep.Jails[i].Source != "") != (rep.Jails[k].Source != "") {
			return rep.Jails[i].Source != ""
		}
		return rep.Jails[i].Name < rep.Jails[k].Name
	})
}

func sortSources(s []model.Fail2banSource) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].Found != s[j].Found {
			return s[i].Found > s[j].Found
		}
		if s[i].Bans != s[j].Bans {
			return s[i].Bans > s[j].Bans
		}
		return s[i].Addr < s[j].Addr
	})
}

func actionName(a uint8) string {
	switch a {
	case actBan:
		return "ban"
	case actUnban:
		return "unban"
	case actRestore:
		return "restore"
	case actIncrease:
		return "increase"
	case actStart:
		return "start"
	case actStop:
		return "stop"
	case actJailStart:
		return "jail_start"
	case actJailStop:
		return "jail_stop"
	}
	return ""
}

// safeJail — имя jail, которое можно подставить в команду без кавычек.
var safeJail = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,64}$`)

// unbanCommand — команда разблокировки (текст для администратора). IP
// уже проверен netip.ParseAddr; имя jail из журнала — проверяем, чтобы в
// команду не попало ничего лишнего.
func unbanCommand(jail, ip string) string {
	if !safeJail.MatchString(jail) {
		return ""
	}
	if a, err := netip.ParseAddr(ip); err != nil || a.Zone() != "" {
		return ""
	}
	return "fail2ban-client set " + jail + " unbanip " + ip
}

// findings — системные находки по состоянию fail2ban.
func findings(rep *model.Fail2banReport, in Input, how string, sc serverConfig, jc jailConfig, logErr error) []model.SystemFinding {
	var out []model.SystemFinding
	if !rep.Running {
		ev := []i18n.Msg{i18n.T("ev.f2b_installed", how), i18n.T("ev.f2b_no_process")}
		for _, e := range rep.Recent {
			if e.Action == "stop" {
				ev = append(ev, i18n.T("ev.f2b_last_stop", e.Time.Format("2006-01-02 15:04:05")))
				break
			}
		}
		out = append(out, model.SystemFinding{Finding: model.Finding{ID: "fail2ban_not_running", Title: i18n.T("rule.fail2ban_not_running.title"),
			Category: model.CatExposure, Weight: 10, Evidence: ev, Recommendation: i18n.T("rule.fail2ban_not_running.rec")}, Path: "/etc/fail2ban", Risk: model.RiskMedium})
	}

	// SSH из интернета без jail для SSH. Если конфигурация jail не
	// прочиталась (нет прав), вывод сделать нельзя.
	sshJail := false
	var names []string
	for _, j := range jc.Jails {
		names = append(names, j.Name)
		sshJail = sshJail || j.SSH()
	}
	if ssh, ok := publicSSH(in.Exposure); ok && !sshJail && len(jc.Files) > 0 {
		ev := []i18n.Msg{i18n.T("ev.f2b_ssh_public", exposure.Endpoint(ssh.Addr, ssh.Port), orUnknown(ssh.ProcName))}
		if len(names) > 0 {
			ev = append(ev, i18n.T("ev.f2b_jails", strings.Join(names, ", ")))
		} else {
			ev = append(ev, i18n.T("ev.f2b_no_jails"))
		}
		f := model.SystemFinding{Finding: model.Finding{ID: "fail2ban_sshd_disabled", Title: i18n.T("rule.fail2ban_sshd_disabled.title"),
			Category: model.CatExposure, Weight: 5, Evidence: ev, Recommendation: i18n.T("rule.fail2ban_sshd_disabled.rec")}, Path: "/etc/fail2ban/jail.local", Risk: model.RiskLow}
		if in.Allowed != nil && ssh.ProcKey != "" {
			for _, p := range in.Procs {
				if p.Key == ssh.ProcKey && in.Allowed(p, "fail2ban_sshd_disabled") {
					f.Suppressed, f.Risk = true, model.RiskInfo
				}
			}
		}
		out = append(out, f)
	}

	if !rep.LogAvailable {
		var ev i18n.Msg
		path, isFile := sc.logFile()
		switch {
		case !isFile:
			ev = i18n.T("ev.f2b_logtarget", sc.LogTarget)
		case errors.Is(logErr, fs.ErrNotExist):
			ev = i18n.T("ev.f2b_log_missing", path)
		default:
			ev = i18n.T("ev.f2b_log_unreadable", path, errText(logErr))
		}
		out = append(out, model.SystemFinding{Finding: model.Finding{ID: "fail2ban_log_unavailable", Title: i18n.T("rule.fail2ban_log_unavailable.title"),
			Category: model.CatInfo, Evidence: []i18n.Msg{ev}, Recommendation: i18n.T("rule.fail2ban_log_unavailable.rec")}, Path: "/etc/fail2ban/fail2ban.conf", Risk: model.RiskInfo})
	}
	return out
}

// publicSSH — слушающий SSH, доступный из интернета (порт 22 или процесс
// sshd на другом порту). Порты контейнеров не учитываются: их защищает
// fail2ban внутри контейнера, если он там есть.
func publicSSH(rep *model.ExposureReport) (model.Exposure, bool) {
	if rep == nil {
		return model.Exposure{}, false
	}
	for _, e := range rep.Entries {
		if e.Scope != model.ScopePublic || e.Docker != nil || !strings.HasPrefix(e.Proto, "tcp") {
			continue
		}
		if e.ProcName == "sshd" || (e.Port == 22 && e.ProcName != "docker-proxy") {
			return e, true
		}
	}
	return model.Exposure{}, false
}

func orUnknown(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func errText(err error) i18n.Msg {
	switch {
	case err == nil:
		return i18n.L("?")
	case errors.Is(err, safefile.ErrNotRegular):
		return i18n.T("ev.f2b_not_regular")
	case errors.Is(err, fs.ErrPermission):
		return i18n.T("ev.f2b_no_permission")
	}
	return i18n.L(err.Error())
}

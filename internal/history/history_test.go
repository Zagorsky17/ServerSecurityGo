package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func proc(pid int, key string, start time.Time, ticks uint64) *model.Process {
	return &model.Process{PID: pid, Key: key, Name: "p", User: "root", Exe: "/usr/bin/p", Cmdline: "p", StartTime: start, CPUTicks: ticks}
}

func types(evs []model.Event) map[string]int {
	m := map[string]int{}
	for _, e := range evs {
		m[e.Type]++
	}
	return m
}

func TestLifecycleEvents(t *testing.T) {
	s, err := Open(Options{CPUThreshold: 80, MemThreshold: 50})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	start := t0.Add(-100 * time.Second)

	// Первое сканирование — только baseline, без «started» для всех.
	a := proc(10, "10-1", start, 5000) // 50 с CPU за 100 с жизни = 50%
	s.Observe(t0, []*model.Process{a})
	ev := s.Record(t0, []*model.Process{a}, nil)
	if tp := types(ev); tp[model.EvBaseline] != 1 || tp[model.EvStarted] != 0 {
		t.Errorf("первое сканирование: %v", tp)
	}
	if !a.CPUAverage || a.CPUPercent < 49 || a.CPUPercent > 51 {
		t.Errorf("средний CPU: %.1f avg=%v", a.CPUPercent, a.CPUAverage)
	}
	if !a.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen = %v", a.FirstSeen)
	}

	// Второе: a нагрузил CPU на 100% за 10 с, появился b, у a сменилась cmdline.
	t1 := t0.Add(10 * time.Second)
	a2 := proc(10, "10-1", start, 6000)
	a2.Cmdline = "p --changed"
	a2.Risk = model.RiskMedium
	a2.Findings = []model.Finding{{ID: "exe_in_temp", Title: i18n.L("x"), Category: model.CatLocation, Weight: 15}}
	a2.Sockets = []model.Socket{{Proto: "tcp", State: "LISTEN", LocalAddr: "0.0.0.0", LocalPort: 31337}}
	b := proc(20, "20-5", t1, 0)
	s.Observe(t1, []*model.Process{a2, b})
	if a2.CPUAverage || a2.CPUPercent < 99 || a2.CPUPercent > 101 {
		t.Errorf("мгновенный CPU: %.1f", a2.CPUPercent)
	}
	if !a2.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen должен сохраниться: %v", a2.FirstSeen)
	}
	if c := s.Counters("10-1"); c.HighCPUScans != 1 {
		t.Errorf("счётчик CPU: %+v", c)
	}
	ev = s.Record(t1, []*model.Process{a2, b}, nil)
	tp := types(ev)
	for _, want := range []string{model.EvStarted, model.EvChanged, model.EvRiskUp, model.EvFinding, model.EvListen} {
		if tp[want] != 1 {
			t.Errorf("нет события %s: %v", want, tp)
		}
	}

	// Третье: a завершился.
	t2 := t1.Add(10 * time.Second)
	s.Observe(t2, []*model.Process{b})
	ev = s.Record(t2, []*model.Process{b}, nil)
	if tp := types(ev); tp[model.EvExited] != 1 {
		t.Errorf("нет exited: %v", tp)
	}
	if tr, ok := s.Track("10-1"); !ok || !tr.Exited {
		t.Error("трек завершённого процесса должен храниться до истечения retention")
	}
	if got := s.EventsFor("10-1"); len(got) < 4 {
		t.Errorf("события процесса: %d", len(got))
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p := proc(1, "1-1", now.Add(-time.Hour), 10)
	s.Observe(now, []*model.Process{p})
	s.Record(now, []*model.Process{p}, []model.SystemFinding{{Finding: model.Finding{ID: "ld_so_preload", Title: i18n.L("x")}, Path: "/etc/ld.so.preload", Risk: model.RiskHigh}})
	if err := s.Flush(now); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state.json: %v %v", fi, err)
	}

	// После «перезапуска» история сохраняется, baseline не повторяется,
	// системная находка не дублируется.
	s2, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Events(0)) != len(s.Events(0)) {
		t.Errorf("события не восстановлены: %d vs %d", len(s2.Events(0)), len(s.Events(0)))
	}
	later := now.Add(time.Minute)
	p2 := proc(1, "1-1", now.Add(-time.Hour), 20)
	s2.Observe(later, []*model.Process{p2})
	if !p2.FirstSeen.Equal(now) && p2.FirstSeen.Sub(now).Abs() > time.Second {
		t.Errorf("FirstSeen после перезапуска: %v", p2.FirstSeen)
	}
	ev := s2.Record(later, []*model.Process{p2}, []model.SystemFinding{{Finding: model.Finding{ID: "ld_so_preload"}, Path: "/etc/ld.so.preload", Risk: model.RiskHigh}})
	if tp := types(ev); tp[model.EvBaseline] != 0 || tp[model.EvSystem] != 0 {
		t.Errorf("лишние события после перезапуска: %v", tp)
	}
}

func TestCorruptStateAndRotation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, MaxEventsBytes: 200})
	if err != nil {
		t.Fatalf("повреждённый state.json не должен мешать запуску: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json.corrupt")); err != nil {
		t.Error("копия повреждённого файла не сохранена")
	}
	now := time.Now()
	for i := range 5 {
		ps := []*model.Process{proc(100+i, "k"+string(rune('a'+i)), now, 0)}
		s.Observe(now, ps)
		s.Record(now.Add(time.Duration(i)*time.Second), ps, nil)
	}
	if _, err := os.Stat(filepath.Join(dir, "events.jsonl.1")); err != nil {
		t.Error("ротация журнала не выполнена")
	}
}

func TestRetention(t *testing.T) {
	s, _ := Open(Options{Retention: time.Hour})
	now := time.Now()
	p := proc(1, "old", now, 0)
	s.Observe(now, []*model.Process{p})
	s.Record(now, []*model.Process{p}, nil)
	s.Record(now.Add(time.Minute), nil, nil) // завершился
	s.Record(now.Add(2*time.Hour), nil, nil) // прошло больше retention
	if _, ok := s.Track("old"); ok {
		t.Error("старый трек не удалён")
	}
}

// TestTrackCopyRace: копия трека не делит срезы с хранилищем. Раньше
// Record переписывал Findings на месте, а копию в это время кодировали в
// JSON — детектор гонок (go test -race) ловил это.
func TestTrackCopyRace(t *testing.T) {
	s, _ := Open(Options{})
	now := time.Now()
	p := proc(1, "k", now, 0)
	p.Findings = []model.Finding{{ID: "a", Category: model.CatLocation}, {ID: "b", Category: model.CatLocation}}
	s.Observe(now, []*model.Process{p})
	s.Record(now, []*model.Process{p}, nil)
	tr, _ := s.Track("k")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 200 {
			p.Findings = []model.Finding{{ID: fmt.Sprintf("c%d", i), Category: model.CatLocation}, {ID: "d", Category: model.CatLocation}}
			s.Record(now.Add(time.Duration(i)*time.Second), []*model.Process{p}, nil)
		}
	}()
	for range 200 {
		if _, err := json.Marshal(tr); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	if tr.Findings[0] != "a" || tr.Findings[1] != "b" {
		t.Errorf("копия изменилась вместе с хранилищем: %v", tr.Findings)
	}
}

// TestSystemFindingsBounded: событие системной находки — при появлении и
// при росте уровня; кратковременное исчезновение (перезапуск службы)
// события не даёт, а долго отсутствующая находка забывается, так что
// ключи не накапливаются.
func TestSystemFindingsBounded(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir})
	now := time.Now()
	tick := 0
	record := func(f ...model.SystemFinding) int {
		tick++
		n := 0
		for _, e := range s.Record(now.Add(time.Duration(tick)*time.Second), nil, f) {
			if e.Type == model.EvSystem {
				n++
			}
		}
		return n
	}
	sf := func(port int, r model.Risk) model.SystemFinding {
		return model.SystemFinding{Finding: model.Finding{ID: "exposed_database", Title: i18n.L("Redis")}, Path: fmt.Sprintf("%d/tcp", port), Risk: r}
	}
	if n := record(sf(6379, model.RiskLow)); n != 1 {
		t.Errorf("новая находка: %d событий", n)
	}
	if n := record(sf(6379, model.RiskLow)); n != 0 {
		t.Errorf("та же находка: %d событий", n)
	}
	// ufw выключили: тот же ключ, уровень вырос — событие.
	if n := record(sf(6379, model.RiskCritical)); n != 1 {
		t.Errorf("рост уровня: %d событий", n)
	}
	// Снижение уровня — без события.
	if n := record(sf(6379, model.RiskLow)); n != 0 {
		t.Errorf("снижение уровня: %d событий", n)
	}
	// Перезапуск службы: порт пропал на одно сканирование — без события.
	record()
	if n := record(sf(6379, model.RiskLow)); n != 0 {
		t.Errorf("после перезапуска: %d событий", n)
	}
	// Порт закрыли надолго, потом снова открыли — новое событие.
	for range systemForget {
		record()
	}
	if n := record(sf(6379, model.RiskLow)); n != 1 {
		t.Errorf("вернувшаяся находка: %d событий", n)
	}
	// Уровень переживает перезапуск службы.
	s2, _ := Open(Options{Dir: dir})
	if seen := s2.systemSet["exposed_database|6379/tcp"]; seen == nil || seen.risk != model.RiskLow {
		t.Errorf("после Open: %+v", seen)
	}
	// Тысяча разных портов по очереди: в памяти остаются лишь последние.
	for i := range 1000 {
		record(sf(10000+i, model.RiskHigh))
	}
	s.mu.RLock()
	n := len(s.systemSet)
	s.mu.RUnlock()
	if n > systemForget {
		t.Errorf("в systemSet %d ключей", n)
	}
}

// TestOldStateSystemRisk: state.json прошлой версии без systemRisk — после
// обновления известные находки не дают ложного события о росте уровня.
func TestOldStateSystemRisk(t *testing.T) {
	dir := t.TempDir()
	old := `{"version":1,"tracks":{"1-1":{"key":"1-1","pid":1,"lastSeen":"2026-10-01T00:00:00Z"}},"system":["ld_so_preload|/etc/ld.so.preload"]}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	evs := s.Record(time.Now(), nil, []model.SystemFinding{{Finding: model.Finding{ID: "ld_so_preload"}, Path: "/etc/ld.so.preload", Risk: model.RiskHigh}})
	for _, e := range evs {
		if e.Type == model.EvSystem {
			t.Errorf("ложное событие: %+v", e)
		}
	}
}

// TestRecordAudit: событие — когда проверка стала опасной (или хуже) и
// когда её исправили; советы и повторы событий не дают; статусы
// переживают перезапуск службы.
func TestRecordAudit(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir})
	now := time.Now()
	chk := func(id, st string, sev model.Risk) model.AuditCheck {
		return model.AuditCheck{ID: id, Title: i18n.L(id), Status: st, Severity: sev}
	}
	types := func(evs []model.Event) []string {
		var out []string
		for _, e := range evs {
			out = append(out, e.Name+":"+e.Risk.String())
		}
		return out
	}
	evs := s.RecordAudit(now, []model.AuditCheck{
		chk("ssh_password_auth", model.AuditFail, model.RiskHigh),
		chk("ssh_port", model.AuditInfo, model.RiskInfo),
		chk("ssh_x11", model.AuditWarn, model.RiskLow),
		chk("ssh_root", model.AuditPass, model.RiskHigh),
	})
	if got := types(evs); len(got) != 2 || got[0] != "ssh_password_auth:HIGH" || got[1] != "ssh_x11:LOW" {
		t.Errorf("первый запуск: %v", got)
	}
	if evs[0].Type != model.EvAudit || !strings.Contains(evs[0].Details.String(), "опасно") {
		t.Errorf("событие: %+v", evs[0])
	}
	// Без изменений — тишина; warn → fail — событие; fail → pass — «исправлено».
	if evs := s.RecordAudit(now, []model.AuditCheck{chk("ssh_password_auth", model.AuditFail, model.RiskHigh), chk("ssh_x11", model.AuditWarn, model.RiskLow)}); len(evs) != 0 {
		t.Errorf("повтор: %v", types(evs))
	}
	evs = s.RecordAudit(now, []model.AuditCheck{chk("ssh_password_auth", model.AuditPass, model.RiskHigh), chk("ssh_x11", model.AuditFail, model.RiskLow)})
	if got := types(evs); len(got) != 2 || got[0] != "ssh_password_auth:INFO" || got[1] != "ssh_x11:LOW" {
		t.Errorf("исправлено/хуже: %v", got)
	}
	if !strings.Contains(evs[0].Details.String(), "исправлено") {
		t.Errorf("текст: %s", evs[0].Details)
	}
	// После перезапуска состояние восстанавливается — повторных событий нет.
	s2, _ := Open(Options{Dir: dir})
	if evs := s2.RecordAudit(now, []model.AuditCheck{chk("ssh_password_auth", model.AuditPass, model.RiskHigh), chk("ssh_x11", model.AuditFail, model.RiskLow)}); len(evs) != 0 {
		t.Errorf("после перезапуска: %v", types(evs))
	}
	// Пропавшие проверки забываются.
	s2.RecordAudit(now, []model.AuditCheck{chk("ssh_x11", model.AuditFail, model.RiskLow)})
	s2.mu.RLock()
	n := len(s2.auditSet)
	s2.mu.RUnlock()
	if n != 1 {
		t.Errorf("auditSet: %d", n)
	}
}

// TestRecordAuditChangeCheck: проверка изменений, вернувшаяся в pass
// (изменение устарело), не даёт события «исправлено».
func TestRecordAuditChangeCheck(t *testing.T) {
	s, _ := Open(Options{})
	now := time.Now()
	c := model.AuditCheck{ID: "acct_new", Title: i18n.L("new"), Status: model.AuditFail, Severity: model.RiskHigh, Change: true}
	if evs := s.RecordAudit(now, []model.AuditCheck{c}); len(evs) != 1 {
		t.Fatalf("событие о новом пользователе: %d", len(evs))
	}
	c.Status = model.AuditPass
	if evs := s.RecordAudit(now, []model.AuditCheck{c}); len(evs) != 0 {
		t.Errorf("«исправлено» для устаревшего изменения: %+v", evs)
	}
}

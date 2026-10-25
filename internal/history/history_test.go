package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// Пакет history хранит историю процессов между сканированиями.
//
// Что хранится:
//   - треки процессов (Track): первое/последнее наблюдение, последние
//     известные exe/cmdline/риск, счётчики длительной нагрузки, тики CPU
//     для расчёта мгновенной загрузки;
//   - журнал событий (появление, завершение, изменение, рост риска,
//     новые признаки, новые слушающие порты).
//
// Хранение без внешних зависимостей: state.json (снимок треков,
// записывается атомарно через временный файл и rename) и events.jsonl
// (журнал событий в формате JSON Lines с ротацией по размеру).
// Если каталог не задан, всё живёт только в памяти (демо, разовый scan).
package history

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
)

// Track — накопленные сведения об одном экземпляре процесса.
type Track struct {
	Key          string     `json:"key"`
	PID          int        `json:"pid"`
	Name         string     `json:"name"`
	User         string     `json:"user"`
	Exe          string     `json:"exe"`
	Cmdline      string     `json:"cmdline"`
	FirstSeen    time.Time  `json:"firstSeen"`
	LastSeen     time.Time  `json:"lastSeen"`
	Risk         model.Risk `json:"risk"`
	Findings     []string   `json:"findings"`
	Listen       []string   `json:"listen"`
	HighCPUScans int        `json:"highCpuScans"`
	HighMemScans int        `json:"highMemScans"`
	CPUTicks     uint64     `json:"cpuTicks"`
	SampleTime   time.Time  `json:"sampleTime"`
	Exited       bool       `json:"exited"`
}

// Options — настройки хранилища.
type Options struct {
	Dir            string        // каталог данных; пусто — только память
	Retention      time.Duration // сколько хранить треки завершённых процессов
	MaxEventsBytes int64         // размер events.jsonl до ротации
	MemoryEvents   int           // сколько последних событий держать в памяти
	CPUThreshold   float64
	MemThreshold   float64
}

// Store — хранилище истории. Безопасно для конкурентного использования.
type Store struct {
	mu        sync.RWMutex
	opt       Options
	tracks    map[string]*Track
	events    []model.Event
	baseline  bool // треки уже были (после рестарта не пишем «started» для всех)
	dirty     bool
	lastSave  time.Time
	systemSet map[string]*sysSeen // системные находки по ключу «ID|Path»
}

// sysSeen — что известно о системной находке между сканированиями.
type sysSeen struct {
	risk model.Risk // последний уровень
	miss int        // сколько сканирований подряд находки не было
}

// systemForget — через сколько сканирований без находки она забывается.
// Небольшой запас нужен, чтобы перезапуск службы (порт пропал на одно
// сканирование) не давал повторного события, а память не росла: ключи
// пропавших находок удаляются.
const systemForget = 3

type stateFile struct {
	Version int               `json:"version"`
	Saved   time.Time         `json:"saved"`
	Tracks  map[string]*Track `json:"tracks"`
	System  []string          `json:"system"`
	// SystemRisk — уровень системных находок (с версии с открытыми
	// портами). В старом state.json его нет.
	SystemRisk map[string]model.Risk `json:"systemRisk,omitempty"`
}

// Open открывает (или создаёт) хранилище.
func Open(opt Options) (*Store, error) {
	if opt.Retention <= 0 {
		opt.Retention = 7 * 24 * time.Hour
	}
	if opt.MaxEventsBytes <= 0 {
		opt.MaxEventsBytes = 20 << 20
	}
	if opt.MemoryEvents <= 0 {
		opt.MemoryEvents = 5000
	}
	s := &Store{opt: opt, tracks: map[string]*Track{}, systemSet: map[string]*sysSeen{}}
	if opt.Dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(opt.Dir, 0o700); err != nil {
		return nil, i18n.Errorf("err.data_dir", err)
	}
	if data, err := os.ReadFile(s.statePath()); err == nil {
		var st stateFile
		if err := json.Unmarshal(data, &st); err != nil {
			// Повреждённый файл не должен мешать запуску: сохраняем копию
			// для разбора и начинаем с чистого листа.
			_ = os.Rename(s.statePath(), s.statePath()+".corrupt")
		} else {
			if st.Tracks != nil {
				s.tracks = st.Tracks
			}
			for _, k := range st.System {
				// Уровень неизвестен (старый state.json) — считаем
				// наивысшим, чтобы после обновления не было ложного
				// события о росте уровня.
				r, ok := st.SystemRisk[k]
				if !ok {
					r = model.RiskCritical
				}
				s.systemSet[k] = &sysSeen{risk: r}
			}
			s.baseline = len(s.tracks) > 0
		}
	}
	s.loadEvents()
	return s, nil
}

func (s *Store) statePath() string  { return filepath.Join(s.opt.Dir, "state.json") }
func (s *Store) eventsPath() string { return filepath.Join(s.opt.Dir, "events.jsonl") }

// loadEvents читает хвост журнала событий в память.
func (s *Store) loadEvents() {
	f, err := os.Open(s.eventsPath())
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e model.Event
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			s.events = append(s.events, e)
			if len(s.events) > s.opt.MemoryEvents*2 {
				s.events = slices.Clone(s.events[len(s.events)-s.opt.MemoryEvents:])
			}
		}
	}
	if len(s.events) > s.opt.MemoryEvents {
		s.events = s.events[len(s.events)-s.opt.MemoryEvents:]
	}
}

// Observe вызывается до анализа: считает CPU%, проставляет время
// первого/последнего наблюдения и обновляет счётчики нагрузки.
func (s *Store) Observe(now time.Time, procs []*model.Process) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range procs {
		t := s.tracks[p.Key]
		if t == nil || t.Exited {
			if t == nil {
				t = &Track{Key: p.Key, PID: p.PID, FirstSeen: now}
			}
			// Первое наблюдение: мгновенного значения нет, берём среднее
			// с момента запуска процесса.
			if life := now.Sub(p.StartTime).Seconds(); life > 0 && !p.StartTime.IsZero() {
				p.CPUPercent = float64(p.CPUTicks) / procfs.ClockTicks / life * 100
			}
			p.CPUAverage = true
		} else if dt := now.Sub(t.SampleTime).Seconds(); dt > 0 && p.CPUTicks >= t.CPUTicks {
			p.CPUPercent = float64(p.CPUTicks-t.CPUTicks) / procfs.ClockTicks / dt * 100
		}
		if p.CPUPercent >= s.opt.CPUThreshold && s.opt.CPUThreshold > 0 {
			t.HighCPUScans++
		} else {
			t.HighCPUScans = 0
		}
		if p.MemPercent >= s.opt.MemThreshold && s.opt.MemThreshold > 0 {
			t.HighMemScans++
		} else {
			t.HighMemScans = 0
		}
		t.CPUTicks, t.SampleTime = p.CPUTicks, now
		p.FirstSeen, p.LastSeen = t.FirstSeen, now
		if s.tracks[p.Key] == nil {
			// Новый трек фиксируется в Record, чтобы сгенерировать событие.
			s.pending(t)
		}
	}
}

// pending временно хранит новый трек в карте с пометкой Exited=false,
// но без LastSeen — Record отличит его по нулевому LastSeen.
func (s *Store) pending(t *Track) { s.tracks[t.Key] = t }

// Counters возвращает счётчики для правил поведения.
func (s *Store) Counters(key string) detect.Counters {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t := s.tracks[key]; t != nil {
		return detect.Counters{HighCPUScans: t.HighCPUScans, HighMemScans: t.HighMemScans}
	}
	return detect.Counters{}
}

// Record вызывается после анализа: генерирует события, обновляет треки,
// помечает завершённые процессы и сохраняет состояние.
func (s *Store) Record(now time.Time, procs []*model.Process, system []model.SystemFinding) []model.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var evs []model.Event
	first := !s.baseline
	alive := make(map[string]bool, len(procs))
	newCount := 0

	for _, p := range procs {
		alive[p.Key] = true
		t := s.tracks[p.Key]
		if t == nil { // Observe не вызывался для этого процесса
			t = &Track{Key: p.Key, PID: p.PID, FirstSeen: now}
			s.tracks[p.Key] = t
		}
		isNew := t.LastSeen.IsZero()
		listen := listenList(p)
		findings := activeFindings(p)
		base := model.Event{Time: now, Key: p.Key, PID: p.PID, Name: p.Name, User: p.User, Exe: p.Exe, Risk: p.Risk}

		switch {
		case isNew && !first:
			newCount++
			e := base
			e.Type = model.EvStarted
			if p.PPID > 0 {
				e.Details = i18n.T("hist.started_parent", truncate(p.Cmdline, 200), p.PPID)
			} else {
				e.Details = i18n.T("hist.started", truncate(p.Cmdline, 200))
			}
			evs = append(evs, e)
		case !isNew:
			var ch []i18n.Msg
			if t.Exe != p.Exe {
				ch = append(ch, i18n.L(fmt.Sprintf("exe: %s → %s", t.Exe, p.Exe)))
			}
			if t.Cmdline != p.Cmdline {
				ch = append(ch, i18n.L(fmt.Sprintf("cmdline: %s → %s", truncate(t.Cmdline, 120), truncate(p.Cmdline, 120))))
			}
			if t.User != p.User {
				ch = append(ch, i18n.T("hist.user_changed", t.User, p.User))
			}
			if len(ch) > 0 {
				e := base
				e.Type = model.EvChanged
				e.Details = i18n.Join("; ", ch...)
				evs = append(evs, e)
			}
			if p.Risk > t.Risk {
				e := base
				e.Type = model.EvRiskUp
				e.Details = i18n.T("hist.risk", t.Risk, p.Risk)
				evs = append(evs, e)
			} else if p.Risk < t.Risk {
				e := base
				e.Type = model.EvRiskDown
				e.Details = i18n.T("hist.risk", t.Risk, p.Risk)
				evs = append(evs, e)
			}
		}
		// Новые признаки и порты — и для новых процессов при первом
		// сканировании (чтобы в истории было видно исходное состояние
		// подозрительных процессов), и для уже известных.
		for _, fid := range findings {
			if !slices.Contains(t.Findings, fid.id) && (p.Risk >= model.RiskLow) {
				e := base
				e.Type = model.EvFinding
				e.Details = i18n.T("hist.finding", fid.title)
				evs = append(evs, e)
			}
		}
		if !isNew || !first {
			for _, l := range listen {
				if !slices.Contains(t.Listen, l) {
					e := base
					e.Type = model.EvListen
					e.Details = i18n.T("hist.listen", l)
					evs = append(evs, e)
				}
			}
		}

		t.PID, t.Name, t.User, t.Exe, t.Cmdline = p.PID, p.Name, p.User, p.Exe, p.Cmdline
		t.Risk, t.LastSeen, t.Exited = p.Risk, now, false
		t.Listen = listen
		t.Findings = t.Findings[:0]
		for _, f := range findings {
			t.Findings = append(t.Findings, f.id)
		}
	}

	// Завершившиеся процессы.
	for k, t := range s.tracks {
		if alive[k] || t.Exited {
			continue
		}
		t.Exited = true
		evs = append(evs, model.Event{Time: now, Type: model.EvExited, Key: k, PID: t.PID, Name: t.Name, User: t.User, Exe: t.Exe, Risk: t.Risk,
			Details: i18n.T("hist.exited", t.FirstSeen.Format("2006-01-02 15:04:05"))})
	}
	// Удаляем старые треки завершённых процессов.
	for k, t := range s.tracks {
		if t.Exited && now.Sub(t.LastSeen) > s.opt.Retention {
			delete(s.tracks, k)
		}
	}

	// Системные находки: событие при появлении и при росте уровня (Redis
	// был закрыт ufw — LOW, ufw выключили — CRITICAL с тем же ключом).
	// Находка, которой нет systemForget сканирований подряд, забывается:
	// иначе ключи копились бы всё время работы службы (порты приходят и
	// уходят), а вернувшаяся находка — новое событие.
	present := make(map[string]bool, len(system))
	for _, sf := range system {
		k := sf.ID + "|" + sf.Path
		present[k] = true
		seen := s.systemSet[k]
		if (seen == nil || sf.Risk > seen.risk) && sf.Risk >= model.RiskLow {
			evs = append(evs, model.Event{Time: now, Type: model.EvSystem, Exe: sf.Path, Risk: sf.Risk, Details: i18n.T("hist.system", sf.Title, sf.Path)})
		}
		if seen == nil {
			seen = &sysSeen{}
			s.systemSet[k] = seen
		}
		if seen.risk != sf.Risk {
			s.dirty = true
		}
		seen.risk, seen.miss = sf.Risk, 0
	}
	for k, seen := range s.systemSet {
		if present[k] {
			continue
		}
		if seen.miss++; seen.miss >= systemForget {
			delete(s.systemSet, k)
			s.dirty = true
		}
	}

	if first {
		evs = append([]model.Event{{Time: now, Type: model.EvBaseline,
			Details: i18n.T("hist.baseline", len(procs))}}, evs...)
		s.baseline = true
	}
	s.appendEvents(evs)
	if len(evs) > 0 {
		s.dirty = true
	}
	// Состояние пишем при изменениях, но не реже раза в 5 минут (чтобы
	// LastSeen не устаревал сильно после перезапуска).
	if s.opt.Dir != "" && (s.dirty || now.Sub(s.lastSave) > 5*time.Minute) {
		if err := s.save(now); err == nil {
			s.dirty, s.lastSave = false, now
		}
	}
	return evs
}

type fidTitle struct {
	id    string
	title i18n.Msg
}

func activeFindings(p *model.Process) []fidTitle {
	var out []fidTitle
	for _, f := range p.Findings {
		if !f.Suppressed && f.Category != model.CatInfo {
			out = append(out, fidTitle{f.ID, f.Title})
		}
	}
	return out
}

func listenList(p *model.Process) []string {
	var out []string
	for _, s := range p.Sockets {
		if s.State == "LISTEN" && s.Proto != "unix" {
			out = append(out, fmt.Sprintf("%s %s:%d", s.Proto, s.LocalAddr, s.LocalPort))
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// appendEvents добавляет события в память и в файл журнала.
func (s *Store) appendEvents(evs []model.Event) {
	if len(evs) == 0 {
		return
	}
	s.events = append(s.events, evs...)
	if over := len(s.events) - s.opt.MemoryEvents; over > 0 {
		s.events = slices.Clone(s.events[over:])
	}
	if s.opt.Dir == "" {
		return
	}
	s.rotateIfNeeded()
	f, err := os.OpenFile(s.eventsPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, e := range evs {
		_ = enc.Encode(e)
	}
	_ = w.Flush()
}

// rotateIfNeeded переименовывает журнал в events.jsonl.1, если он
// превысил лимит. Хранится одна предыдущая копия.
func (s *Store) rotateIfNeeded() {
	fi, err := os.Stat(s.eventsPath())
	if err != nil || fi.Size() < s.opt.MaxEventsBytes {
		return
	}
	_ = os.Rename(s.eventsPath(), s.eventsPath()+".1")
}

// save атомарно записывает state.json.
func (s *Store) save(now time.Time) error {
	st := stateFile{Version: 1, Saved: now, Tracks: s.tracks}
	st.SystemRisk = make(map[string]model.Risk, len(s.systemSet))
	for k, seen := range s.systemSet {
		st.System = append(st.System, k)
		st.SystemRisk[k] = seen.risk
	}
	sort.Strings(st.System)
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.opt.Dir, ".state-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.statePath())
}

// Flush принудительно сохраняет состояние (при остановке службы).
func (s *Store) Flush(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opt.Dir == "" {
		return nil
	}
	return s.save(now)
}

// Events возвращает последние события (новые в конце), не более limit.
func (s *Store) Events(limit int) []model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ev := s.events
	if limit > 0 && len(ev) > limit {
		ev = ev[len(ev)-limit:]
	}
	return slices.Clone(ev)
}

// EventsFor возвращает события конкретного процесса.
func (s *Store) EventsFor(key string) []model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Event
	for _, e := range s.events {
		if e.Key == key {
			out = append(out, e)
		}
	}
	return out
}

// Track возвращает копию трека. Срезы копируются тоже: Record
// переписывает Findings того же трека на месте (t.Findings[:0] + append),
// а копию веб-обработчик кодирует в JSON уже без блокировки — общий
// массив дал бы гонку данных (в Go гонка на строках может закончиться
// чтением «разорванной» строки и паникой).
func (s *Store) Track(key string) (Track, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tracks[key]
	if !ok {
		return Track{}, false
	}
	c := *t
	c.Findings = slices.Clone(t.Findings)
	c.Listen = slices.Clone(t.Listen)
	return c, true
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

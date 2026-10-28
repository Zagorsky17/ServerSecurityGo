package metrics

import (
	"sort"
	"time"
)

// Имена рядов. Это публичный API (/api/metrics) и ключи в metrics.json,
// поэтому переименование ломает совместимость.
const (
	KeyCPU       = "cpu"        // занятость процессора, %
	KeyCPUUser   = "cpu_user"   // %
	KeyCPUSystem = "cpu_system" // %
	KeyCPUIOWait = "cpu_iowait" // %
	KeySteal     = "steal"      // %
	KeyLoad1     = "load1"      // средняя нагрузка за минуту
	KeyMem       = "mem"        // занято памяти, %
	KeySwap      = "swap"       // занято swap, %
	KeySwapUsed  = "swap_used"  // занято swap, МБ (для признака роста)
	KeyDiskRead  = "disk_read"  // МБ/с по всем устройствам
	KeyDiskWrite = "disk_write" // МБ/с
	KeyDiskBusy  = "disk_busy"  // самое загруженное устройство, %
	KeyDiskFull  = "disk_full"  // самый заполненный раздел, %
	KeyNetRx     = "net_rx"     // МБ/с
	KeyNetTx     = "net_tx"     // МБ/с
	KeyPPSIn     = "pps_in"     // пакетов/с
	KeyPPSOut    = "pps_out"    // пакетов/с
	KeyPSICPU    = "psi_cpu"    // %
	KeyPSIMem    = "psi_mem"    // %
	KeyPSIIO     = "psi_io"     // %
)

// Окна хранения. Детализация понижается: за час видно каждый замер, за
// сутки — минуты, за месяц — четверти часа. Для каждой точки хранятся
// среднее и максимум, иначе короткий всплеск steal исчез бы при
// усреднении.
const (
	RangeHour  = "1h"
	RangeDay   = "24h"
	RangeMonth = "30d"
)

const (
	stepMin1  = time.Minute
	stepMin15 = 15 * time.Minute
	capMin1   = 1440 // сутки по минуте
	// capRaw — час сырых замеров при интервале 5 с; при меньшем
	// интервале окно короче, при большем — длиннее, память ограничена
	// числом точек.
	capRaw = 720
)

// Point — точка ряда: среднее и максимум за шаг.
type Point struct {
	T   time.Time `json:"t"`
	Avg float64   `json:"avg"`
	Max float64   `json:"max"`
}

// ring — кольцевой буфер точек: старые вытесняются новыми.
type ring struct {
	pts  []Point
	next int
	full bool
}

func newRing(n int) *ring { return &ring{pts: make([]Point, 0, n)} }

func (r *ring) push(p Point) {
	if cap(r.pts) == 0 {
		return
	}
	if !r.full {
		r.pts = append(r.pts, p)
		if len(r.pts) == cap(r.pts) {
			r.full, r.next = true, 0
		}
		return
	}
	r.pts[r.next] = p
	r.next = (r.next + 1) % len(r.pts)
}

// all возвращает точки в порядке времени (копию: вызывающий отдаёт её
// в JSON, пока сборщик продолжает писать).
func (r *ring) all() []Point {
	if !r.full {
		return append([]Point(nil), r.pts...)
	}
	out := make([]Point, 0, len(r.pts))
	out = append(out, r.pts[r.next:]...)
	return append(out, r.pts[:r.next]...)
}

// load заполняет буфер сохранёнными точками (самые новые — последние).
func (r *ring) load(pts []Point) {
	sort.SliceStable(pts, func(i, j int) bool { return pts[i].T.Before(pts[j].T) })
	if n := cap(r.pts); len(pts) > n {
		pts = pts[len(pts)-n:]
	}
	for _, p := range pts {
		r.push(p)
	}
}

// acc — накопитель одного шага агрегации.
type acc struct {
	start time.Time
	sum   float64
	n     int
	max   float64
}

func (a *acc) add(t time.Time, v float64, step time.Duration) (Point, bool) {
	// Границы шага выравниваются по часам: точки разных перезапусков
	// службы складываются в одну сетку.
	slot := t.Truncate(step)
	var done Point
	ok := false
	if a.n > 0 && !slot.Equal(a.start) {
		done, ok = Point{T: a.start, Avg: a.sum / float64(a.n), Max: a.max}, true
		a.sum, a.n, a.max = 0, 0, 0
	}
	if a.n == 0 {
		a.start = slot
	}
	a.sum += v
	a.n++
	if v > a.max {
		a.max = v
	}
	return done, ok
}

// metricSeries — один ряд во всех трёх детализациях.
type metricSeries struct {
	raw, min1, min15 *ring
	acc1, acc15      acc
}

func newMetricSeries(capMonth int) *metricSeries {
	return &metricSeries{raw: newRing(capRaw), min1: newRing(capMin1), min15: newRing(capMonth)}
}

func (m *metricSeries) add(t time.Time, v float64) {
	m.raw.push(Point{T: t, Avg: v, Max: v})
	if p, ok := m.acc1.add(t, v, stepMin1); ok {
		m.min1.push(p)
	}
	if p, ok := m.acc15.add(t, v, stepMin15); ok {
		m.min15.push(p)
	}
}

// points возвращает ряд для окна.
func (m *metricSeries) points(rng string) []Point {
	switch rng {
	case RangeDay:
		return m.min1.all()
	case RangeMonth:
		return m.min15.all()
	}
	return m.raw.all()
}

// last возвращает последнюю точку минутного ряда не новее чем ago
// назад (для признаков вида «swap растёт»). ok = false — таких данных
// ещё нет.
func (m *metricSeries) back(now time.Time, ago time.Duration) (Point, bool) {
	want := now.Add(-ago)
	pts := m.min1.all()
	for i := len(pts) - 1; i >= 0; i-- {
		if !pts[i].T.After(want) {
			return pts[i], true
		}
	}
	return Point{}, false
}

// StepSeconds — шаг точек окна в секундах (для подписи графика).
func StepSeconds(rng string, interval time.Duration) float64 {
	switch rng {
	case RangeDay:
		return stepMin1.Seconds()
	case RangeMonth:
		return stepMin15.Seconds()
	}
	return interval.Seconds()
}

// ValidRange приводит имя окна к известному (по умолчанию — час).
func ValidRange(s string) string {
	switch s {
	case RangeDay, RangeMonth:
		return s
	}
	return RangeHour
}

// values раскладывает замер в именованные ряды. Ряды по ядрам,
// устройствам и интерфейсам по отдельности не хранятся: на сервере с 64
// ядрами это в десятки раз больше памяти, а в интерфейсе по ним нужны
// только текущие значения.
//
// shortcut: только суммарные ряды, без разбивки по устройствам; если
// понадобится «какой диск тормозил ночью» — добавить ряды с префиксом.
func (s *Sample) values() map[string]float64 {
	v := map[string]float64{
		KeyCPU:       s.CPU.Busy,
		KeyCPUUser:   s.CPU.User,
		KeyCPUSystem: s.CPU.System,
		KeyCPUIOWait: s.CPU.IOWait,
		KeySteal:     s.CPU.Steal,
		KeyLoad1:     s.Load.One,
		KeyMem:       s.Mem.Percent,
		KeySwap:      s.Mem.SwapPct,
		KeySwapUsed:  float64(s.Mem.SwapUsed) / (1 << 20),
	}
	for _, d := range s.Disks {
		v[KeyDiskRead] += d.ReadMBs
		v[KeyDiskWrite] += d.WriteMBs
		v[KeyDiskBusy] = max(v[KeyDiskBusy], d.BusyPct)
	}
	for _, n := range s.Nets {
		v[KeyNetRx] += n.RxMBs
		v[KeyNetTx] += n.TxMBs
		v[KeyPPSIn] += n.RxPPS
		v[KeyPPSOut] += n.TxPPS
	}
	for _, p := range s.Parts {
		v[KeyDiskFull] = max(v[KeyDiskFull], p.Percent)
	}
	if p := s.PSI; p != nil {
		v[KeyPSICPU], v[KeyPSIMem], v[KeyPSIIO] = p.CPU, p.Mem, p.IO
	}
	return v
}

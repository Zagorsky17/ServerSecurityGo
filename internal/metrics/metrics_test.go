package metrics

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

const statText = `cpu  1000 100 500 8000 200 10 20 160 5 0
cpu0 500 50 250 4000 100 5 10 80 2 0
cpu1 500 50 250 4000 100 5 10 80 3 0
intr 1 2 3
btime 1700000000
processes 1234
`

func TestParseStat(t *testing.T) {
	total, cores := ParseStat(statText)
	if total.User != 1000 || total.Idle != 8000 || total.Steal != 160 {
		t.Fatalf("итог: %+v", total)
	}
	if len(cores) != 2 || cores[1].Steal != 80 {
		t.Fatalf("ядра: %+v", cores)
	}
	// guest (5) не прибавляется повторно: он уже внутри user.
	if got := total.Total(); got != 1000+100+500+8000+200+10+20+160 {
		t.Errorf("всего времени: %v", got)
	}
	if got := total.Busy(); got != 1000+100+500+10+20+160 {
		t.Errorf("занято: %v", got)
	}
	// Старое ядро без steal: не должно быть паники, steal = 0.
	old, _ := ParseStat("cpu  10 0 5 100\n")
	if old.Steal != 0 || old.Idle != 100 {
		t.Errorf("старый формат: %+v", old)
	}
	// Проценты за интервал.
	next, _ := ParseStat("cpu  1100 100 500 8400 200 10 20 200 5 0\n")
	p := next.sub(total).percent()
	// Прирост: user 100, idle 400, steal 40 — всего 540.
	if got := round1(p.Steal); got != "7.4" {
		t.Errorf("steal: %s", got)
	}
	if got := round1(p.Busy); got != "25.9" {
		t.Errorf("занято: %s", got)
	}
	// Сброс счётчиков (перезагрузка) не даёт отрицательных значений.
	if d := total.sub(next); d.User != 0 || d.Steal != 0 {
		t.Errorf("сброс счётчика: %+v", d)
	}
}

func TestParseLoadAndMem(t *testing.T) {
	l, ok := ParseLoadAvg("1.25 0.80 0.44 3/412 9876\n")
	if !ok || l.One != 1.25 || l.Running != 3 || l.Tasks != 412 {
		t.Fatalf("loadavg: %+v %v", l, ok)
	}
	if _, ok := ParseLoadAvg("нет данных"); ok {
		t.Error("мусор разобрался как loadavg")
	}
	m := ParseMeminfo("MemTotal:  4000000 kB\nMemFree:  100000 kB\nMemAvailable: 1500000 kB\nBuffers: 50000 kB\nCached:  900000 kB\nSwapTotal: 1000000 kB\nSwapFree: 400000 kB\n")
	if m.Total != 4000000 || m.Available != 1500000 || m.SwapFree != 400000 {
		t.Fatalf("meminfo: %+v", m)
	}
	// Без MemAvailable (старое ядро) — оценка из free + cached + buffers.
	old := ParseMeminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 20 kB\nCached: 300 kB\n")
	if old.Available != 420 {
		t.Errorf("без MemAvailable: %d", old.Available)
	}
}

func TestParsePressure(t *testing.T) {
	a10, a60, ok := ParsePressure("some avg10=12.34 avg60=5.67 avg300=1.00 total=123\nfull avg10=1.00 avg60=0.50 avg300=0.10 total=12\n")
	if !ok || a10 != 12.34 || a60 != 5.67 {
		t.Fatalf("PSI: %v %v %v", a10, a60, ok)
	}
	if _, _, ok := ParsePressure("full avg10=1.00\n"); ok {
		t.Error("без строки some PSI не считается прочитанным")
	}
}

func TestParseDiskstats(t *testing.T) {
	data := ` 253       0 vda 1000 0 50000 500 2000 0 80000 1500 0 9000 2000
 253       1 vda1 900 0 49000 480 1900 0 79000 1400 0 8800 1900
 259       0 nvme0n1 10 0 100 10 20 0 200 20 0 300 40
 259       1 nvme0n1p1 5 0 50 5 10 0 100 10 0 150 20
   7       0 loop0 1 0 2 0 0 0 0 0 0 0 0
`
	got := ParseDiskstats(data)
	if len(got) != 2 || got[0].Name != "vda" || got[1].Name != "nvme0n1" {
		t.Fatalf("устройства: %+v", got)
	}
	if got[0].ReadSectors != 50000 || got[0].WriteSectors != 80000 || got[0].IOTicks != 9000 {
		t.Errorf("счётчики vda: %+v", got[0])
	}
}

func TestParseNetDev(t *testing.T) {
	data := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0
  eth0: 5000 50 1 2 0 0 0 0 7000 70 3 4 0 0 0 0
`
	got := ParseNetDev(data)
	if len(got) != 1 || got[0].Name != "eth0" {
		t.Fatalf("интерфейсы: %+v", got)
	}
	if got[0].RxBytes != 5000 || got[0].RxDrop != 2 || got[0].TxPackets != 70 || got[0].TxDrop != 4 {
		t.Errorf("счётчики eth0: %+v", got[0])
	}
}

func TestParseMounts(t *testing.T) {
	data := `/dev/vda1 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/vdb1 /var ext4 rw 0 0
/dev/vdb1 /var/lib/docker/volumes ext4 rw 0 0
/dev/vdc1 /mnt/с\040пробелом ext4 rw 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0
nfs-server:/export /mnt/nfs nfs4 rw 0 0
`
	got := ParseMounts(data)
	if len(got) != 3 {
		t.Fatalf("разделы: %+v", got)
	}
	// Одно устройство — один раздел, остаётся самый короткий путь.
	if got[1].Point != "/var" {
		t.Errorf("повтор устройства: %+v", got[1])
	}
	if got[2].Point != "/mnt/с пробелом" {
		t.Errorf("пробел в пути: %q", got[2].Point)
	}
	for _, m := range got {
		if m.FSType == "nfs4" || m.FSType == "overlay" || m.FSType == "tmpfs" {
			t.Errorf("лишняя файловая система: %+v", m)
		}
	}
}

func TestParseKeyValueAndUptime(t *testing.T) {
	if v, ok := ParseKeyValue("nr_free 10\noom_kill 7\n", "oom_kill"); !ok || v != 7 {
		t.Errorf("oom_kill: %v %v", v, ok)
	}
	if _, ok := ParseKeyValue("oom_kill x\n", "oom_kill"); ok {
		t.Error("нечисловое значение принято")
	}
	if v := ParseUptime("12345.67 98765.43\n"); v != 12345.67 {
		t.Errorf("uptime: %v", v)
	}
	if v := ParseUptime("-1"); v != 0 {
		t.Errorf("отрицательный uptime: %v", v)
	}
}

// fakeProc — поддельный /proc с нужными файлами.
func fakeProc(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeProcFiles(t, root, files)
	return root
}

func writeProcFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// baseFiles — минимальный набор файлов /proc для сборщика.
func baseFiles() map[string]string {
	return map[string]string{
		"stat":        statText,
		"loadavg":     "0.50 0.40 0.30 1/200 500\n",
		"meminfo":     "MemTotal: 4000000 kB\nMemFree: 500000 kB\nMemAvailable: 2000000 kB\nCached: 800000 kB\nSwapTotal: 1000000 kB\nSwapFree: 1000000 kB\n",
		"uptime":      "10000.00 20000.00\n",
		"diskstats":   " 253 0 vda 1000 0 50000 500 2000 0 80000 1500 0 9000 2000\n",
		"net/dev":     "Inter-|\n face |\n  eth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\n",
		"vmstat":      "oom_kill 1\n",
		"cpuinfo":     "flags\t\t: fpu hypervisor\n",
		"self/mounts": "/dev/vda1 / ext4 rw 0 0\n",
	}
}

func usage(total, free uint64) func(string) (Usage, error) {
	return func(string) (Usage, error) {
		return Usage{Total: total, Free: free, Inodes: 1000, InodesFree: 800}, nil
	}
}

// TestCollectRates: второй замер даёт проценты и скорости по разнице
// счётчиков, первый — средние с загрузки.
func TestCollectRates(t *testing.T) {
	root := fakeProc(t, baseFiles())
	c := New(Options{ProcRoot: root, HostRoot: "/", Interval: time.Second, DiskUsage: usage(100<<30, 50<<30), Logger: quietLogger()})
	t0 := time.Now()
	s1, err := c.Collect(t0)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Average {
		t.Error("первый замер должен быть помечен как средний с загрузки")
	}
	if !s1.VM {
		t.Error("флаг hypervisor в cpuinfo — виртуальная машина")
	}
	if s1.NumCPU != 2 || len(s1.Cores) != 2 {
		t.Errorf("ядра: %d %+v", s1.NumCPU, s1.Cores)
	}
	if got := round1(s1.Mem.Percent); got != "50.0" {
		t.Errorf("память: %s", got)
	}
	if len(s1.Parts) != 1 || round1(s1.Parts[0].Percent) != "50.0" {
		t.Errorf("разделы: %+v", s1.Parts)
	}
	// Второй замер: счётчики выросли за 10 секунд.
	writeProcFiles(t, root, map[string]string{
		"stat":      "cpu  1100 100 500 8400 200 10 20 200 5 0\ncpu0 550 50 250 4200 100 5 10 100 2 0\ncpu1 550 50 250 4200 100 5 10 100 3 0\nbtime 1700000000\n",
		"diskstats": " 253 0 vda 1000 0 70480 500 2000 0 80000 1500 0 10000 2000\n",
		"net/dev":   "Inter-|\n face |\n  eth0: 15485760 150 0 1 0 0 0 0 7000 70 0 0 0 0 0 0\n",
		"uptime":    "10010.00 20000.00\n",
	})
	s2, err := c.Collect(t0.Add(10 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if s2.Average {
		t.Error("второй замер считается по разнице, а не с загрузки")
	}
	if got := round1(s2.CPU.Steal); got != "7.4" {
		t.Errorf("steal: %s", got)
	}
	// 20480 секторов × 512 = 10 МБ за 10 с.
	if got := round1(s2.Disks[0].ReadMBs); got != "1.0" {
		t.Errorf("чтение с диска: %s", got)
	}
	// io_ticks +1000 мс за 10 с = 10 %.
	if got := round1(s2.Disks[0].BusyPct); got != "10.0" {
		t.Errorf("загрузка диска: %s", got)
	}
	// 15 МБ за 10 с = 1.5 МБ/с, 100 пакетов за 10 с = 10/с.
	if got := round1(s2.Nets[0].RxMBs); got != "1.5" {
		t.Errorf("приём: %s", got)
	}
	if got := round1(s2.Nets[0].RxPPS); got != "10.0" {
		t.Errorf("пакетов/с: %s", got)
	}
	// Ряды заполняются обоими замерами.
	v := c.View(RangeHour)
	if !v.Ready || len(v.Series[KeySteal]) != 2 {
		t.Errorf("ряды: %+v", v.Series[KeySteal])
	}
	if b := c.Brief(); !b.Ready || b.NumCPU != 2 || round1(b.DiskPct) != "50.0" {
		t.Errorf("сводка: %+v", b)
	}
}

// TestNoPSI: без /proc/pressure метрики собираются, PSI просто нет.
func TestNoPSI(t *testing.T) {
	root := fakeProc(t, baseFiles())
	c := New(Options{ProcRoot: root, Interval: time.Second, DiskUsage: usage(10<<30, 9<<30), Logger: quietLogger()})
	s, err := c.Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s.PSI != nil {
		t.Errorf("PSI без файлов: %+v", s.PSI)
	}
	if v := c.View(RangeHour); v.PSI {
		t.Error("View сообщает о PSI, которого нет")
	}
}

// TestDownsample: минутные и 15-минутные точки хранят среднее и
// максимум, поэтому короткий всплеск виден и в окне на 30 дней.
func TestDownsample(t *testing.T) {
	ms := newMetricSeries(100)
	start := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for i := range 40 {
		v := 10.0
		if i == 7 {
			v = 90.0 // всплеск на одном замере
		}
		ms.add(start.Add(time.Duration(i)*30*time.Second), v)
	}
	min1 := ms.min1.all()
	if len(min1) < 3 {
		t.Fatalf("минутных точек: %d", len(min1))
	}
	spike := false
	for _, p := range min1 {
		if p.Max == 90 {
			spike = true
			if p.Avg >= 90 {
				t.Errorf("среднее не должно равняться максимуму: %+v", p)
			}
		}
	}
	if !spike {
		t.Error("всплеск потерялся при агрегации по минутам")
	}
	// 15-минутные точки: первая закрывается, когда начинается следующая
	// четверть часа.
	if n := len(ms.min15.all()); n == 0 {
		t.Error("нет 15-минутных точек")
	}
	for _, p := range ms.min15.all() {
		if p.Max < p.Avg {
			t.Errorf("максимум меньше среднего: %+v", p)
		}
	}
	// Кольцевой буфер вытесняет старые точки, порядок — по времени.
	r := newRing(3)
	for i := range 5 {
		r.push(Point{T: start.Add(time.Duration(i) * time.Minute), Avg: float64(i)})
	}
	pts := r.all()
	if len(pts) != 3 || pts[0].Avg != 2 || pts[2].Avg != 4 {
		t.Errorf("кольцевой буфер: %+v", pts)
	}
}

// TestSaveLoad: агрегаты переживают перезапуск, повреждённый файл не
// мешает запуску.
func TestSaveLoad(t *testing.T) {
	root := fakeProc(t, baseFiles())
	dir := t.TempDir()
	opt := Options{ProcRoot: root, Interval: time.Second, StateDir: dir, DiskUsage: usage(10<<30, 1<<30), Logger: quietLogger()}
	c := New(opt)
	now := time.Now().Add(-2 * time.Hour)
	for i := range 5 {
		if _, err := c.Collect(now.Add(time.Duration(i) * time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	c.Save()
	if _, err := os.Stat(filepath.Join(dir, stateFileName)); err != nil {
		t.Fatalf("файл метрик не записан: %v", err)
	}
	c2 := New(opt)
	// Сырые точки не сохраняются, минутные — сохраняются.
	if n := len(c2.View(RangeHour).Series[KeyCPU]); n != 0 {
		t.Errorf("сырые точки восстановились: %d", n)
	}
	if n := len(c2.View(RangeDay).Series[KeyCPU]); n == 0 {
		t.Error("минутные точки не восстановились")
	}
	// Повреждённый файл отодвигается в сторону.
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte("{не json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c3 := New(opt)
	if n := len(c3.View(RangeDay).Series[KeyCPU]); n != 0 {
		t.Errorf("повреждённый файл прочитан: %d", n)
	}
	if _, err := os.Stat(filepath.Join(dir, stateFileName+".corrupt")); err != nil {
		t.Errorf("повреждённый файл не сохранён для разбора: %v", err)
	}
}

// findingByID — признак по ID (для проверок).
func findingByID(fs []model.SystemFinding, id string) (model.SystemFinding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return model.SystemFinding{}, false
}

// TestFindings: steal и нагрузка дают признак только после удержания,
// заполненный раздел — сразу, oom — по росту счётчика.
func TestFindings(t *testing.T) {
	files := baseFiles()
	// steal 50 % и нагрузка 8 при 2 ядрах.
	files["loadavg"] = "8.00 7.00 6.00 2/200 500\n"
	files["pressure/memory"] = "some avg10=20.00 avg60=15.00 avg300=5.00 total=1\n"
	root := fakeProc(t, files)
	c := New(Options{ProcRoot: root, Interval: time.Minute, DiskUsage: usage(100<<30, 5<<30), Logger: quietLogger()})
	now := time.Now()
	if _, err := c.Collect(now); err != nil {
		t.Fatal(err)
	}
	// Первый замер: процентов за интервал ещё нет, но заполненный раздел
	// виден сразу.
	f, ok := findingByID(c.Findings(), "disk_almost_full")
	if !ok || f.Risk != model.RiskMedium || f.Path != "/" {
		t.Fatalf("disk_almost_full: %+v %v", f, ok)
	}
	if !strings.Contains(f.Title.In(i18n.RU), "95.0") {
		t.Errorf("заголовок без процента: %q", f.Title.In(i18n.RU))
	}
	if _, ok := findingByID(c.Findings(), "steal_high"); ok {
		t.Error("steal_high на первом замере (проценты ещё средние с загрузки)")
	}
	// Счётчики растут так, что steal = 50 %: 100 тиков steal из 200.
	bump := func(n int) {
		writeProcFiles(t, root, map[string]string{"stat": statLineAt(n)})
	}
	// 16 минут: steal_high держится 10 минут, load_high — 15.
	for i := 1; i <= 16; i++ {
		bump(i)
		if _, err := c.Collect(now.Add(time.Duration(i) * time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	fs := c.Findings()
	st, ok := findingByID(fs, "steal_high")
	if !ok || st.Risk != model.RiskLow {
		t.Fatalf("steal_high после 16 минут: %+v %v", st, ok)
	}
	if _, ok := findingByID(fs, "load_high"); !ok {
		t.Error("load_high после 15 минут удержания не появился")
	}
	if _, ok := findingByID(fs, "memory_pressure"); !ok {
		t.Error("memory_pressure при PSI 15 % не появился")
	}
	// steal пропал — признак снимается сразу (отсчёт начинается заново).
	writeProcFiles(t, root, map[string]string{"stat": statLineCalm()})
	if _, err := c.Collect(now.Add(17 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := findingByID(c.Findings(), "steal_high"); ok {
		t.Error("steal_high остался после того, как steal упал")
	}
	// Рост oom_kill — признак, первое чтение им не считается.
	writeProcFiles(t, root, map[string]string{"vmstat": "oom_kill 3\n"})
	if _, err := c.Collect(now.Add(18 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if f, ok := findingByID(c.Findings(), "oom_recent"); !ok || f.Risk != model.RiskLow {
		t.Errorf("oom_recent: %+v %v", f, ok)
	}
}

// statLineAt — /proc/stat на n-й минуте: за минуту набегает 6000 тиков
// простоя и 6000 тиков steal (50 %).
func statLineAt(n int) string {
	idle := 8000 + 6000*n
	steal := 160 + 6000*n
	return "cpu  1000 100 500 " + itoa(idle) + " 200 10 20 " + itoa(steal) + "\ncpu0 500 50 250 " + itoa(idle/2) + " 100 5 10 " + itoa(steal/2) + "\nbtime 1700000000\n"
}

// statLineCalm — счётчики после statLineAt(16), но дальше растёт только
// простой: steal больше не увеличивается.
func statLineCalm() string {
	idle := 8000 + 6000*16 + 6000
	steal := 160 + 6000*16
	return "cpu  1000 100 500 " + itoa(idle) + " 200 10 20 " + itoa(steal) + "\ncpu0 500 50 250 " + itoa(idle/2) + " 100 5 10 " + itoa(steal/2) + "\nbtime 1700000000\n"
}

func itoa(n int) string { return strings.TrimSpace(round0(float64(n))) }

func round0(v float64) string { return strings.TrimSuffix(round1(v), ".0") }

// TestHumanBytes — подписи размеров в фактах признаков.
func TestHumanBytes(t *testing.T) {
	for in, want := range map[uint64]string{0: "0", 512: "512", 2048: "2K", 5 << 20: "5M", 3 << 30: "3.0G", 2 << 40: "2.0T"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, ожидалось %q", in, got, want)
		}
	}
}

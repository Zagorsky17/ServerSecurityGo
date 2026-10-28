// Пакет metrics собирает метрики сервера: загрузку процессора (включая
// steal — время, которое гипервизор отдал другим ВМ), среднюю нагрузку,
// давление PSI, память и swap, заполненность разделов, ввод-вывод
// дисков и трафик интерфейсов.
//
// Метрики читаются отдельной лёгкой горутиной (Collector.Run) каждые
// SSG_METRICS_INTERVAL — чаще, чем идёт сканирование процессов: всплеск
// длиной полминуты при интервале сканирования 30 с был бы не виден.
// Горутина читает только несколько маленьких файлов /proc и не ходит по
// /proc/PID.
//
// Метрики не влияют на оценку риска процессов: перегруженный сервер —
// вопрос качества VPS, а не взлома. Но признаки из них (steal_high,
// disk_almost_full) видны в «Системе» и в истории, а заполненный диск
// мешает расследованию: журналы перестают писаться.
package metrics

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxProcFile — предел чтения одного файла /proc. На сервере с сотнями
// дисков diskstats и mounts бывают большими, но не настолько.
const maxProcFile = 4 << 20

// CPU — загрузка процессора в процентах за интервал между замерами.
type CPU struct {
	Busy   float64 `json:"busy"` // всё, кроме простоя и ожидания диска
	User   float64 `json:"user"` // user + nice
	System float64 `json:"system"`
	IOWait float64 `json:"iowait"`
	Steal  float64 `json:"steal"`
	Idle   float64 `json:"idle"`
}

// MemUsage — память в байтах и процентах.
type MemUsage struct {
	Total     uint64  `json:"total"`
	Available uint64  `json:"available"`
	Used      uint64  `json:"used"` // total - available
	Cached    uint64  `json:"cached"`
	Percent   float64 `json:"percent"`
	SwapTotal uint64  `json:"swapTotal"`
	SwapUsed  uint64  `json:"swapUsed"`
	SwapPct   float64 `json:"swapPct"`
}

// PSI — давление (/proc/pressure): доля времени, когда задачи ждали
// ресурс. Показывает нехватку точнее, чем загрузка: CPU может быть
// занят на 100 % и без очереди.
// Хранится avg60 — доля за минуту: avg10 слишком дёргается, чтобы
// показывать её в интерфейсе.
type PSI struct {
	CPU float64 `json:"cpu"`
	Mem float64 `json:"mem"`
	IO  float64 `json:"io"`
}

// DiskRate — скорость и загруженность одного устройства.
type DiskRate struct {
	Name     string  `json:"name"`
	ReadMBs  float64 `json:"readMBs"`
	WriteMBs float64 `json:"writeMBs"`
	BusyPct  float64 `json:"busyPct"`
}

// NetRate — трафик одного интерфейса.
type NetRate struct {
	Name     string  `json:"name"`
	RxMBs    float64 `json:"rxMBs"`
	TxMBs    float64 `json:"txMBs"`
	RxPPS    float64 `json:"rxPPS"`
	TxPPS    float64 `json:"txPPS"`
	RxDrops  float64 `json:"rxDrops"` // отбросов в секунду
	RxErrors float64 `json:"rxErrors"`
}

// Partition — заполненность раздела.
type Partition struct {
	Device     string  `json:"device"`
	Point      string  `json:"point"`
	FSType     string  `json:"fstype"`
	Total      uint64  `json:"total"`
	Free       uint64  `json:"free"`
	Percent    float64 `json:"percent"`
	InodePct   float64 `json:"inodePct"`
	InodeTotal uint64  `json:"inodeTotal"`
}

// Sample — один замер метрик.
type Sample struct {
	Time time.Time `json:"time"`
	// Average — проценты посчитаны за всё время с загрузки, а не за
	// интервал: это первый замер, сравнивать было не с чем.
	Average   bool        `json:"average,omitempty"`
	CPU       CPU         `json:"cpu"`
	Cores     []CPU       `json:"cores"`
	NumCPU    int         `json:"numCPU"`
	Load      Load        `json:"load"`
	Mem       MemUsage    `json:"mem"`
	PSI       *PSI        `json:"psi,omitempty"`
	Disks     []DiskRate  `json:"disks"`
	Nets      []NetRate   `json:"nets"`
	Parts     []Partition `json:"parts"`
	UptimeSec float64     `json:"uptimeSec"`
	OOMKills  uint64      `json:"oomKills"`
	// VM — сервер виртуальный (есть смысл смотреть на steal).
	VM bool `json:"vm"`
	// Container — метрики читаются внутри контейнера: /proc/stat и
	// /proc/meminfo показывают хост, а не лимиты контейнера.
	Container bool `json:"container"`
}

// raw — сырые счётчики одного чтения /proc; из разницы двух raw
// получаются скорости.
type raw struct {
	time   time.Time
	cpu    CPUTimes
	cores  []CPUTimes
	disks  []DiskCounters
	nets   []NetCounters
	uptime float64
}

// readProc читает файл /proc с лимитом размера. Файлы /proc
// принадлежат ядру: защищаться от подмены не нужно, но от неожиданно
// большого файла — нужно.
func readProc(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcFile))
	return string(data), err
}

// procPath — путь внутри корня /proc (SSG_PROC_ROOT).
func (c *Collector) procPath(parts ...string) string {
	return filepath.Join(append([]string{c.opt.ProcRoot}, parts...)...)
}

// readRaw снимает счётчики. Отсутствие отдельного файла не ошибка:
// PSI бывает выключен, diskstats пуст в контейнере.
func (c *Collector) readRaw(now time.Time) (raw, error) {
	r := raw{time: now}
	stat, err := readProc(c.procPath("stat"))
	if err != nil {
		return r, err
	}
	r.cpu, r.cores = ParseStat(stat)
	if s, err := readProc(c.procPath("diskstats")); err == nil {
		r.disks = ParseDiskstats(s)
	}
	if s, err := readProc(c.procPath("net", "dev")); err == nil {
		r.nets = ParseNetDev(s)
	}
	if s, err := readProc(c.procPath("uptime")); err == nil {
		r.uptime = ParseUptime(s)
	}
	return r, nil
}

// readPSI читает /proc/pressure/*; nil — ядро без PSI (до 4.20 или
// psi=0 в параметрах загрузки).
func (c *Collector) readPSI() *PSI {
	var p PSI
	any := false
	for _, f := range []struct {
		file string
		dst  *float64
	}{{"cpu", &p.CPU}, {"memory", &p.Mem}, {"io", &p.IO}} {
		s, err := readProc(c.procPath("pressure", f.file))
		if err != nil {
			continue
		}
		if _, avg60, ok := ParsePressure(s); ok {
			any = true
			*f.dst = avg60
		}
	}
	if !any {
		return nil
	}
	return &p
}

// isVM — сервер виртуальный: флаг hypervisor в /proc/cpuinfo или
// ненулевой steal с загрузки. На голом железе steal всегда 0, и
// показывать «steal 0 % — отлично» было бы обманом.
func (c *Collector) isVM(cpu CPUTimes) bool {
	if cpu.Steal > 0 {
		return true
	}
	s, err := readProc(c.procPath("cpuinfo"))
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(s, "\n") {
		if name, rest, ok := strings.Cut(line, ":"); ok && strings.HasPrefix(strings.TrimSpace(name), "flags") {
			return strings.Contains(" "+strings.TrimSpace(rest)+" ", " hypervisor ")
		}
	}
	return false
}

// inContainer — метрики снимаются внутри контейнера: тогда загрузка и
// память относятся к хосту, а не к контейнеру.
func (c *Collector) inContainer() bool {
	if s, err := readProc(c.procPath("1", "cgroup")); err == nil && strings.Contains(s, "docker") {
		return true
	}
	_, err := os.Lstat(filepath.Join(c.opt.HostRoot, ".dockerenv"))
	return err == nil
}

// partitions измеряет заполненность разделов из /proc/self/mounts.
func (c *Collector) partitions() []Partition {
	data, err := readProc(c.procPath("self", "mounts"))
	if err != nil {
		return nil
	}
	var out []Partition
	for _, m := range ParseMounts(data) {
		u, err := c.usage(filepath.Join(c.opt.HostRoot, m.Point))
		if err != nil || u.Total == 0 {
			continue
		}
		p := Partition{Device: m.Device, Point: m.Point, FSType: m.FSType, Total: u.Total, Free: u.Free,
			Percent: pct(u.Total-u.Free, u.Total), InodeTotal: u.Inodes}
		if u.Inodes > 0 {
			p.InodePct = pct(u.Inodes-u.InodesFree, u.Inodes)
		}
		out = append(out, p)
	}
	return out
}

// usage — свободное место раздела (statfs или подстановка в тестах).
func (c *Collector) usage(path string) (Usage, error) {
	if c.opt.DiskUsage != nil {
		return c.opt.DiskUsage(path)
	}
	return diskUsage(path)
}

func pct(part, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

// rate — приращение счётчика в секунду. Уменьшение счётчика
// (перезагрузка, переполнение) даёт 0: отрицательной скорости не бывает.
func rate(cur, prev uint64, dt float64) float64 {
	if dt <= 0 || cur < prev {
		return 0
	}
	return float64(cur-prev) / dt
}

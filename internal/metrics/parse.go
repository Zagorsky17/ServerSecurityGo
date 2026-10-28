package metrics

import (
	"strconv"
	"strings"
)

// CPUTimes — время процессора из /proc/stat. Значения — тики ядра
// (USER_HZ) в сыром виде и проценты после деления дельт.
type CPUTimes struct {
	User    float64 `json:"user"`
	Nice    float64 `json:"nice"`
	System  float64 `json:"system"`
	Idle    float64 `json:"idle"`
	IOWait  float64 `json:"iowait"`
	IRQ     float64 `json:"irq"`
	SoftIRQ float64 `json:"softirq"`
	// Steal — время, которое гипервизор отдал другим виртуальным
	// машинам, пока наша ждала процессор.
	Steal float64 `json:"steal"`
}

// Total — всё время, включая простой. guest и guest_nice в /proc/stat
// уже входят в user и nice, поэтому не прибавляются повторно.
func (c CPUTimes) Total() float64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// Busy — время, когда процессор был занят работой: без простоя и без
// ожидания диска (iowait — это тоже простой, но по вине ввода-вывода).
func (c CPUTimes) Busy() float64 { return c.Total() - c.Idle - c.IOWait }

// sub — разница двух замеров. Уменьшение счётчика (перезагрузка,
// отключение ядра) даёт нуль, а не отрицательное значение.
func (c CPUTimes) sub(prev CPUTimes) CPUTimes {
	d := func(a, b float64) float64 {
		if a < b {
			return 0
		}
		return a - b
	}
	return CPUTimes{User: d(c.User, prev.User), Nice: d(c.Nice, prev.Nice), System: d(c.System, prev.System),
		Idle: d(c.Idle, prev.Idle), IOWait: d(c.IOWait, prev.IOWait), IRQ: d(c.IRQ, prev.IRQ),
		SoftIRQ: d(c.SoftIRQ, prev.SoftIRQ), Steal: d(c.Steal, prev.Steal)}
}

// percent — доли составляющих в процентах от всего времени.
func (c CPUTimes) percent() CPU {
	total := c.Total()
	if total <= 0 {
		return CPU{}
	}
	p := func(v float64) float64 { return v / total * 100 }
	return CPU{Busy: p(c.Busy()), User: p(c.User + c.Nice), System: p(c.System + c.IRQ + c.SoftIRQ),
		IOWait: p(c.IOWait), Steal: p(c.Steal), Idle: p(c.Idle)}
}

// ParseStat разбирает строки cpu и cpuN из /proc/stat. На старых ядрах
// полей меньше (нет steal или guest) — отсутствующие считаются нулём.
func ParseStat(data string) (total CPUTimes, cores []CPUTimes) {
	for line := range strings.SplitSeq(data, "\n") {
		rest, ok := strings.CutPrefix(line, "cpu")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		// «cpu  1 2 3» — итог, «cpu0 1 2 3» — ядро: номер приклеен к имени.
		idx, vals := -1, f
		if n, err := strconv.Atoi(f[0]); err == nil && !strings.HasPrefix(rest, " ") {
			idx, vals = n, f[1:]
		} else if rest != "" && !strings.HasPrefix(rest, " ") {
			continue // cpuinfo-подобная строка, не наша
		}
		var t CPUTimes
		dst := []*float64{&t.User, &t.Nice, &t.System, &t.Idle, &t.IOWait, &t.IRQ, &t.SoftIRQ, &t.Steal}
		for i, v := range vals {
			if i >= len(dst) {
				break
			}
			n, err := strconv.ParseFloat(v, 64)
			if err != nil || n < 0 {
				break
			}
			*dst[i] = n
		}
		if idx < 0 {
			total = t
			continue
		}
		for len(cores) <= idx {
			cores = append(cores, CPUTimes{})
		}
		cores[idx] = t
	}
	return total, cores
}

// Load — средняя нагрузка из /proc/loadavg.
type Load struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
	Running int     `json:"running"`
	Tasks   int     `json:"tasks"`
}

// ParseLoadAvg разбирает «0.44 0.31 0.25 2/431 12345».
func ParseLoadAvg(s string) (Load, bool) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return Load{}, false
	}
	var l Load
	for i, dst := range []*float64{&l.One, &l.Five, &l.Fifteen} {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil || v < 0 {
			return Load{}, false
		}
		*dst = v
	}
	if len(f) >= 4 {
		run, tasks, _ := strings.Cut(f[3], "/")
		l.Running, _ = strconv.Atoi(run)
		l.Tasks, _ = strconv.Atoi(tasks)
	}
	return l, true
}

// Mem — значения /proc/meminfo в килобайтах (как в файле).
type Mem struct {
	Total, Available, Free, Cached, Buffers, SwapTotal, SwapFree uint64
}

// ParseMeminfo читает нужные строки /proc/meminfo.
func ParseMeminfo(data string) Mem {
	var m Mem
	keys := map[string]*uint64{"MemTotal": &m.Total, "MemAvailable": &m.Available, "MemFree": &m.Free,
		"Cached": &m.Cached, "Buffers": &m.Buffers, "SwapTotal": &m.SwapTotal, "SwapFree": &m.SwapFree}
	for line := range strings.SplitSeq(data, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		dst, ok := keys[name]
		if !ok || *dst != 0 {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		if v, err := strconv.ParseUint(f[0], 10, 64); err == nil {
			*dst = v
		}
	}
	// MemAvailable нет на ядрах до 3.14: грубая замена.
	if m.Available == 0 {
		m.Available = m.Free + m.Cached + m.Buffers
	}
	return m
}

// ParsePressure разбирает /proc/pressure/{cpu,memory,io}: строку some
// («часть задач ждала») — avg10 и avg60 в процентах времени.
func ParsePressure(data string) (avg10, avg60 float64, ok bool) {
	for line := range strings.SplitSeq(data, "\n") {
		rest, cut := strings.CutPrefix(strings.TrimSpace(line), "some ")
		if !cut {
			continue
		}
		for _, kv := range strings.Fields(rest) {
			k, v, _ := strings.Cut(kv, "=")
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			switch k {
			case "avg10":
				avg10, ok = n, true
			case "avg60":
				avg60, ok = n, true
			}
		}
		return avg10, avg60, ok
	}
	return 0, 0, false
}

// DiskCounters — счётчики одного блочного устройства из /proc/diskstats.
type DiskCounters struct {
	Name         string
	ReadSectors  uint64
	WriteSectors uint64
	// IOTicks — миллисекунды, когда у устройства была работа (поле 10 в
	// документации ядра): отношение к прошедшему времени даёт загрузку.
	IOTicks uint64
}

// ParseDiskstats разбирает /proc/diskstats. Виртуальные устройства
// (loop, ram, zram) и разделы пропускаются: раздел — это имя, к
// которому дописаны цифры (sda1) или «p» с цифрами (nvme0n1p1) после
// имени целого устройства из того же файла.
func ParseDiskstats(data string) []DiskCounters {
	var all []DiskCounters
	names := map[string]bool{}
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		name := f[2]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") {
			continue
		}
		rs, err1 := strconv.ParseUint(f[5], 10, 64)
		ws, err2 := strconv.ParseUint(f[9], 10, 64)
		ticks, err3 := strconv.ParseUint(f[12], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		names[name] = true
		all = append(all, DiskCounters{Name: name, ReadSectors: rs, WriteSectors: ws, IOTicks: ticks})
	}
	out := make([]DiskCounters, 0, len(all))
	for _, d := range all {
		if !isPartition(d.Name, names) {
			out = append(out, d)
		}
	}
	return out
}

// isPartition — имя получается из имени другого устройства файла
// добавлением номера: sda → sda1, nvme0n1 → nvme0n1p1.
func isPartition(name string, names map[string]bool) bool {
	for i := len(name) - 1; i > 0; i-- {
		if name[i] < '0' || name[i] > '9' {
			break
		}
		base := name[:i]
		if base[len(base)-1] == 'p' {
			base = base[:len(base)-1]
		}
		if names[base] {
			return true
		}
	}
	return false
}

// NetCounters — счётчики одного сетевого интерфейса из /proc/net/dev.
type NetCounters struct {
	Name                               string
	RxBytes, RxPackets, RxErrs, RxDrop uint64
	TxBytes, TxPackets, TxErrs, TxDrop uint64
}

// ParseNetDev разбирает /proc/net/dev. Петлевой интерфейс пропускается:
// на нём виден только обмен сервера с самим собой.
func ParseNetDev(data string) []NetCounters {
	var out []NetCounters
	for line := range strings.SplitSeq(data, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || name == "lo" || strings.Contains(name, "|") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 12 {
			continue
		}
		nums := make([]uint64, 12)
		bad := false
		for i := range nums {
			v, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				bad = true
				break
			}
			nums[i] = v
		}
		if bad {
			continue
		}
		out = append(out, NetCounters{Name: name, RxBytes: nums[0], RxPackets: nums[1], RxErrs: nums[2], RxDrop: nums[3],
			TxBytes: nums[8], TxPackets: nums[9], TxErrs: nums[10], TxDrop: nums[11]})
	}
	return out
}

// ParseUptime — первое число /proc/uptime (секунды с загрузки).
func ParseUptime(s string) float64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// ParseKeyValue — значение счётчика «имя число» (/proc/vmstat).
func ParseKeyValue(data, key string) (uint64, bool) {
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			v, err := strconv.ParseUint(f[1], 10, 64)
			return v, err == nil
		}
	}
	return 0, false
}

// Mount — строка /proc/self/mounts.
type Mount struct {
	Device, Point, FSType string
}

// skipFS — файловые системы, которые не показывают место на диске:
// виртуальные (proc, sysfs), в памяти (tmpfs), слои контейнеров
// (overlay), образы snap (squashfs). Сетевые (nfs, cifs, sshfs) тоже
// пропускаются, но по другой причине: statfs на недоступном сервере
// зависает, а вместе с ним зависла бы горутина метрик.
var skipFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "ramfs": true,
	"overlay": true, "squashfs": true, "cgroup": true, "cgroup2": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "configfs": true, "pstore": true, "bpf": true, "autofs": true, "mqueue": true,
	"hugetlbfs": true, "fusectl": true, "binfmt_misc": true, "nsfs": true, "efivarfs": true, "rpc_pipefs": true,
	"fuse.gvfsd-fuse": true, "fuse.portal": true, "nfs": true, "nfs4": true, "cifs": true, "smb3": true,
	"fuse.sshfs": true, "fuse.rclone": true, "9p": true, "virtiofs": true, "zfs": true,
}

// ParseMounts разбирает /proc/self/mounts и оставляет разделы, у
// которых есть смысл измерять заполненность. Одно устройство
// показывается один раз (bind-монтирования и подтома повторяют его):
// остаётся самый короткий путь.
func ParseMounts(data string) []Mount {
	var out []Mount
	seen := map[string]int{} // устройство → индекс в out
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		m := Mount{Device: unescapeMount(f[0]), Point: unescapeMount(f[1]), FSType: f[2]}
		if skipFS[m.FSType] || strings.HasPrefix(m.FSType, "fuse.") || !strings.HasPrefix(m.Device, "/") {
			continue
		}
		if i, ok := seen[m.Device]; ok {
			if len(m.Point) < len(out[i].Point) {
				out[i] = m
			}
			continue
		}
		seen[m.Device] = len(out)
		out = append(out, m)
	}
	return out
}

// unescapeMount раскрывает восьмеричные последовательности, которыми
// ядро кодирует пробел и другие особые символы в путях (\040).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

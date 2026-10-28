package metrics

import (
	"strings"
	"testing"
)

// Фаззинг разборщиков файлов /proc: формат меняется между версиями
// ядра, а служба читает их постоянно. go test выполняет только
// начальный корпус; долгий прогон:
// go test -fuzz=FuzzParseStat ./internal/metrics.

func FuzzParseStat(f *testing.F) {
	for _, s := range []string{statText, "cpu  1 2 3", "cpu0", "cpu99999999999999999999 1", "cpu  -1 x 3\ncpuX 1", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		total, cores := ParseStat(data)
		if total.Total() < 0 {
			t.Fatalf("отрицательное время: %+v", total)
		}
		// Ядер не может быть больше, чем строк в файле: иначе номер ядра
		// из файла раздул бы срез.
		if len(cores) > len(data)+1 {
			t.Fatalf("ядер %d на %d байт", len(cores), len(data))
		}
		for _, c := range cores {
			if p := c.percent(); p.Busy < 0 || p.Busy > 100.0001 {
				t.Fatalf("занятость вне диапазона: %v", p.Busy)
			}
		}
	})
}

func FuzzParseDiskstats(f *testing.F) {
	for _, s := range []string{" 253 0 vda 1 2 3 4 5 6 7 8 9 10 11", "x", " 1 1 sda1 " + strings.Repeat("1 ", 20), ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		for _, d := range ParseDiskstats(data) {
			if d.Name == "" {
				t.Fatal("устройство без имени")
			}
		}
	})
}

func FuzzParseNetDev(f *testing.F) {
	for _, s := range []string{"  eth0: " + strings.Repeat("1 ", 16), "lo:", ":::", "a: x y z", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		for _, n := range ParseNetDev(data) {
			if n.Name == "" || n.Name == "lo" {
				t.Fatalf("интерфейс %q", n.Name)
			}
		}
	})
}

func FuzzParseMounts(f *testing.F) {
	for _, s := range []string{"/dev/sda1 / ext4 rw 0 0", `/dev/sda1 /a\040b ext4 rw 0 0`, "a b", `x \999 y`, ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		for _, m := range ParseMounts(data) {
			if !strings.HasPrefix(m.Device, "/") {
				t.Fatalf("устройство без пути: %+v", m)
			}
			if skipFS[m.FSType] {
				t.Fatalf("пропущенная файловая система: %+v", m)
			}
		}
	})
}

func FuzzParsePressure(f *testing.F) {
	for _, s := range []string{"some avg10=1.00 avg60=2.00 avg300=3.00 total=4", "some avg10=x", "full avg60=1", "some", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		a10, a60, ok := ParsePressure(data)
		if !ok && (a10 != 0 || a60 != 0) {
			t.Fatalf("значения без признака успеха: %v %v", a10, a60)
		}
	})
}

func FuzzParseMeminfo(f *testing.F) {
	for _, s := range []string{"MemTotal: 1 kB", "MemTotal:", "MemTotal: -1 kB\nCached: 99999999999999999999 kB", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		m := ParseMeminfo(data)
		if m.Total == 0 && m.Available != m.Free+m.Cached+m.Buffers {
			t.Fatalf("оценка доступной памяти: %+v", m)
		}
	})
}

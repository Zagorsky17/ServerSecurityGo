package detect

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/redact"
)

// Системные проверки ищут признаки закрепления (persistence): места,
// откуда вредоносное ПО обычно перезапускает себя после перезагрузки.
// Все проверки только читают файлы. Ключи SSH и секреты в интерфейс не
// попадают: показываются пути, время изменения и замаскированные строки.

// persistPattern — явно подозрительное содержимое файлов автозапуска:
// загрузка с выполнением, декодирование base64, reverse shell, майнеры.
var persistPattern = regexp.MustCompile(`(?i)(curl|wget)\b[^\n|]*\|\s*(ba|da)?sh\b|base64\s+(-d|--decode)|/dev/shm/|/dev/tcp/|\bnc(at)?\b[^\n]*\s-e\s|stratum\+tcp|xmrig|chmod\s+\+x\s+/(tmp|dev/shm|var/tmp)`)

// tempPattern — запуск чего-либо из /tmp или /var/tmp. Бывает и в
// штатных скриптах, поэтому даёт только LOW.
var tempPattern = regexp.MustCompile(`(^|[\s;'"=])/(var/)?tmp/[^\s;'"]+`)

// maxSystemFile — больше этого файлы проверок не читаются: настоящие
// crontab, профили и authorized_keys намного меньше.
const maxSystemFile = 1 << 20

var (
	errNotRegular = errors.New("не обычный файл")
	errTooLarge   = errors.New("файл больше 1 МБ")
)

// readRegular безопасно читает файл проверки: только обычный файл и не
// больше max байт. Сканер работает от root, а файлы в домашних каталогах
// (authorized_keys) создаёт пользователь: FIFO на их месте повесил бы
// сканирование навсегда, а симлинк на /dev/zero или огромный файл
// исчерпал бы память службы. follow = false — симлинк не открывается
// (для файлов, которыми управляет пользователь). Тип и размер берутся из
// уже открытого дескриптора, поэтому подмена файла между проверкой и
// чтением ничего не даёт.
func readRegular(path string, max int64, follow bool) ([]byte, fs.FileInfo, error) {
	f, err := openForRead(path, follow)
	if err != nil {
		// Открыть не удалось из-за типа (симлинк при follow = false):
		// сообщаем об этом отдельно от «файла нет».
		if fi, lerr := os.Lstat(path); lerr == nil && !fi.Mode().IsRegular() {
			return nil, fi, errNotRegular
		}
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fi, errNotRegular
	}
	if fi.Size() > max {
		return nil, fi, errTooLarge
	}
	// Файл мог вырасти после Stat — читаем не больше max+1 байт.
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fi, err
	}
	if int64(len(data)) > max {
		return nil, fi, errTooLarge
	}
	return data, fi, nil
}

// SystemChecks выполняет проверки относительно корня хоста hostRoot.
func SystemChecks(hostRoot string, now time.Time, cfg Config) []model.SystemFinding {
	if cfg.RecentDays <= 0 {
		cfg.RecentDays = 7
	}
	recent := now.Add(-time.Duration(cfg.RecentDays) * 24 * time.Hour)
	h := func(p string) string { return filepath.Join(hostRoot, p) }
	var out []model.SystemFinding

	// 1. /etc/ld.so.preload — глобальная подгрузка библиотек во все
	//    процессы. В штатной системе файла нет или он пустой.
	// Файл принадлежит root; по симлинку идём (динамический загрузчик тоже
	// идёт), но без блокировки на FIFO и с ограничением размера.
	if data, fi, err := readRegular(h("etc/ld.so.preload"), maxSystemFile, true); err == nil {
		lines := meaningfulLines(string(data))
		if len(lines) > 0 {
			out = append(out, sys(model.Finding{
				ID: "ld_so_preload", Title: "Глобальная подгрузка библиотек через /etc/ld.so.preload", Category: model.CatPersistence, Weight: 35, Strong: true,
				Evidence:       append([]string{"файл не пустой, библиотеки подгружаются во ВСЕ процессы:"}, lines...),
				Recommendation: "Штатно файл отсутствует. Проверьте каждую библиотеку: dpkg -S <путь>; sha256sum <путь>. Так работают многие руткиты пользовательского уровня.",
			}, "/etc/ld.so.preload", model.RiskHigh, fi.ModTime()))
		}
	}

	// 2. Задания cron и файлы автозапуска.
	var files []string
	files = append(files, h("etc/crontab"), h("etc/rc.local"), h("etc/bash.bashrc"), h("etc/profile"), h("root/.bashrc"), h("root/.profile"))
	for _, pat := range []string{"etc/cron.d/*", "etc/cron.hourly/*", "etc/cron.daily/*", "etc/cron.weekly/*", "etc/cron.monthly/*",
		"var/spool/cron/crontabs/*", "var/spool/cron/*", "etc/profile.d/*", "etc/systemd/system/*.service", "etc/systemd/system/*.timer",
		"etc/systemd/system/*/*.service", "etc/init.d/*", "etc/update-motd.d/*"} {
		m, _ := filepath.Glob(h(pat))
		files = append(files, m...)
	}
	sort.Strings(files)
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		// Симлинки, каталоги и большие файлы пропускаются, как и раньше.
		data, fi, err := readRegular(f, maxSystemFile, false)
		if err != nil {
			continue
		}
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(f, filepath.Clean(hostRoot)), "/")
		var hits, tempHits []string
		for i, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			ref := fmt.Sprintf("строка %d: %s", i+1, truncate(redact.String(t), 200))
			if persistPattern.MatchString(t) && len(hits) < 5 {
				hits = append(hits, ref)
			} else if tempPattern.MatchString(t) && len(tempHits) < 5 {
				tempHits = append(tempHits, ref)
			}
		}
		if len(hits) == 0 && len(tempHits) > 0 {
			out = append(out, sys(model.Finding{
				ID: "autostart_temp", Title: "Файл автозапуска ссылается на временный каталог", Category: model.CatPersistence, Weight: 8,
				Evidence:       tempHits,
				Recommendation: fmt.Sprintf("Проверьте, что именно запускается из /tmp в %s: штатные скрипты обычно так не делают.", rel),
			}, rel, model.RiskLow, fi.ModTime()))
			continue
		}
		if len(hits) > 0 {
			out = append(out, sys(model.Finding{
				ID: "autostart_suspicious", Title: "Подозрительная команда в файле автозапуска", Category: model.CatPersistence, Weight: 30,
				Evidence:       hits,
				Recommendation: fmt.Sprintf("Изучите файл %s и выясните, кто и когда его изменил (stat, журналы auth.log, история команд).", rel),
			}, rel, model.RiskMedium, fi.ModTime()))
			continue
		}
		if fi.ModTime().After(recent) {
			out = append(out, sys(model.Finding{
				ID: "autostart_recent", Title: "Недавно изменён файл автозапуска", Category: model.CatPersistence, Weight: 3,
				Evidence:       []string{fmt.Sprintf("изменён %s", fi.ModTime().Format("2006-01-02 15:04"))},
				Recommendation: "Обычно это результат установки пакетов или действий администратора. Убедитесь, что изменение ожидаемо.",
			}, rel, model.RiskInfo, fi.ModTime()))
		}
	}

	// 3. authorized_keys — недавние изменения и ключи с command=.
	keys := []string{h("root/.ssh/authorized_keys"), h("root/.ssh/authorized_keys2")}
	homes, _ := filepath.Glob(h("home/*/.ssh/authorized_keys"))
	keys = append(keys, homes...)
	for _, f := range keys {
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(f, filepath.Clean(hostRoot)), "/")
		// Файл в домашнем каталоге контролирует его владелец: по симлинку
		// не идём, FIFO и устройства не открываем, размер ограничен.
		data, fi, err := readRegular(f, maxSystemFile, false)
		if errors.Is(err, errNotRegular) || errors.Is(err, errTooLarge) {
			out = append(out, sys(model.Finding{
				ID: "ssh_keys_not_regular", Title: "Файл authorized_keys — не обычный файл или слишком большой", Category: model.CatPersistence, Weight: 10,
				Evidence:       []string{describeUnusual(f, fi, err)},
				Recommendation: "Файл не прочитан: сканер не открывает ссылки, FIFO и устройства в домашних каталогах. sshd по ссылке идёт — проверьте, куда она указывает и кто её создал (ls -la " + filepath.Dir(rel) + ").",
			}, rel, model.RiskLow, fi.ModTime()))
			continue
		}
		if err != nil {
			continue
		}
		lines := meaningfulLines(string(data))
		var cmdHits []string
		for i, l := range lines {
			if strings.Contains(l, "command=") && persistPattern.MatchString(l) {
				cmdHits = append(cmdHits, fmt.Sprintf("ключ №%d содержит подозрительную опцию command=", i+1))
			}
		}
		if len(cmdHits) > 0 {
			out = append(out, sys(model.Finding{
				ID: "ssh_key_command", Title: "Ключ SSH с подозрительной принудительной командой", Category: model.CatPersistence, Weight: 25,
				Evidence:       cmdHits,
				Recommendation: "Просмотрите файл вручную и удалите неизвестные ключи (приложение этого не делает).",
			}, rel, model.RiskMedium, fi.ModTime()))
		}
		if fi.ModTime().After(recent) {
			out = append(out, sys(model.Finding{
				ID: "ssh_keys_recent", Title: "Недавно изменён список ключей SSH", Category: model.CatPersistence, Weight: 10,
				Evidence:       []string{fmt.Sprintf("изменён %s, ключей: %d", fi.ModTime().Format("2006-01-02 15:04"), len(lines))},
				Recommendation: "Сверьте ключи со списком ожидаемых: ssh-keygen -lf " + rel + ". Добавление ключа — частый способ закрепления.",
			}, rel, model.RiskLow, fi.ModTime()))
		}
	}
	return out
}

func sys(f model.Finding, path string, r model.Risk, mt time.Time) model.SystemFinding {
	return model.SystemFinding{Finding: f, Path: path, Risk: r, ModTime: mt}
}

// describeUnusual — пояснение, почему файл проверки не прочитан.
func describeUnusual(path string, fi fs.FileInfo, err error) string {
	switch {
	case errors.Is(err, errTooLarge):
		return fmt.Sprintf("размер %d байт — больше лимита 1 МБ", fi.Size())
	case fi.Mode()&fs.ModeSymlink != 0:
		target, _ := os.Readlink(path)
		return "символическая ссылка → " + target
	case fi.Mode()&fs.ModeNamedPipe != 0:
		return "именованный канал (FIFO)"
	case fi.Mode()&fs.ModeDevice != 0:
		return "файл устройства"
	case fi.IsDir():
		return "каталог"
	}
	return "тип файла: " + fi.Mode().Type().String()
}

func meaningfulLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

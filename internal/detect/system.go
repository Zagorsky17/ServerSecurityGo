package detect

import (
	"fmt"
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
	if data, err := os.ReadFile(h("etc/ld.so.preload")); err == nil {
		lines := meaningfulLines(string(data))
		if len(lines) > 0 {
			out = append(out, sys(model.Finding{
				ID: "ld_so_preload", Title: "Глобальная подгрузка библиотек через /etc/ld.so.preload", Category: model.CatPersistence, Weight: 35, Strong: true,
				Evidence:       append([]string{"файл не пустой, библиотеки подгружаются во ВСЕ процессы:"}, lines...),
				Recommendation: "Штатно файл отсутствует. Проверьте каждую библиотеку: dpkg -S <путь>; sha256sum <путь>. Так работают многие руткиты пользовательского уровня.",
			}, "/etc/ld.so.preload", model.RiskHigh, modTime(h("etc/ld.so.preload"))))
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
		fi, err := os.Lstat(f)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
			continue
		}
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(f, filepath.Clean(hostRoot)), "/")
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
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
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(f, filepath.Clean(hostRoot)), "/")
		data, _ := os.ReadFile(f)
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

func modTime(p string) time.Time {
	if fi, err := os.Stat(p); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
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

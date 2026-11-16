package detect

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// Системные проверки ищут признаки закрепления (persistence): места,
// откуда вредоносное ПО обычно перезапускает себя после перезагрузки.
// Все проверки только читают файлы. Ключи SSH и секреты в интерфейс не
// попадают: показываются пути, время изменения и замаскированные строки.

// persistPattern — явно подозрительное содержимое файлов автозапуска:
// загрузка с выполнением, декодирование base64, reverse shell, майнеры.
var persistPattern = regexp.MustCompile(`(?i)\bLD_PRELOAD\s*=\s*[^\s;]+|(curl|wget)\b[^\n|]*\|\s*(ba|da)?sh\b|base64\s+(-d|--decode)|/dev/shm/|/dev/tcp/|\bnc(at)?\b[^\n]*\s-e\s|stratum\+tcp|xmrig|chmod\s+\+x\s+/(tmp|dev/shm|var/tmp)`)

// tempPattern — запуск чего-либо из /tmp или /var/tmp. Бывает и в
// штатных скриптах, поэтому даёт только LOW.
var tempPattern = regexp.MustCompile(`(^|[\s;'"=])/(var/)?tmp/[^\s;'"]+`)

// maxSystemFile — больше этого файлы проверок не читаются: настоящие
// crontab, профили и authorized_keys намного меньше.
const maxSystemFile = 1 << 20

// readRegular безопасно читает файл проверки (см. safefile.ReadRegular).
func readRegular(path string, max int64, follow bool) ([]byte, fs.FileInfo, error) {
	return safefile.ReadRegular(path, max, follow)
}

// SystemChecks выполняет проверки относительно корня хоста hostRoot.
func SystemChecks(hostRoot string, now time.Time, cfg Config) []model.SystemFinding {
	return SystemChecksWithContext(hostRoot, now, cfg, nil, nil)
}

func SystemChecksWithContext(hostRoot string, now time.Time, cfg Config, owners map[string]bool, procs []*model.Process) []model.SystemFinding {
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
				ID: "ld_so_preload", Title: i18n.T("rule.ld_so_preload.title"), Category: model.CatPersistence, Weight: 35, Strong: true,
				Evidence:       append([]i18n.Msg{i18n.T("ev.preload_not_empty")}, i18n.Ls(lines)...),
				Recommendation: i18n.T("rule.ld_so_preload.rec"),
			}, "/etc/ld.so.preload", model.RiskHigh, fi.ModTime()))
		}
	}

	out = append(out, persistenceChecks(hostRoot, now, cfg, owners, procs)...)

	// 3. authorized_keys — недавние изменения и ключи с command=.
	keys := []string{h("root/.ssh/authorized_keys"), h("root/.ssh/authorized_keys2")}
	homes, _ := filepath.Glob(h("home/*/.ssh/authorized_keys"))
	keys = append(keys, homes...)
	for _, f := range keys {
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(f, filepath.Clean(hostRoot)), "/")
		// Файл в домашнем каталоге контролирует его владелец: по симлинку
		// не идём, FIFO и устройства не открываем, размер ограничен.
		data, fi, err := readRegular(f, maxSystemFile, false)
		if errors.Is(err, safefile.ErrNotRegular) || errors.Is(err, safefile.ErrTooLarge) {
			out = append(out, sys(model.Finding{
				ID: "ssh_keys_not_regular", Title: i18n.T("rule.ssh_keys_not_regular.title"), Category: model.CatPersistence, Weight: 10,
				Evidence:       []i18n.Msg{describeUnusual(f, fi, err)},
				Recommendation: i18n.T("rule.ssh_keys_not_regular.rec", filepath.Dir(rel)),
			}, rel, model.RiskLow, fi.ModTime()))
			continue
		}
		if err != nil {
			continue
		}
		lines := meaningfulLines(string(data))
		var cmdHits []i18n.Msg
		for i, l := range lines {
			if strings.Contains(l, "command=") && persistPattern.MatchString(l) {
				cmdHits = append(cmdHits, i18n.T("ev.key_command", i+1))
			}
		}
		if len(cmdHits) > 0 {
			out = append(out, sys(model.Finding{
				ID: "ssh_key_command", Title: i18n.T("rule.ssh_key_command.title"), Category: model.CatPersistence, Weight: 25,
				Evidence:       cmdHits,
				Recommendation: i18n.T("rule.ssh_key_command.rec"),
			}, rel, model.RiskMedium, fi.ModTime()))
		}
		if fi.ModTime().After(recent) {
			out = append(out, sys(model.Finding{
				ID: "ssh_keys_recent", Title: i18n.T("rule.ssh_keys_recent.title"), Category: model.CatPersistence, Weight: 10,
				Evidence:       []i18n.Msg{i18n.T("ev.modified_keys", fi.ModTime().Format("2006-01-02 15:04"), len(lines))},
				Recommendation: i18n.T("rule.ssh_keys_recent.rec", rel),
			}, rel, model.RiskLow, fi.ModTime()))
		}
	}
	return out
}

func sys(f model.Finding, path string, r model.Risk, mt time.Time) model.SystemFinding {
	return model.SystemFinding{Finding: f, Path: path, Risk: r, ModTime: mt}
}

// describeUnusual — пояснение, почему файл проверки не прочитан.
func describeUnusual(path string, fi fs.FileInfo, err error) i18n.Msg {
	switch {
	case errors.Is(err, safefile.ErrTooLarge):
		return i18n.T("ev.file_too_large", fi.Size())
	case fi.Mode()&fs.ModeSymlink != 0:
		target, _ := os.Readlink(path)
		return i18n.T("ev.file_symlink", target)
	case fi.Mode()&fs.ModeNamedPipe != 0:
		return i18n.T("ev.file_fifo")
	case fi.Mode()&fs.ModeDevice != 0:
		return i18n.T("ev.file_device")
	case fi.IsDir():
		return i18n.T("ev.file_dir")
	}
	return i18n.T("ev.file_type", fi.Mode().Type().String())
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

// Пакет audit проверяет конфигурацию сервера: SSH, учётные записи и sudo.
// В отличие от detect, он смотрит не на поведение процессов, а на
// причины взлома: вход по паролю, лишний UID 0, NOPASSWD: ALL.
//
// Аудит только читает файлы. Исправления предлагаются текстом команды
// (AuditCheck.FixCommand), выполняет их администратор. Хеши паролей из
// /etc/shadow никуда не выводятся и не сохраняются: используется только
// тип алгоритма и признак «пусто / заблокировано».
package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// maxConfigFile — предел размера читаемого конфигурационного файла.
const maxConfigFile = 1 << 20

// maxEvidence — сколько строк фактов в одной проверке.
const maxEvidence = 20

// maxLine — длина строки конфигурации в доказательствах.
const maxLine = 200

// Options — параметры одного запуска аудита.
type Options struct {
	// HostRoot — корень хоста (SSG_HOST_ROOT); все пути читаются
	// относительно него.
	HostRoot string
	// RootUID — UID, который считается root при проверке владельцев
	// файлов. На сервере 0; в тестах и демо — UID пользователя, записавшего
	// поддельное дерево.
	RootUID int
	// Baseline — состояние прошлого запуска для проверок изменений
	// (новые пользователи, изменения sudoers). nil — такие проверки n/a
	// (разовый запуск без службы).
	Baseline *Baseline
	// Now — время запуска (для тестов); нулевое — текущее.
	Now time.Time
}

// ChangeWindow — сколько проверка изменений (новый пользователь, правка
// sudoers) остаётся «опасной» после обнаружения. Без этого следующий
// запуск (через час или по кнопке) уже сравнивал бы с новой базовой
// линией, и тревога гасла бы сама, как будто всё исправили.
const ChangeWindow = 24 * time.Hour

// maxRecent — сколько недавних изменений хранить в базовой линии.
const maxRecent = 500

// Change — обнаруженное изменение (новый пользователь, правка sudoers).
type Change struct {
	Time     time.Time `json:"time"`
	Check    string    `json:"check"` // ID проверки
	Fail     bool      `json:"fail"`  // опасно (иначе — требует внимания)
	Evidence i18n.Msg  `json:"evidence"`
}

// Baseline — то, что запоминается между запусками аудита.
type Baseline struct {
	// Init — базовая линия уже снята (после первого запуска).
	Init bool `json:"init"`
	// Users — имя пользователя → UID.
	Users map[string]int `json:"users"`
	// Priv — члены привилегированных групп: группа → отсортированный список.
	Priv map[string][]string `json:"priv"`
	// Sudoers — путь файла sudoers → SHA-256 содержимого.
	Sudoers map[string]string `json:"sudoers"`
	// Recent — изменения за последние ChangeWindow.
	Recent []Change `json:"recent,omitempty"`
}

// Run выполняет все проверки и возвращает их результаты и новую базовую
// линию (её нужно передать в следующий запуск).
func Run(opt Options) ([]model.AuditCheck, Baseline) {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	a := &auditor{opt: opt, next: Baseline{Init: true, Users: map[string]int{}, Priv: map[string][]string{}, Sudoers: map[string]string{}}}
	if b := opt.Baseline; b != nil {
		for _, c := range b.Recent {
			if opt.Now.Sub(c.Time) < ChangeWindow {
				a.next.Recent = append(a.next.Recent, c)
			}
		}
	}
	var out []model.AuditCheck
	out = append(out, a.sshChecks()...)
	out = append(out, a.accountChecks()...)
	out = append(out, a.sudoChecks()...)
	// Источник не прочитался (нет прав, файл заменяют прямо сейчас) —
	// его раздел базовой линии остаётся прежним. Иначе следующий запуск
	// счёл бы всех пользователей и все файлы sudoers новыми.
	if b := opt.Baseline; b != nil {
		if !a.usersRead {
			a.next.Users = b.Users
		}
		if !a.groupsRead {
			a.next.Priv = b.Priv
		}
		if !a.sudoRead {
			a.next.Sudoers = b.Sudoers
		}
	}
	if n := len(a.next.Recent); n > maxRecent {
		a.next.Recent = a.next.Recent[n-maxRecent:]
	}
	return out, a.next
}

// auditor — общий контекст проверок одного запуска.
type auditor struct {
	opt  Options
	next Baseline
	// Какие источники базовой линии прочитаны в этом запуске.
	usersRead, groupsRead, sudoRead bool
}

// change запоминает обнаруженное изменение.
func (a *auditor) change(check string, fail bool, ev i18n.Msg) {
	a.next.Recent = append(a.next.Recent, Change{Time: a.opt.Now, Check: check, Fail: fail, Evidence: ev})
}

// applyRecent переводит проверку в fail/warn, если за последние
// ChangeWindow у неё были изменения, и показывает их со временем.
// Возвращает true, если изменения были.
func (a *auditor) applyRecent(c *model.AuditCheck) bool {
	found := false
	for _, ch := range a.next.Recent {
		if ch.Check != c.ID {
			continue
		}
		found = true
		st := model.AuditWarn
		if ch.Fail {
			st = model.AuditFail
		}
		if worse(st, c.Status) {
			c.Status = st
		}
		addEv(c, i18n.T("ev.audit_change_at", ch.Evidence, ch.Time.Local().Format("2006-01-02 15:04")))
	}
	return found
}

// host — путь внутри корня хоста.
func (a *auditor) host(p string) string { return filepath.Join(a.opt.HostRoot, p) }

// rel — путь для показа: относительно корня хоста, с ведущим «/».
func (a *auditor) rel(p string) string {
	r, err := filepath.Rel(filepath.Clean(a.opt.HostRoot), p)
	if err != nil || strings.HasPrefix(r, "..") {
		return p
	}
	return "/" + r
}

// read безопасно читает конфигурационный файл (только обычный файл, с
// лимитом размера). follow — переходить ли по симлинку: системные
// конфиги принадлежат root, а файлы в домашних каталогах — нет.
func (a *auditor) read(p string, follow bool) ([]byte, error) {
	data, _, err := safefile.ReadRegular(a.host(p), maxConfigFile, follow)
	return data, err
}

// isPerm — ошибка нехватки прав: проверка получает статус unknown.
func isPerm(err error) bool { return errors.Is(err, fs.ErrPermission) }

// isRoot — файл принадлежит root (или RootUID в тестах).
func (a *auditor) isRoot(fi fs.FileInfo) bool {
	uid, _, ok := owner(fi)
	return !ok || uid == a.opt.RootUID
}

// writableByOthers — файл или каталог может изменить не root: владелец
// не root, запись для всех или для группы, отличной от root.
func (a *auditor) writableByOthers(fi fs.FileInfo) bool {
	m := fi.Mode().Perm()
	_, gid, ok := owner(fi)
	groupRoot := !ok || gid == 0 || gid == a.opt.RootUID
	return !a.isRoot(fi) || m&0o002 != 0 || (m&0o020 != 0 && !groupRoot)
}

// describe — «права 0644, владелец UID 1000» для доказательств.
func describe(fi fs.FileInfo) string {
	uid, gid, ok := owner(fi)
	if !ok {
		return fmt.Sprintf("%04o", fi.Mode().Perm())
	}
	return fmt.Sprintf("%04o uid=%d gid=%d", fi.Mode().Perm(), uid, gid)
}

// newCheck — заготовка результата проверки.
func newCheck(id, group string, sev model.Risk, titleKey string, refs ...string) model.AuditCheck {
	return model.AuditCheck{ID: id, Group: group, Title: i18n.T(titleKey), Severity: sev, Status: model.AuditPass, References: refs}
}

// addEv добавляет факт, не больше maxEvidence.
func addEv(c *model.AuditCheck, m i18n.Msg) {
	if len(c.Evidence) < maxEvidence {
		c.Evidence = append(c.Evidence, m)
	}
}

// at — «файл:строка  текст» для доказательств.
func at(file string, line int, text string) i18n.Msg {
	if line > 0 {
		return i18n.L(fmt.Sprintf("%s:%d  %s", file, line, truncate(text, maxLine)))
	}
	return i18n.L(fmt.Sprintf("%s  %s", file, truncate(text, maxLine)))
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// worse — status a хуже b (для сведения нескольких фактов в один итог).
func worse(a, b string) bool { return statusRank(a) > statusRank(b) }

func statusRank(s string) int {
	switch s {
	case model.AuditFail:
		return 5
	case model.AuditWarn:
		return 4
	case model.AuditUnknown:
		return 3
	case model.AuditInfo:
		return 2
	case model.AuditPass:
		return 1
	}
	return 0
}

// sortedKeys — ключи карты по порядку (для стабильного вывода).
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lstat/stat относительно корня хоста.
func (a *auditor) lstat(p string) (fs.FileInfo, error) { return os.Lstat(a.host(p)) }
func (a *auditor) stat(p string) (fs.FileInfo, error)  { return os.Stat(a.host(p)) }

// Summary — сводка «пройдено N из M»: pass среди проверок со статусом
// pass, fail или warn (советы, n/a и unknown не учитываются).
func Summary(checks []model.AuditCheck) (pass, total int) {
	for _, c := range checks {
		switch c.Status {
		case model.AuditPass:
			pass++
			total++
		case model.AuditFail, model.AuditWarn:
			total++
		}
	}
	return pass, total
}

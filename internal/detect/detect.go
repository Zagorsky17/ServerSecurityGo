// Пакет detect анализирует процессы и выставляет уровень риска.
//
// Принципы:
//   - каждое правило выдаёт признак (model.Finding) с проверяемыми
//     фактами: что прочитано и откуда. Вывод «это вредонос» правило не
//     делает никогда;
//   - итоговый уровень зависит от суммы весов и от числа независимых
//     категорий признаков. Один признак (имя, путь или нагрузка) сам по
//     себе не поднимает риск выше LOW, а «сильный» — выше MEDIUM;
//   - справочные признаки (категория info) показываются, но не влияют на
//     оценку;
//   - allowlist подавляет известные легитимные срабатывания, но не
//     скрывает их: подавленный признак виден с пометкой.
package detect

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// Config — пороги и настройки анализа.
type Config struct {
	CPUThreshold   float64 // % CPU, выше которого нагрузка считается высокой
	CPUSustainScan int     // сколько сканирований подряд нужно для признака
	MemThreshold   float64 // % RAM
	ScanInterval   time.Duration
	RecentDays     int // «недавно изменённые» файлы для системных проверок
	Allow          []AllowRule
}

// DefaultConfig — значения по умолчанию.
func DefaultConfig() Config {
	return Config{CPUThreshold: 80, CPUSustainScan: 10, MemThreshold: 50, ScanInterval: 30 * time.Second, RecentDays: 7}
}

// Counters — данные из истории, нужные правилам поведения.
type Counters struct {
	HighCPUScans int
	HighMemScans int
}

// Context — всё, что правило может узнать о системе помимо процесса.
type Context struct {
	Cfg      Config
	ByPID    map[int]*model.Process
	Counters func(key string) Counters
	Now      time.Time
}

func (c *Context) parent(p *model.Process) *model.Process {
	if c.ByPID == nil {
		return nil
	}
	return c.ByPID[p.PPID]
}

// Rule — правило обнаружения.
type Rule func(p *model.Process, c *Context) []model.Finding

// Rules — все процессные правила в порядке применения.
var Rules = []Rule{
	ruleExeLocation,
	ruleHiddenPath,
	ruleCwdTemp,
	ruleExeDeleted,
	ruleMemfd,
	ruleExePerms,
	ruleKthreadMasquerade,
	ruleSystemNameMasquerade,
	ruleNameMismatch,
	ruleUnusualName,
	ruleEmptyCmdline,
	ruleCmdlineTruncated,
	ruleWebShellChain,
	ruleSchedulerChain,
	ruleStdioSocket,
	ruleReverseShellPattern,
	ruleDownloadExec,
	ruleMinerPattern,
	ruleMinerName,
	rulePoolPort,
	ruleShellOutbound,
	ruleSuspiciousListen,
	ruleCPUSustained,
	ruleMemSustained,
	ruleLDPreload,
	ruleRootFromWritable,
	ruleInfoContainer,
	ruleInfoListen,
	ruleInfoAccess,
}

// Analyze применяет правила ко всем процессам и заполняет поля
// Findings, Score, Risk, Explanation и Recommendations.
func Analyze(procs []*model.Process, c *Context) {
	if c.ByPID == nil {
		c.ByPID = make(map[int]*model.Process, len(procs))
		for _, p := range procs {
			c.ByPID[p.PID] = p
		}
	}
	if c.Counters == nil {
		c.Counters = func(string) Counters { return Counters{} }
	}
	for _, p := range procs {
		AnalyzeOne(p, c)
	}
}

// AnalyzeOne анализирует один процесс.
func AnalyzeOne(p *model.Process, c *Context) {
	var findings []model.Finding
	for _, r := range Rules {
		findings = append(findings, r(p, c)...)
	}
	for i := range findings {
		if c.Cfg.allowed(p, findings[i].ID) {
			findings[i].Suppressed = true
		}
	}
	p.Findings = findings
	p.Score, p.Risk, p.Explanation = Score(findings)
	p.Recommendations = recommendations(p, findings)
}

// Пороги суммы весов для уровней.
const (
	thrLow      = 1
	thrMedium   = 15
	thrHigh     = 35
	thrCritical = 60
)

// Score вычисляет баллы, уровень и текстовое объяснение оценки.
func Score(findings []model.Finding) (int, model.Risk, string) {
	score := 0
	cats := map[string]bool{}
	strong := 0
	var active []model.Finding
	suppressed := 0
	for _, f := range findings {
		if f.Category == model.CatInfo {
			continue
		}
		if f.Suppressed {
			suppressed++
			continue
		}
		score += f.Weight
		cats[f.Category] = true
		if f.Strong {
			strong++
		}
		active = append(active, f)
	}

	var risk model.Risk
	switch {
	case score >= thrCritical:
		risk = model.RiskCritical
	case score >= thrHigh:
		risk = model.RiskHigh
	case score >= thrMedium:
		risk = model.RiskMedium
	case score >= thrLow:
		risk = model.RiskLow
	default:
		risk = model.RiskInfo
	}

	// Ограничение по числу независимых категорий: «громкий» признак
	// одного типа не должен давать HIGH/CRITICAL без подтверждения.
	limit := model.RiskCritical
	limitReason := ""
	switch n := len(cats); {
	case n == 1 && strong == 0:
		limit, limitReason = model.RiskLow, "все признаки одной категории и ни одного сильного — не выше LOW"
	case n == 1:
		limit, limitReason = model.RiskMedium, "признаки только одной категории — не выше MEDIUM"
	case n == 2 && strong < 2:
		limit, limitReason = model.RiskHigh, "признаки двух категорий — не выше HIGH (для CRITICAL нужны 3 категории или 2 сильных признака)"
	}
	capped := false
	if risk > limit {
		risk, capped = limit, true
	}

	var b strings.Builder
	if len(active) == 0 {
		b.WriteString("Подозрительных признаков не обнаружено.")
		if suppressed > 0 {
			fmt.Fprintf(&b, " Подавлено правилами allowlist: %d.", suppressed)
		}
		return 0, model.RiskInfo, b.String()
	}
	catNames := make([]string, 0, len(cats))
	for k := range cats {
		catNames = append(catNames, CategoryTitle(k))
	}
	sort.Strings(catNames)
	fmt.Fprintf(&b, "Итог %s: %d балл(ов), признаков — %d, категорий — %d (%s), сильных — %d. ",
		risk, score, len(active), len(cats), strings.Join(catNames, ", "), strong)
	parts := make([]string, 0, len(active))
	for _, f := range active {
		s := fmt.Sprintf("«%s» +%d", f.Title, f.Weight)
		if f.Strong {
			s += " (сильный)"
		}
		parts = append(parts, s)
	}
	b.WriteString("Сработали: " + strings.Join(parts, "; ") + ". ")
	fmt.Fprintf(&b, "Шкала: LOW от %d, MEDIUM от %d, HIGH от %d, CRITICAL от %d баллов.", thrLow, thrMedium, thrHigh, thrCritical)
	if capped {
		b.WriteString(" Уровень ограничен: " + limitReason + ".")
	}
	if suppressed > 0 {
		fmt.Fprintf(&b, " Подавлено правилами allowlist: %d.", suppressed)
	}
	b.WriteString(" Это оценка по косвенным признакам, а не доказательство компрометации.")
	return score, risk, b.String()
}

// CategoryTitle — русское название категории.
func CategoryTitle(c string) string {
	switch c {
	case model.CatLocation:
		return "расположение"
	case model.CatIntegrity:
		return "целостность файла"
	case model.CatMasquerade:
		return "маскировка/имя"
	case model.CatChain:
		return "цепочка запуска"
	case model.CatNetwork:
		return "сеть"
	case model.CatContent:
		return "командная строка"
	case model.CatBehavior:
		return "поведение"
	case model.CatEnvironment:
		return "окружение"
	case model.CatPrivilege:
		return "привилегии"
	case model.CatPersistence:
		return "закрепление"
	default:
		return "справка"
	}
}

// recommendations собирает уникальные рекомендации из признаков и
// добавляет общие шаги проверки для процессов с риском от MEDIUM.
func recommendations(p *model.Process, findings []model.Finding) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, f := range findings {
		if !f.Suppressed && f.Category != model.CatInfo {
			add(f.Recommendation)
		}
	}
	if p.Risk >= model.RiskMedium {
		add(fmt.Sprintf("Сохраните сведения до любых действий: ls -l /proc/%d/exe /proc/%d/cwd; cat /proc/%d/maps; ss -tunap | grep 'pid=%d,'", p.PID, p.PID, p.PID, p.PID))
		add(fmt.Sprintf("Снимите копию исполняемого файла для анализа: cp /proc/%d/exe /root/evidence-%d.bin && sha256sum /root/evidence-%d.bin", p.PID, p.PID, p.PID))
		add("Приложение ничего не завершает и не удаляет. Решение о действиях (изоляция, остановка, расследование) принимает администратор.")
	}
	return out
}

// AllowRule — правило подавления признаков для известных легитимных
// процессов. Пустое поле означает «любое значение». Exe и Name
// поддерживают шаблоны filepath.Match (например, /opt/app/bin/*).
type AllowRule struct {
	Exe     string   `json:"exe"`
	Name    string   `json:"name"`
	User    string   `json:"user"`
	Rules   []string `json:"rules"` // ID правил; пусто — все правила
	Comment string   `json:"comment"`
}

func (cfg Config) allowed(p *model.Process, ruleID string) bool {
	for _, a := range cfg.Allow {
		if a.Exe == "" && a.Name == "" && a.User == "" {
			continue // правило без условий подавляло бы всё — игнорируем
		}
		if a.Exe != "" && !globMatch(a.Exe, p.Exe) {
			continue
		}
		if a.Name != "" && !globMatch(a.Name, p.Name) {
			continue
		}
		if a.User != "" && a.User != p.User {
			continue
		}
		if len(a.Rules) > 0 && !slices.Contains(a.Rules, ruleID) {
			continue
		}
		return true
	}
	return false
}

func globMatch(pattern, s string) bool {
	if pattern == s {
		return true
	}
	ok, err := filepath.Match(pattern, s)
	return err == nil && ok
}

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
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
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
	// Exposed — опасные публичные порты (exposure.Build) по inode сокета.
	// nil — доступность портов не оценивалась.
	Exposed map[uint64]*model.Exposure
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
	ruleUnicodeControl,
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
	ruleExposure,
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

// Score вычисляет баллы, уровень и объяснение оценки.
func Score(findings []model.Finding) (int, model.Risk, i18n.Msg) {
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
	var limitReason i18n.Msg
	switch n := len(cats); {
	case n == 1 && strong == 0:
		limit, limitReason = model.RiskLow, i18n.T("score.limit_one_weak")
	case n == 1:
		limit, limitReason = model.RiskMedium, i18n.T("score.limit_one")
	case n == 2 && strong < 2:
		limit, limitReason = model.RiskHigh, i18n.T("score.limit_two")
	}
	capped := false
	if risk > limit {
		risk, capped = limit, true
	}

	var out []i18n.Msg
	if len(active) == 0 {
		out = append(out, i18n.T("score.none"))
		if suppressed > 0 {
			out = append(out, i18n.T("score.suppressed", suppressed))
		}
		return 0, model.RiskInfo, i18n.Join(" ", out...)
	}
	catIDs := make([]string, 0, len(cats))
	for k := range cats {
		catIDs = append(catIDs, k)
	}
	sort.Strings(catIDs)
	catNames := make([]i18n.Msg, len(catIDs))
	for i, k := range catIDs {
		catNames[i] = CategoryTitle(k)
	}
	out = append(out, i18n.T("score.total", risk, score, len(active), len(cats), i18n.Join(", ", catNames...), strong))
	parts := make([]i18n.Msg, 0, len(active))
	for _, f := range active {
		if f.Strong {
			parts = append(parts, i18n.T("score.part_strong", f.Title, f.Weight))
		} else {
			parts = append(parts, i18n.T("score.part", f.Title, f.Weight))
		}
	}
	out = append(out, i18n.T("score.fired", i18n.Join("; ", parts...)))
	out = append(out, i18n.T("score.scale", thrLow, thrMedium, thrHigh, thrCritical))
	if capped {
		out = append(out, i18n.T("score.capped", limitReason))
	}
	if suppressed > 0 {
		out = append(out, i18n.T("score.suppressed", suppressed))
	}
	out = append(out, i18n.T("score.disclaimer"))
	return score, risk, i18n.Join(" ", out...)
}

// categories — известные категории признаков (ключи каталога cat.<id>).
var categories = map[string]bool{
	model.CatLocation: true, model.CatIntegrity: true, model.CatMasquerade: true, model.CatChain: true,
	model.CatNetwork: true, model.CatContent: true, model.CatBehavior: true, model.CatEnvironment: true,
	model.CatPrivilege: true, model.CatPersistence: true, model.CatExposure: true, model.CatInfo: true,
}

// CategoryTitle — переводимое название категории; неизвестная
// категория считается справочной.
func CategoryTitle(c string) i18n.Msg {
	if !categories[c] {
		c = model.CatInfo
	}
	return i18n.T("cat." + c)
}

// recommendations собирает уникальные рекомендации из признаков и
// добавляет общие шаги проверки для процессов с риском от MEDIUM.
func recommendations(p *model.Process, findings []model.Finding) []i18n.Msg {
	var out []i18n.Msg
	seen := map[string]bool{}
	add := func(m i18n.Msg) {
		// Сравнение по русскому тексту: одинаковые рекомендации разных
		// признаков совпадают на любом языке.
		if s := m.In(i18n.RU); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, m)
		}
	}
	for _, f := range findings {
		if !f.Suppressed && f.Category != model.CatInfo {
			add(f.Recommendation)
		}
	}
	if p.Risk >= model.RiskMedium {
		add(i18n.T("rec.preserve", p.PID))
		add(i18n.T("rec.copy_exe", p.PID))
		add(i18n.T("rec.admin_decides"))
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

// Allowed сообщает, что правило allowlist подавляет признак ruleID для
// процесса p. Нужен и вне пакета: так же подавляются системные находки
// о доступности порта, который держит этот процесс.
func (cfg Config) Allowed(p *model.Process, ruleID string) bool { return cfg.allowed(p, ruleID) }

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
		// Имя (comm) процесс меняет сам (prctl, exec -a): правило только по
		// имени подавило бы признаки майнера, назвавшегося «node». Поэтому
		// без exe имя должно совпасть и с именем исполняемого файла (comm
		// обрезается до 15 байт — сравниваем и с обрезанным); exe не
		// прочитан — правило не срабатывает.
		if a.Exe == "" && a.Name != "" && !nameMatchesExe(a.Name, p.Exe) {
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

func nameMatchesExe(pattern, exe string) bool {
	if exe == "" {
		return false
	}
	base := filepath.Base(exe)
	return globMatch(pattern, base) || (len(base) > 15 && globMatch(pattern, base[:15]))
}

// WeakAllowRules описывает правила allowlist, которые легко обойти: без
// exe (имя и пользователь не привязаны к исполняемому файлу). Служба
// пишет их в журнал при запуске.
func WeakAllowRules(rules []AllowRule) []string {
	var out []string
	for i, a := range rules {
		if a.Exe != "" || (a.Name == "" && a.User == "") {
			continue
		}
		what := fmt.Sprintf("(name=%q user=%q)", a.Name, a.User)
		if a.Name == "" {
			out = append(out, i18n.S("allow.weak_user_only", i+1, what))
		} else {
			out = append(out, i18n.S("allow.weak_no_exe", i+1, what))
		}
	}
	return out
}

func globMatch(pattern, s string) bool {
	if pattern == s {
		return true
	}
	ok, err := filepath.Match(pattern, s)
	return err == nil && ok
}

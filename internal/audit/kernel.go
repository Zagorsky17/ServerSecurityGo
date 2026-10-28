package audit

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/exposure"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fail2ban"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// sysctlFile — файл, в который предлагается дописать параметр ядра.
// Отдельный файл в /etc/sysctl.d не конфликтует с /etc/sysctl.conf
// дистрибутива и применяется командой sysctl --system.
const sysctlFile = "/etc/sysctl.d/90-hardening.conf"

// maxSysctl — предел размера файла /proc/sys (у них размер 0, но путь
// может оказаться подменён).
const maxSysctl = 4096

// Как сравнивается значение параметра с ожидаемым.
const (
	opEq  = "="
	opMin = ">="
	opMax = "<="
)

// sysctlRule — ожидание для одного числового параметра /proc/sys.
type sysctlRule struct {
	id   string
	name string // путь внутри /proc/sys
	// title, rec — ключи каталога. Литералы, а не склейка с id:
	// keys_test сверяет ключи из кода с каталогом.
	title, rec string
	op         string
	want       int
	sev        model.Risk
	// bad — статус при отклонении: warn для настроек, которые стоит
	// поправить, info для советов.
	bad string
	// optional — параметра может не быть (модуль ядра не загружен), и
	// это не «нет данных», а «неприменимо».
	optional bool
}

// netSysctls — готовность сети к атаке (раздел 16.4 плана). Значения
// консервативные: агрессивная «оптимизация» sysctl из интернет-советов
// ломает сервер чаще, чем помогает.
var netSysctls = []sysctlRule{
	{id: "net_syncookies", title: "audit.net_syncookies.title", rec: "audit.net_syncookies.rec", name: "net/ipv4/tcp_syncookies", op: opEq, want: 1, sev: model.RiskLow, bad: model.AuditWarn},
	{id: "net_syn_backlog", title: "audit.net_syn_backlog.title", rec: "audit.net_syn_backlog.rec", name: "net/ipv4/tcp_max_syn_backlog", op: opMin, want: 1024, sev: model.RiskInfo, bad: model.AuditInfo},
	{id: "net_somaxconn", title: "audit.net_somaxconn.title", rec: "audit.net_somaxconn.rec", name: "net/core/somaxconn", op: opMin, want: 1024, sev: model.RiskInfo, bad: model.AuditInfo},
	{id: "net_synack_retries", title: "audit.net_synack_retries.title", rec: "audit.net_synack_retries.rec", name: "net/ipv4/tcp_synack_retries", op: opMax, want: 3, sev: model.RiskInfo, bad: model.AuditInfo},
	{id: "net_conntrack_max", title: "audit.net_conntrack_max.title", rec: "audit.net_conntrack_max.rec", name: "net/netfilter/nf_conntrack_max", op: opMin, want: 65536, sev: model.RiskLow, bad: model.AuditWarn, optional: true},
	{id: "net_icmp_broadcast", title: "audit.net_icmp_broadcast.title", rec: "audit.net_icmp_broadcast.rec", name: "net/ipv4/icmp_echo_ignore_broadcasts", op: opEq, want: 1, sev: model.RiskLow, bad: model.AuditWarn},
}

// kernelChecks — группа «Ядро»: параметры /proc/sys и ограничение
// частоты подключений к SSH (раздел 16.4 плана).
func (a *auditor) kernelChecks() []model.AuditCheck {
	out := make([]model.AuditCheck, 0, len(netSysctls)+1)
	for _, r := range netSysctls {
		out = append(out, a.sysctlCheck(r))
	}
	return append(out, a.sshRateLimit())
}

// sysctl читает числовой параметр ядра из /proc/sys.
func (a *auditor) sysctl(name string) (int, error) {
	data, _, err := safefile.ReadRegular(filepath.Join(a.opt.ProcRoot, "sys", name), maxSysctl, true)
	if err != nil {
		return 0, err
	}
	// В файле может быть несколько значений (например, per-CPU): берём
	// первое поле — у проверяемых здесь параметров оно одно.
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, strconv.ErrSyntax
	}
	return strconv.Atoi(f[0])
}

func (a *auditor) sysctlCheck(r sysctlRule) model.AuditCheck {
	ch := newCheck(r.id, model.AuditGroupKernel, r.sev, r.title)
	shown := "/proc/sys/" + r.name
	val, err := a.sysctl(r.name)
	switch {
	case err == nil:
	case isPerm(err):
		ch.Status = model.AuditUnknown
		addEv(&ch, i18n.T("ev.audit_no_access", shown))
		return ch
	case r.optional:
		ch.Status = model.AuditNA
		addEv(&ch, i18n.T("ev.audit_sysctl_absent", shown))
		return ch
	default:
		ch.Status = model.AuditUnknown
		addEv(&ch, i18n.T("ev.audit_sysctl_absent", shown))
		return ch
	}
	addEv(&ch, i18n.L(shown+" = "+strconv.Itoa(val)))
	ok := false
	switch r.op {
	case opEq:
		ok = val == r.want
	case opMin:
		ok = val >= r.want
	case opMax:
		ok = val <= r.want
	}
	if ok {
		return ch
	}
	addEv(&ch, i18n.T("ev.audit_sysctl_want", r.op+" "+strconv.Itoa(r.want)))
	ch.Status = r.bad
	ch.Recommendation = i18n.T(r.rec)
	ch.FixCommand = sysctlFix(r.name, r.want)
	return ch
}

// sysctlFix — команда, дописывающая параметр в /etc/sysctl.d: значение
// сохранится после перезагрузки, в отличие от sysctl -w.
func sysctlFix(name string, want int) string {
	key := strings.ReplaceAll(name, "/", ".")
	return "echo '" + key + " = " + strconv.Itoa(want) + "' >> " + sysctlFile + " && sysctl --system"
}

// sshRateLimit — ограничена ли частота подключений к SSH: правило
// «ufw limit» или jail fail2ban. Без ограничения перебор паролей и
// простой поток подключений ничем не сдерживаются.
func (a *auditor) sshRateLimit() model.AuditCheck {
	ch := newCheck("fw_ssh_ratelimit", model.AuditGroupKernel, model.RiskInfo, "audit.fw_ssh_ratelimit.title", "T1110")
	port := 22
	if n, err := strconv.Atoi(a.parseSSHD().setting("port").val); err == nil && n > 0 {
		port = n
	}
	if fail2ban.SSHJail(a.opt.HostRoot) {
		addEv(&ch, i18n.T("ev.audit_f2b_jail"))
		return ch
	}
	if exposure.ReadUFW(a.opt.HostRoot).RateLimited("tcp", port) {
		addEv(&ch, i18n.T("ev.audit_ufw_limit", port))
		return ch
	}
	ch.Status = model.AuditInfo
	addEv(&ch, i18n.T("ev.audit_no_ratelimit", port))
	ch.Recommendation = i18n.T("audit.fw_ssh_ratelimit.rec", port)
	ch.FixCommand = "ufw limit " + strconv.Itoa(port) + "/tcp"
	return ch
}

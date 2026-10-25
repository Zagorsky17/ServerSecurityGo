package exposure

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// maxConfigFile — предел размера конфигурационных файлов ufw и Docker.
const maxConfigFile = 1 << 20

// maxUFWRules — сколько правил ufw разбирать (защита от огромного файла).
const maxUFWRules = 10_000

// ufwRule — одно правило из /etc/ufw/user.rules (строка «### tuple ###»).
type ufwRule struct {
	action string // allow, limit, deny, reject
	proto  string // tcp, udp, any
	dport  string // any, 22, 80,443, 8000:8100
	src    string
	in     bool // входящее правило
}

// UFW — разобранная конфигурация ufw. Правила IPv4 (user.rules) и IPv6
// (user6.rules) хранятся раздельно: ufw применяет их к своему семейству
// адресов, и правило одного семейства не решает судьбу порта другого.
type UFW struct {
	Info   model.FirewallInfo
	rules4 []ufwRule
	rules6 []ufwRule
}

// Семейства адресов сокета для PortState.
const (
	Fam4    = 4  // IPv4
	Fam6    = 6  // IPv6
	FamBoth = 46 // [::] без IPV6_V6ONLY принимает и IPv4, и IPv6
)

// active — ufw включён и по умолчанию не пропускает входящие: только
// тогда его правила что-то закрывают.
func (u *UFW) active() bool {
	return u != nil && u.Info.UFW == "active" && u.Info.DefaultInput != "ACCEPT"
}

// ReadUFW читает состояние ufw относительно корня хоста. Файлы
// принадлежат root; по симлинкам идём, но читаем безопасно (без
// блокировки на FIFO, с лимитом размера).
func ReadUFW(hostRoot string) *UFW {
	h := func(p string) string { return filepath.Join(hostRoot, p) }
	u := &UFW{Info: model.FirewallInfo{UFW: "absent"}}
	data, _, err := safefile.ReadRegular(h("etc/ufw/ufw.conf"), maxConfigFile, true)
	if err != nil {
		return u
	}
	u.Info.UFW = "inactive"
	if strings.EqualFold(shellValue(string(data), "ENABLED"), "yes") {
		u.Info.UFW = "active"
	}
	// Политика по умолчанию — в /etc/default/ufw. Нет файла — у ufw
	// политика DROP.
	u.Info.DefaultInput = "DROP"
	if data, _, err := safefile.ReadRegular(h("etc/default/ufw"), maxConfigFile, true); err == nil {
		if v := strings.ToUpper(shellValue(string(data), "DEFAULT_INPUT_POLICY")); v != "" {
			u.Info.DefaultInput = v
		}
	}
	if data, _, err := safefile.ReadRegular(h("etc/ufw/user.rules"), maxConfigFile, true); err == nil {
		u.rules4 = ParseUFWRules(string(data))
	}
	if data, _, err := safefile.ReadRegular(h("etc/ufw/user6.rules"), maxConfigFile, true); err == nil {
		u.rules6 = ParseUFWRules(string(data))
	}
	u.Info.Rules = len(u.rules4) + len(u.rules6)
	return u
}

// shellValue — значение KEY=value из файла в формате shell (кавычки
// снимаются, последнее присваивание побеждает).
func shellValue(data, key string) string {
	v := ""
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, key+"="); ok {
			v = strings.Trim(strings.TrimSpace(rest), `"'`)
		}
	}
	return v
}

// ParseUFWRules разбирает строки «### tuple ###» из user.rules. Формат
// (ufw/common.py): действие протокол dport dst sport src [dapp sapp]
// направление [comment=…]. Маршрутизируемые правила (route:…) не
// относятся к входящим соединениям сервера и пропускаются.
func ParseUFWRules(data string) []ufwRule {
	var out []ufwRule
	for line := range strings.SplitSeq(data, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "### tuple ###")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		// Комментарий в конце не относится к правилу.
		for len(f) > 0 && strings.HasPrefix(f[len(f)-1], "comment=") {
			f = f[:len(f)-1]
		}
		if len(f) < 7 || strings.HasPrefix(f[0], "route:") {
			continue
		}
		dir := f[len(f)-1]
		// С журналированием ufw дописывает тип журнала к действию:
		// allow_log, allow_log-all, deny_log. Решение — часть до «_».
		action, _, _ := strings.Cut(strings.ToLower(f[0]), "_")
		out = append(out, ufwRule{
			action: action, proto: strings.ToLower(f[1]), dport: f[2], src: f[5],
			in: dir == "in" || strings.HasPrefix(dir, "in_"),
		})
		if len(out) >= maxUFWRules {
			break
		}
	}
	return out
}

// anyAddr — адрес «откуда угодно / куда угодно» в правиле ufw.
func anyAddr(a string) bool { return a == "0.0.0.0/0" || a == "::/0" || a == "any" }

// portIn сообщает, входит ли порт в спецификацию ufw: any, 22,
// 80,443, 8000:8100 и их сочетания через запятую.
func portIn(spec string, port int) bool {
	if spec == "any" {
		return true
	}
	for part := range strings.SplitSeq(spec, ",") {
		lo, hi, isRange := strings.Cut(part, ":")
		a, err1 := strconv.Atoi(lo)
		if !isRange {
			if err1 == nil && a == port {
				return true
			}
			continue
		}
		b, err2 := strconv.Atoi(hi)
		if err1 == nil && err2 == nil && port >= a && port <= b {
			return true
		}
	}
	return false
}

// PortState — что ufw делает с входящими на порт со всего интернета:
// FwOpen (разрешено правилом для любых адресов), FwFiltered (не
// разрешено) или "" (ufw выключен или пропускает всё по умолчанию —
// тогда ничего не известно). Правила проверяются по порядку, первое
// подходящее решает, как и в самом ufw. Правила с конкретным адресом
// источника порт для всего интернета не открывают и пропускаются.
//
// fam — семейство адресов сокета (Fam4, Fam6, FamBoth). Для FamBoth
// порт открыт, если его открывают правила любого из семейств.
func (u *UFW) PortState(proto string, port, fam int) string {
	if !u.active() {
		return ""
	}
	switch fam {
	case Fam4:
		return portState(u.rules4, proto, port)
	case Fam6:
		return portState(u.rules6, proto, port)
	}
	if portState(u.rules4, proto, port) == model.FwOpen || portState(u.rules6, proto, port) == model.FwOpen {
		return model.FwOpen
	}
	return model.FwFiltered
}

func portState(rules []ufwRule, proto string, port int) string {
	for _, r := range rules {
		// Адрес назначения — один из адресов самого сервера, поэтому
		// правило с конкретным dst тоже открывает порт для интернета;
		// важен только источник.
		if !r.in || !anyAddr(r.src) {
			continue
		}
		if r.proto != "any" && r.proto != proto {
			continue
		}
		if !portIn(r.dport, port) {
			continue
		}
		switch r.action {
		case "allow", "limit":
			return model.FwOpen
		case "deny", "reject":
			return model.FwFiltered
		}
	}
	return model.FwFiltered
}

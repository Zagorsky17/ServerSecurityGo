package investigate

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"strings"
	"testing"
)

func TestExplainCatalogAndAliases(t *testing.T) {
	for _, key := range i18n.Keys() {
		if (strings.HasPrefix(key, "rule.") || strings.HasPrefix(key, "audit.")) && strings.HasSuffix(key, ".title") {
			id := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(key, "rule."), "audit."), ".title")
			f, e := Explain(id)
			if e != nil || f.ID != id || f.Title.In(i18n.EN) == "" || f.Why.In(i18n.EN) == "" || f.Legitimate.In(i18n.RU) == "" {
				t.Fatal(id, f, e)
			}
		}
	}
	for id := range explanationTitles {
		if _, e := Explain(id); e != nil {
			t.Fatal(id, e)
		}
	}
	f, e := Explain("web_spawns_shell")
	if e != nil || len(f.Attack) != 2 || f.Why.Key != "card.why.execution" {
		t.Fatal(f, e)
	}
	for _, id := range []string{"", "does_not_exist", "../../etc/passwd", "exe_memfd\x1b[2J"} {
		if _, e := Explain(id); e == nil {
			t.Fatal("accepted", id)
		}
	}
}

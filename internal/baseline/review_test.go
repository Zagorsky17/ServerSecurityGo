package baseline

import (
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestImportantChangesRequireCompleteSections(t *testing.T) {
	a := sample()
	for _, name := range []string{"ssh_keys", "suid", "capabilities", "audit"} {
		a.Sections[name] = model.BaselineSection{Scope: "test", Complete: true, Items: map[string]string{}}
	}
	b := clone(a)
	for _, name := range []string{"ports", "ssh_keys", "suid", "capabilities", "audit"} {
		b.Sections[name].Items["new"] = "value"
	}
	d := Diff(a, b)
	if d.Incomplete || len(d.Changes) != 5 {
		t.Fatal(d)
	}
	for i, c := range d.Changes {
		if c.ReviewFirst != (i < 4) || c.After != "value" {
			t.Fatal("important sections not prioritized or data changed", c)
		}
	}
	section := b.Sections["ssh_keys"]
	section.Complete = false
	b.Sections["ssh_keys"] = section
	d = Diff(a, b)
	if !d.Incomplete || len(d.Changes) != 4 {
		t.Fatal("incomplete data manufactured SSH changes")
	}
	for _, c := range d.Changes {
		if c.Section == "ssh_keys" {
			t.Fatal(c)
		}
	}
}

package fsinspect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestPackageOwnedPrivilegeChangeKeepsWarningAndEvidence(t *testing.T) {
	for _, initial := range []os.FileMode{0755, os.ModeSetuid | 0755} {
		t.Run(initial.String(), func(t *testing.T) {
			o, write := fixture(t)
			write("usr/bin/example", "fixture")
			p := filepath.Join(o.HostRoot, "usr/bin/example")
			if err := os.Chmod(p, initial); err != nil {
				t.Fatal(err)
			}
			base := New(o).RunOnce(context.Background())
			if base.Incomplete {
				t.Fatal(base.Warnings)
			}
			if err := os.Chmod(p, os.ModeSetuid|os.ModeSetgid|0755); err != nil {
				t.Fatal(err)
			}
			rep := New(o).RunOnce(context.Background())
			if len(rep.Files) != 1 || rep.Files[0].PackageOwned == nil || !*rep.Files[0].PackageOwned {
				t.Fatal("fixture not package owned")
			}
			for _, f := range rep.Findings {
				if f.ID != "fs_privilege_new" {
					continue
				}
				if f.Risk != model.RiskHigh || len(f.Evidence) != 3 || !strings.Contains(f.Evidence[2].In(i18n.EN), "sgid=true") {
					t.Fatal("privilege delta missing or warning downgraded", f)
				}
				before := f.Evidence[1].In(i18n.EN)
				if initial&os.ModeSetuid != 0 {
					if !strings.Contains(before, "sgid=false") {
						t.Fatal(before)
					}
				} else if !strings.Contains(before, "does not prove that the file itself was absent") {
					t.Fatal(before)
				}
				return
			}
			t.Fatal("package-owned change omitted")
		})
	}
}

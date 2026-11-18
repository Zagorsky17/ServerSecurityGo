package view

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func orphan(path, owner string) model.SystemFinding {
	return model.SystemFinding{Path: path, Risk: model.RiskMedium, Finding: model.Finding{ID: "fs_unowned", Evidence: i18n.Ls([]string{owner})}}
}

func TestSystemGroups(t *testing.T) {
	findings := []model.SystemFinding{
		orphan("/usr/local/include/node/a.h", "uid=1001 gid=1001"),
		orphan("/usr/local/include/node/b.h", "uid=1001 gid=1001"),
		orphan("/usr/local/lib/node_modules/a.js", "uid=1001 gid=1001"),
		orphan("/usr/local/include/node/c.h", "uid=501 gid=50"),
		orphan("/usr/local/include/node/d.h", "uid=1001 gid=1001"),
		orphan("/usr/local/include/node/e.h", "uid=1001 gid=1001"),
		orphan("/usr/local/include/node/f.h", "uid=1001 gid=1001"),
		orphan("/usr/local/include/node/../x.h", "uid=1001 gid=1001"),
		orphan("relative/file", "uid=1001 gid=1001"),
		orphan("/usr/local/include/node/g.h", "uid=1001 gid=1001 extra"),
	}
	findings[4].Risk = model.RiskHigh
	findings[5].Suppressed = true
	findings[6].ID = "fs_world_writable_system"
	before := fmt.Sprint(findings)
	groups := GroupSystem(findings)
	if len(groups) != 1 || groups[0].Directory != "/usr/local/include" || groups[0].Owner != "uid=1001 gid=1001" || !reflect.DeepEqual(groups[0].Indices, []int{0, 1}) {
		t.Fatalf("unexpected grouping: %+v", groups)
	}
	if fmt.Sprint(findings) != before {
		t.Fatal("source findings changed")
	}
	findings = append(findings, orphan("/usr/local/include/new.h", "uid=1001 gid=1001"))
	if next := GroupSystem(findings); next[0].Key != groups[0].Key || len(next[0].Indices) != 3 {
		t.Fatal("group identity changed with membership")
	}
}

func TestSystemGroupsLargeAndUnknownEvidence(t *testing.T) {
	var findings []model.SystemFinding
	for i := 0; i < 7229; i++ {
		findings = append(findings, orphan(fmt.Sprintf("/opt/loki/build-home/tree/file%d", i), "uid=501 gid=50"))
	}
	groups := GroupSystem(findings)
	if len(groups) != 1 || len(groups[0].Indices) != len(findings) {
		t.Fatal("large group lost members")
	}
	for i, n := range groups[0].Indices {
		if n != i {
			t.Fatal("member order changed")
		}
	}
	findings[0].Evidence = nil
	findings[1].Evidence = []i18n.Msg{i18n.T("unrecognized")}
	if got := GroupSystem(findings); len(got[0].Indices) != len(findings)-2 {
		t.Fatal("unknown evidence grouped")
	}
}

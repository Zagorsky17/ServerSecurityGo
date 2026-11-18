package web

import (
	"encoding/json"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func TestSystemGroupsPreserveRawAPI(t *testing.T) {
	s := newTestServer(t, "")
	// В этом тесте фоновый сканер не запущен; задаём опубликованный снимок до запросов.
	snap := s.opt.Scanner.Snapshot()
	snap.System = nil
	for _, p := range []string{"/opt/app/tree/b", "/opt/app/tree/a"} {
		snap.System = append(snap.System, model.SystemFinding{Path: p, Risk: model.RiskMedium, Finding: model.Finding{ID: "fs_unowned", Evidence: i18n.Ls([]string{"uid=501 gid=50"})}})
	}
	snap.System = append(snap.System, model.SystemFinding{Path: "/etc/high", Risk: model.RiskHigh, Finding: model.Finding{ID: "fs_world_writable_system"}})
	w := do(s, "GET", "/api/system", "localhost:8090", "", nil)
	var result struct {
		Findings []model.SystemFinding `json:"findings"`
		Groups   []view.SystemGroup    `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 {
		t.Fatal(w.Code, err)
	}
	if len(result.Findings) != 3 || len(result.Groups) != 1 || len(result.Groups[0].Indices) != 2 {
		t.Fatal("grouping removed raw findings or omitted members")
	}
	if result.Findings[0].Risk != model.RiskHigh || result.Findings[0].Path != "/etc/high" {
		t.Fatal("risk ordering changed")
	}
	for _, i := range result.Groups[0].Indices {
		if result.Findings[i].ID != "fs_unowned" || result.Findings[i].Risk != model.RiskMedium {
			t.Fatal("group index does not refer to original finding")
		}
	}
	if len(snap.System) != 3 || snap.System[0].Path != "/opt/app/tree/b" {
		t.Fatal("snapshot changed")
	}
}

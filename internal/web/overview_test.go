package web

import (
	"encoding/json"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func TestSystemOverviewPreservesRawFindings(t *testing.T) {
	s := newTestServer(t, "")
	w := do(s, "GET", "/api/system", "127.0.0.1", "", nil)
	var r struct {
		Findings []model.SystemFinding `json:"findings"`
		Overview view.SystemOverview   `json:"overview"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &r) != nil {
		t.Fatal(w.Code, w.Body)
	}
	if len(r.Findings) != len(s.opt.Scanner.Snapshot().System) || r.Overview.Attention+len(r.Overview.Details) != len(r.Findings) {
		t.Fatal("raw findings lost", r.Overview)
	}
	for _, i := range r.Overview.Details {
		if i < 0 || i >= len(r.Findings) || !view.SystemDetailOnly(r.Findings[i]) {
			t.Fatal("hidden actionable finding", i)
		}
	}
}

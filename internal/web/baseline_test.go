package web

import (
	"context"
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/baseline"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"strings"
	"testing"
	"time"
)

func TestChangesAPIReadOnlyAndProtected(t *testing.T) {
	s := newTestServer(t, "")
	b := &model.BaselineSnapshot{Version: 1, Host: "fixture", Time: time.Now(), Sections: map[string]model.BaselineSection{"users": {Scope: "local", Complete: true, Items: map[string]string{"root": "0"}}}}
	m := baseline.NewMonitor(baseline.New(t.TempDir()), func(context.Context) *model.BaselineSnapshot { return b })
	m.Refresh(context.Background())
	s.opt.Scanner.SetBaselines(m)
	w := do(s, "GET", "/api/changes", "127.0.0.1", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var r model.ChangesReport
	if e := json.Unmarshal(w.Body.Bytes(), &r); e != nil || r.Installation == nil || r.Installation.Incomplete {
		t.Fatal(r, e)
	}
	if w = do(s, "POST", "/api/changes", "127.0.0.1", "", nil); w.Code == 200 {
		t.Fatal("mutation exposed")
	}
	if w = do(s, "GET", "/api/changes", "evil.example", "", nil); w.Code == 200 {
		t.Fatal("Host bypass")
	}
	protected := newTestServer(t, "configured")
	if w = do(protected, "GET", "/api/changes", "127.0.0.1", "", nil); w.Code == 200 {
		t.Fatal("authentication bypass")
	}
	w = do(s, "GET", "/api/system", "127.0.0.1", "", nil)
	if !strings.Contains(w.Body.String(), `"why"`) || !strings.Contains(w.Body.String(), `"legitimate"`) {
		t.Fatal("finding context missing", w.Body)
	}
}

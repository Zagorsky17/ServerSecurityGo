package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func TestSecurityProcessAPI(t *testing.T) {
	tree := fakeproc.Demo(time.Now())
	p := tree.Procs[0]
	p.StatusExtra = "CapEff:\t0000000000200000\nCapPrm:\t0000000000200000\nCapBnd:\t0000000000200000\nCapAmb:\t0000000000000000\nSeccomp:\t2\nNoNewPrivs:\t1\n"
	p.Env = []string{"PROMPT_COMMAND=curl SECRET_API_SENTINEL"}
	s := newTreeServer(t, tree, "")
	w := do(s, "GET", fmt.Sprintf("/api/process/%d-%d", p.PID, p.StartTicks), "127.0.0.1", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var d view.Detail
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Process.Security == nil || len(d.Process.Security.CapEff) != 1 || d.Process.Security.CapEff[0] != "CAP_SYS_ADMIN" {
		t.Fatalf("%+v", d.Process)
	}
	if strings.Contains(w.Body.String(), "SECRET_API_SENTINEL") {
		t.Fatal("secret in detail API")
	}
}

func TestQuotedSecretsInAPIHistoryAndReport(t *testing.T) {
	for _, command := range []string{`DB_PASSWORD='AUDIT_SECRET value' sleep 60`, `DB_PASSWORD="AUDIT_SECRET value" sleep 60`, `DB_PASSWORD="AUDIT_SECRET\" tail" sleep 60`, `DB_PASSWORD='AUDIT_'"SECRET" sleep 60`} {
		tree := fakeproc.Demo(time.Now())
		p := tree.Procs[0]
		p.Args = []string{"sh", "-c", command}
		s := newTreeServer(t, tree, "")
		w := do(s, "GET", fmt.Sprintf("/api/process/%d-%d", p.PID, p.StartTicks), "127.0.0.1", "", nil)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		snap := s.opt.Scanner.Snapshot()
		track, ok := s.opt.Scanner.History().Track(fmt.Sprintf("%d-%d", p.PID, p.StartTicks))
		if !ok {
			t.Fatal("missing track")
		}
		historyJSON, err := json.Marshal(track)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := report.NewScan(snap, model.RiskInfo, "test").Render(&out, report.JSON, i18n.EN); err != nil {
			t.Fatal(err)
		}
		for _, data := range []string{w.Body.String(), string(historyJSON), out.String()} {
			if strings.Contains(data, "AUDIT_") {
				t.Fatalf("secret leaked for %q", command)
			}
		}
	}
}

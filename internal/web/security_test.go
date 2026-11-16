package web

import (
	"encoding/json"
	"fmt"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
	"strings"
	"testing"
	"time"
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

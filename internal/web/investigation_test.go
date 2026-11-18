package web

import (
	"context"
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/authlog"
	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInvestigationEndpoints(t *testing.T) {
	s := newTestServer(t, "")
	for _, path := range []string{"/api/logins", "/api/timeline?since=48h"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "127.0.0.1"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var v map[string]any
		if json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatal(w.Body.String())
		}
	}
}
func TestInvestigationAccessAndWindow(t *testing.T) {
	hash, e := HashPassword("test-password")
	if e != nil {
		t.Fatal(e)
	}
	locked := newTestServer(t, hash)
	for _, p := range []string{"/api/logins", "/api/timeline"} {
		if w := do(locked, "GET", p, "127.0.0.1", "", nil); w.Code != 401 {
			t.Fatalf("%s unprotected: %d", p, w.Code)
		}
	}
	s := newTestServer(t, "")
	for _, p := range []string{"/api/timeline?since=-1h", "/api/timeline?since=20000h", "/api/timeline?since=invalid"} {
		if w := do(s, "GET", p, "127.0.0.1", "", nil); w.Code != 400 {
			t.Fatal(p, w.Code)
		}
	}
}

func TestAuthenticationPipelineToAPI(t *testing.T) {
	now := time.Now()
	tree := fakeproc.Demo(now)
	for i := 1; i <= 2; i++ {
		at := now.UTC().Truncate(15 * time.Minute).Add(-15*time.Minute + time.Duration(i)*time.Minute)
		tree.HostFiles["var/log/auth.log"] += at.Format(time.RFC3339) + " host sshd[42]: Failed password for test-user from 192.0.2.177 port 12345 ssh2\n"
	}
	tree.HostFiles["var/log/auth.log"] += now.Add(-time.Minute).UTC().Format(time.RFC3339) + " host sudo: deploy : TTY=pts/0 ; COMMAND=/bin/app --password pipeline-canary\n"
	proc, host, e := tree.Write(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	hist, _ := history.Open(history.Options{})
	sc := scanner.New(scanner.Options{FS: fakeproc.NewFS(proc, host), Detect: detect.DefaultConfig(), History: hist, Auth: authlog.New(authlog.Options{Root: host, ReadOnly: true}), Recent: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); sc.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		snap := sc.Snapshot()
		if snap != nil && snap.Recent != nil && len(snap.Recent.Files) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background metadata not published")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s := New(Options{Scanner: sc, ListenAddr: "127.0.0.1:8090"})
	w := do(s, "GET", "/api/logins", "127.0.0.1", "", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "pipeline-canary") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var r struct {
		Enabled bool              `json:"enabled"`
		Groups  []view.LoginGroup `json:"groups"`
		Report  *model.AuthReport `json:"report"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &r); e != nil || !r.Enabled || r.Report == nil || len(r.Report.Events) < 2 {
		t.Fatalf("%+v %v", r, e)
	}

	grouped := false
	seen := make([]int, len(r.Report.Events))
	for _, g := range r.Groups {
		for _, i := range g.Indices {
			if i < 0 || i >= len(seen) {
				t.Fatal("invalid group index", i)
			}
			seen[i]++
		}
		if len(g.Indices) == 2 && r.Report.Events[g.Indices[0]].IP == "192.0.2.177" {
			grouped = true
		}
	}
	for _, n := range seen {
		if n != 1 {
			t.Fatal("API group lost or duplicated raw record")
		}
	}
	if !grouped {
		t.Fatal("repeated failures not grouped", r.Groups)
	}
	found := false
	for _, f := range r.Report.Findings {
		if f.ID == "login_password_root" {
			found = true
			if len(f.VerifyCommands) == 0 {
				t.Fatal("missing manual verification")
			}
		}
	}
	if !found {
		t.Fatal("login finding not exposed")
	}
	w = do(s, "GET", "/api/timeline?since=48h", "127.0.0.1", "", nil)
	var timeline struct {
		Events []model.TimelineEvent `json:"events"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &timeline); e != nil {
		t.Fatal(e)
	}
	login, file := false, false
	for _, e := range timeline.Events {
		login = login || e.Kind == "login"
		file = file || e.Kind == "file"
	}
	if !login || !file {
		t.Fatal("timeline sources missing", login, file)
	}
}

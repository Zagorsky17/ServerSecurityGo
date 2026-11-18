package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
)

func BenchmarkReportRefresh(b *testing.B) {
	tree := fakeproc.Demo(time.Now())
	proc, root, err := tree.Write(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	hist, _ := history.Open(history.Options{})
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	sc := scanner.New(scanner.Options{FS: fakeproc.NewFS(proc, root), Detect: detect.DefaultConfig(), History: hist, Logger: quiet})
	snap, err := sc.ScanOnce()
	if err != nil {
		b.Fatal(err)
	}
	snap.System = nil
	for i := 0; i < 7229; i++ {
		snap.System = append(snap.System, model.SystemFinding{Path: fmt.Sprintf("/opt/fixture/worktree/%05d/file", i), Risk: model.RiskLow, Finding: model.Finding{ID: "fs_unowned", Title: i18n.L("Unknown local owner"), Evidence: []i18n.Msg{i18n.L("uid=1001 gid=1001"), i18n.L(strings.Repeat("fixture evidence ", 14))}, Recommendation: i18n.L("Verify local account ownership and the file's origin."), FindingContext: model.FindingContext{Why: i18n.L(strings.Repeat("Review ownership. ", 8)), Legitimate: i18n.L("Files copied from another host or a removed account."), RelatedEvents: []model.Event{}}, VerifyCommands: []string{"stat -- '/opt/fixture/file'"}}})
	}
	for _, scenario := range []struct {
		name, query string
		newSnapshot bool
	}{
		{"TUI", "", false}, {"Web", "?summary=1", false},
		{"TUI_NewSnapshot", "", true}, {"Web_NewSnapshot", "?summary=1", true},
	} {
		name, q := scenario.name, scenario.query
		b.Run(name, func(b *testing.B) {
			s := New(Options{Scanner: sc, Logger: quiet, ListenAddr: "127.0.0.1:8090"})
			handler := s.LocalHandler()
			fetch := func(tag string) *httptest.ResponseRecorder {
				if scenario.newSnapshot {
					snap.System = append([]model.SystemFinding(nil), snap.System...)
				}
				r := httptest.NewRequest("GET", "http://127.0.0.1:8090/api/system"+q, nil)
				if tag != "" {
					r.Header.Set("If-None-Match", tag)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			first := fetch("")
			tag := first.Header().Get("ETag")
			initial := first.Body.Len()
			b.ReportAllocs()
			b.ResetTimer()
			bytes := 0
			for i := 0; i < b.N; i++ {
				w := fetch(tag)
				bytes += w.Body.Len()
				if w.Code == 200 {
					var out struct {
						Findings []model.SystemFinding `json:"findings"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
						b.Fatal(err)
					}
				} else if w.Code != 304 {
					b.Fatal(w.Code)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(bytes)/float64(b.N), "body-B/op")
			b.ReportMetric(float64(initial), "initial-B")
		})
	}
}

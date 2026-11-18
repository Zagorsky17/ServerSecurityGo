package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func TestSystemConditionalSummaryAndDetail(t *testing.T) {
	s := newTestServer(t, "")
	snap := s.opt.Scanner.Snapshot()
	snap.System = []model.SystemFinding{{Path: "/tmp/<img>'", Risk: model.RiskHigh, Finding: model.Finding{ID: "fixture", Title: i18n.L("fixture"), Evidence: []i18n.Msg{i18n.L("original facts")}}}}
	snap.Warnings = []i18n.Msg{i18n.L("incomplete fixture")}
	get := func(path, tag string) *httptest.ResponseRecorder {
		return do(s, "GET", path, "127.0.0.1:8090", "", map[string]string{"If-None-Match": tag})
	}
	first := get("/api/system?summary=1", "")
	var summary struct {
		Revision string
		Summary  bool
		Findings []systemItem
		Warnings []i18n.Msg
	}
	if err := json.Unmarshal(first.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if !summary.Summary || len(summary.Findings) != 1 || len(summary.Warnings) != 1 || strings.Contains(first.Body.String(), "original facts") {
		t.Fatal(first.Body.String())
	}
	tag := first.Header().Get("ETag")
	for _, match := range []string{tag, "W/" + tag, `"other", ` + tag, "*"} {
		response := get("/api/system?summary=1", match)
		if response.Code != 304 || response.Body.Len() != 0 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(response)
		}
	}
	detail := "/api/system/detail?index=0&revision=" + url.QueryEscape(summary.Revision)
	if response := get(detail, ""); response.Code != 200 || !strings.Contains(response.Body.String(), "original facts") {
		t.Fatal(response.Body.String())
	}
	full := get("/api/system", "")
	if !strings.Contains(full.Body.String(), "original facts") || full.Header().Get("ETag") == tag {
		t.Fatal("legacy API or representation tag broken")
	}
	// Новый снимок с теми же данными тоже допускает 304.
	snap.System = append([]model.SystemFinding(nil), snap.System...)
	if response := get("/api/system?summary=1", tag); response.Code != 304 {
		t.Fatal("identical new slice was transferred")
	}
	// Меняются только факты: прежняя строка списка больше не даёт старые подробности.
	snap.System = append([]model.SystemFinding(nil), snap.System...)
	snap.System[0].Evidence = []i18n.Msg{i18n.L("updated facts")}
	next := get("/api/system?summary=1", tag)
	if next.Code != 200 || next.Header().Get("ETag") == tag {
		t.Fatal("evidence change was hidden")
	}
	if response := get(detail, ""); response.Code != 409 {
		t.Fatal("stale detail index accepted", response.Code)
	}
	json.Unmarshal(next.Body.Bytes(), &summary)
	for _, index := range []string{"-1", "1", "bad"} {
		if response := get("/api/system/detail?index="+index+"&revision="+url.QueryEscape(summary.Revision), ""); response.Code != 400 {
			t.Fatal(index, response.Code)
		}
	}
	snap.Warnings = []i18n.Msg{i18n.L("new incomplete source")}
	if response := get("/api/system?summary=1", next.Header().Get("ETag")); response.Code != 200 {
		t.Fatal("coverage warning hidden")
	}
	if response := do(s, "GET", "/api/system?summary=1", "evil.example", "", map[string]string{"If-None-Match": tag}); response.Code != http.StatusMisdirectedRequest {
		t.Fatal("host protection bypassed")
	}
	// Авторизация проверяется раньше условного ответа, даже при совпадении тега.
	hash, err := HashPassword("fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	secured := newTestServer(t, hash)
	if response := do(secured, "GET", "/api/system", "127.0.0.1:8090", "", map[string]string{"If-None-Match": "*"}); response.Code != 401 {
		t.Fatal("conditional auth bypass", response.Code)
	}
}

func TestReportCacheBoundAndConcurrentReuse(t *testing.T) {
	var cache reportCache
	builds := 0
	build := func() any { builds++; return map[string]string{"value": "fixture"} }
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.get("same", build); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if builds != 1 {
		t.Fatal("duplicate encoding", builds)
	}
	if _, err := cache.get("large", func() any { return strings.Repeat("x", maxReportCacheBytes+1) }); err != nil {
		t.Fatal(err)
	}
	if cache.source != nil || cache.reply.body != nil {
		t.Fatal("oversized report retained")
	}
	if _, err := cache.get("broken", func() any { return make(chan int) }); err == nil {
		t.Fatal("encoding error ignored")
	}
}

func TestAuditConditionalRefreshWithUnchangedTime(t *testing.T) {
	s := newTestServer(t, "")
	a := &fakeAudit{rep: &model.AuditReport{Checks: []model.AuditCheck{{ID: "fixture", Status: model.AuditUnknown}}}}
	s.opt.Audit = a
	response := do(s, "GET", "/api/audit", "127.0.0.1:8090", "", nil)
	tag := response.Header().Get("ETag")
	a.rep = &model.AuditReport{Checks: []model.AuditCheck{{ID: "fixture", Status: model.AuditFail}}}
	response = do(s, "GET", "/api/audit", "127.0.0.1:8090", "", map[string]string{"If-None-Match": tag})
	if response.Code != 200 || response.Header().Get("ETag") == tag || !strings.Contains(response.Body.String(), `"status":"fail"`) {
		t.Fatal("partial update hidden")
	}
	tag = response.Header().Get("ETag")
	a.running = true
	if response = do(s, "GET", "/api/audit", "127.0.0.1:8090", "", map[string]string{"If-None-Match": tag}); response.Code != 200 {
		t.Fatal("running status hidden")
	}
}

func TestSummaryRetainsGroupsOverviewAndPriorities(t *testing.T) {
	s := newTestServer(t, "")
	snap := s.opt.Scanner.Snapshot()
	snap.System = []model.SystemFinding{
		{Path: "/opt/app/tree/a", Risk: model.RiskMedium, Finding: model.Finding{ID: "fs_unowned", Evidence: i18n.Ls([]string{"uid=501 gid=50"})}},
		{Path: "/opt/app/tree/b", Risk: model.RiskMedium, Finding: model.Finding{ID: "fs_unowned", Evidence: i18n.Ls([]string{"uid=501 gid=50"})}},
		{Risk: model.RiskInfo, Finding: model.Finding{ID: "routine"}},
		{Risk: model.RiskHigh, Finding: model.Finding{ID: "changed", ReviewFirst: true, Evidence: i18n.Ls([]string{"changed facts"})}},
	}
	response := do(s, "GET", "/api/system?summary=1", "127.0.0.1", "", nil)
	var summary struct {
		Findings []systemItem
		Groups   []view.SystemGroup
		Overview view.SystemOverview
		Revision string
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &summary) != nil {
		t.Fatal(response.Code, response.Body)
	}
	if len(summary.Findings) != 4 || len(summary.Groups) != 1 || summary.Overview.Attention != 3 || len(summary.Overview.Details) != 1 {
		t.Fatalf("combined summary lost metadata: %+v", summary)
	}
	if summary.Findings[0].ID != "changed" || !summary.Findings[0].ReviewFirst {
		t.Fatal("priority lost")
	}
	for _, i := range summary.Groups[0].Indices {
		if summary.Findings[i].ID != "fs_unowned" || summary.Findings[i].Index != i {
			t.Fatal("group index changed")
		}
	}
	if summary.Findings[summary.Overview.Details[0]].ID != "routine" {
		t.Fatal("attention hidden")
	}
	full := do(s, "GET", "/api/system", "127.0.0.1", "", nil)
	var report systemReport
	if json.Unmarshal(full.Body.Bytes(), &report) != nil || len(report.Groups) != 1 || len(report.Overview.Details) != 1 {
		t.Fatal(full.Body)
	}
	for _, item := range summary.Findings {
		detail := do(s, "GET", "/api/system/detail?index="+strconv.Itoa(item.Index)+"&revision="+url.QueryEscape(summary.Revision), "127.0.0.1", "", nil)
		var finding model.SystemFinding
		if detail.Code != 200 || json.Unmarshal(detail.Body.Bytes(), &finding) != nil || finding.ID != item.ID || finding.Path != item.Path {
			t.Fatal("detail index changed", detail.Body)
		}
	}
	tag := response.Header().Get("ETag")
	if r := do(s, "GET", "/api/system?summary=1", "127.0.0.1", "", map[string]string{"If-None-Match": tag}); r.Code != 304 {
		t.Fatal("unchanged report retransmitted")
	}
	snap.System = append([]model.SystemFinding(nil), snap.System...)
	snap.System[2].Risk = model.RiskHigh
	r := do(s, "GET", "/api/system?summary=1", "127.0.0.1", "", map[string]string{"If-None-Match": tag})
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &summary) != nil || len(summary.Overview.Details) != 0 {
		t.Fatal("changed overview stayed cached")
	}
}

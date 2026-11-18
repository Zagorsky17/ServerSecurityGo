package tui

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type reportTransport func(*http.Request) (*http.Response, error)

func (f reportTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCachedReportReuseErrorsAndLegacy(t *testing.T) {
	calls := 0
	r := &RemoteSource{client: &http.Client{Transport: reportTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		status, tag, body := 200, `"fixture"`, `{"findings":[{"id":"fixture","path":"/tmp/file"}]}`
		switch calls {
		case 2:
			if req.Header.Get("If-None-Match") != tag {
				t.Error("missing conditional header")
			}
			status, body = 304, "must not decode this"
		case 3:
			status, body = 503, `{"error":"unavailable"}`
		case 4:
			if req.Header.Get("If-None-Match") != "" {
				t.Error("failed cache reused")
			}
			tag = ""
		case 5:
			if req.Header.Get("If-None-Match") != "" {
				t.Error("legacy response kept old ETag")
			}
			body = "broken"
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Etag": []string{tag}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	var cache cachedReport[systemReport]
	first, err := fetchReport(r, "/api/system", &cache)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fetchReport(r, "/api/system", &cache)
	if err != nil || &second.Findings[0] != &first.Findings[0] {
		t.Fatal("304 decoded or copied cached findings", err)
	}
	if _, err = fetchReport(r, "/api/system", &cache); err == nil || cache.ready {
		t.Fatal("error treated as a fresh report")
	}
	if _, err = fetchReport(r, "/api/system", &cache); err != nil {
		t.Fatal(err)
	}
	if _, err = fetchReport(r, "/api/system", &cache); err == nil || cache.ready {
		t.Fatal("malformed response retained")
	}
}

func TestCachedDataStillShowsStaleStatus(t *testing.T) {
	a, _ := newTestApp(t, 160, 40)
	a.data.Status.Stale = true
	if !strings.Contains(screen(a), "Данные устарели") {
		t.Fatal("stale status hidden by cached data")
	}
}

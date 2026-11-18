package web

import (
	"strings"
	"testing"
)

func TestLearningAPIProtectedAndReadOnly(t *testing.T) {
	s := newTestServer(t, "")
	w := do(s, "GET", "/api/learning", "127.0.0.1", "", nil)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "null" {
		t.Fatal(w.Code, w.Body)
	}
	for _, tc := range []struct{ method, host string }{{"POST", "127.0.0.1"}, {"GET", "evil.example"}} {
		if w = do(s, tc.method, "/api/learning", tc.host, "", nil); w.Code == 200 {
			t.Fatal("mutation/host bypass")
		}
	}
	protected := newTestServer(t, "configured")
	if w = do(protected, "GET", "/api/learning", "127.0.0.1", "", nil); w.Code == 200 {
		t.Fatal("auth bypass")
	}
}

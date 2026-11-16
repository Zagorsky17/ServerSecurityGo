package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

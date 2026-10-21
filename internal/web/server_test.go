package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func newTestServer(t *testing.T, passwordHash string) *Server {
	t.Helper()
	tree := fakeproc.Demo(time.Now())
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hist, _ := history.Open(history.Options{})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sc := scanner.New(scanner.Options{FS: fakeproc.NewFS(procRoot, hostRoot), Detect: detect.DefaultConfig(), History: hist, Logger: log})
	if _, err := sc.ScanOnce(); err != nil {
		t.Fatal(err)
	}
	return New(Options{Scanner: sc, Logger: log, Version: "test", ListenAddr: "127.0.0.1:8090", PasswordHash: passwordHash})
}

func do(s *Server, method, path, host string, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	r.RemoteAddr = "127.0.0.1:50000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestNoAuthAPI(t *testing.T) {
	s := newTestServer(t, "")
	w := do(s, "GET", "/api/processes", "127.0.0.1:8090", "", nil)
	if w.Code != 200 {
		t.Fatalf("код %d: %s", w.Code, w.Body)
	}
	var resp struct {
		Processes []view.Summary `json:"processes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Processes) == 0 {
		t.Fatalf("ответ: %v", err)
	}
	if strings.Contains(w.Body.String(), "hunter2") {
		t.Error("секрет в ответе API")
	}
	// Заголовки безопасности.
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP: %q", csp)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("нет X-Frame-Options")
	}
	for _, path := range []string{"/", "/api/status", "/api/tree", "/api/connections", "/api/events", "/api/system", "/static/app.js", "/healthz"} {
		if w := do(s, "GET", path, "localhost:8090", "", nil); w.Code != 200 {
			t.Errorf("%s: код %d", path, w.Code)
		}
	}
	// Карточка процесса.
	key := resp.Processes[0].Key
	if w := do(s, "GET", "/api/process/"+key, "127.0.0.1", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"ancestors"`) {
		t.Errorf("карточка: %d", w.Code)
	}
	if w := do(s, "GET", "/api/process/nope", "127.0.0.1", "", nil); w.Code != 404 {
		t.Errorf("несуществующая карточка: %d", w.Code)
	}
}

func TestHostCheck(t *testing.T) {
	s := newTestServer(t, "")
	// DNS rebinding: чужое имя хоста, указывающее на 127.0.0.1.
	if w := do(s, "GET", "/api/processes", "evil.example:8090", "", nil); w.Code != http.StatusMisdirectedRequest {
		t.Errorf("чужой Host принят: %d", w.Code)
	}
}

func TestCSRF(t *testing.T) {
	s := newTestServer(t, "")
	if w := do(s, "POST", "/api/rescan", "127.0.0.1", "", nil); w.Code != 403 {
		t.Errorf("POST без CSRF: %d", w.Code)
	}
	if w := do(s, "POST", "/api/rescan", "127.0.0.1", "", map[string]string{"X-CSRF-Token": s.noAuthCSRF}); w.Code != 202 {
		t.Errorf("POST с CSRF: %d", w.Code)
	}
}

func TestAuthFlow(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, hash)
	if w := do(s, "GET", "/api/processes", "127.0.0.1", "", nil); w.Code != 401 {
		t.Errorf("без входа: %d", w.Code)
	}
	if w := do(s, "GET", "/", "127.0.0.1", "", nil); w.Code != http.StatusSeeOther {
		t.Errorf("страница без входа: %d", w.Code)
	}
	if w := do(s, "GET", "/healthz", "127.0.0.1", "", nil); w.Code != 200 {
		t.Errorf("healthz должен работать без входа: %d", w.Code)
	}
	if w := do(s, "POST", "/api/login", "127.0.0.1", `{"password":"wrong password"}`, nil); w.Code != 401 {
		t.Errorf("неверный пароль: %d", w.Code)
	}
	w := do(s, "POST", "/api/login", "127.0.0.1", `{"password":"correct horse battery"}`, nil)
	if w.Code != 200 {
		t.Fatalf("вход: %d %s", w.Code, w.Body)
	}
	var sess *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			sess = c
		}
	}
	if sess == nil || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", sess)
	}
	w = do(s, "GET", "/api/status", "127.0.0.1", "", nil, sess)
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	var st struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.CSRF == "" || st.CSRF == s.noAuthCSRF {
		t.Errorf("CSRF сессии: %q", st.CSRF)
	}
	if w := do(s, "POST", "/api/rescan", "127.0.0.1", "", map[string]string{"X-CSRF-Token": "bad"}, sess); w.Code != 403 {
		t.Errorf("неверный CSRF: %d", w.Code)
	}
	if w := do(s, "POST", "/api/rescan", "127.0.0.1", "", map[string]string{"X-CSRF-Token": st.CSRF}, sess); w.Code != 202 {
		t.Errorf("rescan: %d", w.Code)
	}
	do(s, "POST", "/api/logout", "127.0.0.1", "", map[string]string{"X-CSRF-Token": st.CSRF}, sess)
	if w := do(s, "GET", "/api/status", "127.0.0.1", "", nil, sess); w.Code != 401 {
		t.Errorf("после выхода: %d", w.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	hash, _ := HashPassword("correct horse battery")
	s := newTestServer(t, hash)
	s.limiter.maxFails = 3
	for range 3 {
		do(s, "POST", "/api/login", "127.0.0.1", `{"password":"nope nope nope"}`, nil)
	}
	if w := do(s, "POST", "/api/login", "127.0.0.1", `{"password":"correct horse battery"}`, nil); w.Code != http.StatusTooManyRequests {
		t.Errorf("ограничение попыток: %d", w.Code)
	}
}

func TestPasswordHash(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("короткий пароль принят")
	}
	h, err := HashPassword("long enough password")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(h, "$=") {
		t.Errorf("хеш содержит символы, опасные для .env: %s", h)
	}
	if !ValidHash(h) || !VerifyPassword(h, "long enough password") || VerifyPassword(h, "long enough passwore") {
		t.Error("проверка пароля")
	}
	for _, bad := range []string{"", "plain", "pbkdf2-sha256:1:aa:bb", "md5:1:2:3"} {
		if VerifyPassword(bad, "x") {
			t.Errorf("принят неверный хеш %q", bad)
		}
	}
}

// TestPeerCheck: без пароля панель доступна только пользователям из
// LocalUIDs (по умолчанию root), /healthz и локальный сокет — всем.
func TestPeerCheck(t *testing.T) {
	s := newTestServer(t, "")
	s.opt.CheckPeer, s.opt.LocalUIDs = true, []int{0}
	req := func(path string, info *peerInfo) int {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "127.0.0.1:8090"
		if info != nil {
			r = r.WithContext(context.WithValue(r.Context(), peerKey{}, *info))
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	for _, c := range []struct {
		path string
		info *peerInfo
		want int
	}{
		{"/api/processes", &peerInfo{uid: 0, ok: true}, 200},
		{"/api/processes", &peerInfo{uid: 33, ok: true}, 403}, // www-data
		{"/api/status", &peerInfo{uid: 1000, ok: true}, 403},
		{"/", &peerInfo{uid: 1000, ok: true}, 403},
		{"/api/processes", &peerInfo{}, 403}, // владелец не определён
		{"/api/processes", nil, 403},
		{"/healthz", &peerInfo{uid: 33, ok: true}, 200},
	} {
		if got := req(c.path, c.info); got != c.want {
			t.Errorf("%s %+v: код %d, ожидался %d", c.path, c.info, got, c.want)
		}
	}
	// Через Unix-сокет службы (терминальный интерфейс) проверка не нужна.
	r := httptest.NewRequest("GET", "/api/processes", nil)
	w := httptest.NewRecorder()
	s.LocalHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("локальный сокет: %d", w.Code)
	}
	// С паролем решает вход, а не UID.
	sp := newTestServer(t, "x")
	sp.opt.CheckPeer, sp.opt.LocalUIDs = true, []int{0}
	if code := do(sp, "GET", "/api/processes", "127.0.0.1:8090", "", nil).Code; code != 401 {
		t.Errorf("с паролем: %d", code)
	}
}

// TestPeerContext: в owner передаются адрес клиента и адрес службы.
func TestPeerContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	var gotLocal, gotRemote netip.AddrPort
	ctx := PeerContext(func(local, remote netip.AddrPort) (int, bool) {
		gotLocal, gotRemote = local, remote
		return 1000, true
	})(context.Background(), sc)
	if gotLocal.String() != c.LocalAddr().String() || gotRemote.String() != ln.Addr().String() {
		t.Errorf("owner(%s, %s), ожидалось (%s, %s)", gotLocal, gotRemote, c.LocalAddr(), ln.Addr())
	}
	if uid, ok := peerUID(ctx); uid != 1000 || !ok {
		t.Errorf("peerUID = %d %v", uid, ok)
	}
}

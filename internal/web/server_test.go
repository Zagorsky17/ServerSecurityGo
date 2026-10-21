package web

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// fastHash — хеш с малым числом итераций, чтобы тесты входа шли быстро,
// но проверка пароля всё ещё занимала заметное время.
func fastHash(t *testing.T, password string, iter int) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return fmt.Sprintf("%s:%d:%s:%s", hashPrefix, iter, enc.EncodeToString(salt), enc.EncodeToString(key))
}

func login(s *Server, remote, xff, password string) int {
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"`+password+`"}`))
	r.Host = "127.0.0.1:8090"
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w.Code
}

// TestLoginParallel: параллельные запросы не обходят лимит попыток —
// неверных паролей проверяется не больше maxFails.
func TestLoginParallel(t *testing.T) {
	s := newTestServer(t, fastHash(t, "correct horse battery", 100_000))
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := login(s, "203.0.113.5:4000", "", "wrong password 123")
			mu.Lock()
			codes[c]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[401] > s.limiter.maxFails || codes[401]+codes[429] != 40 {
		t.Errorf("коды ответов: %v (неверных паролей проверено больше %d)", codes, s.limiter.maxFails)
	}
	if c := login(s, "203.0.113.5:4000", "", "correct horse battery"); c != 429 {
		t.Errorf("после исчерпания лимита верный пароль: %d", c)
	}
}

// TestLoginProxyIP: за прокси счётчики разные для разных клиентов, а
// без прокси X-Forwarded-For не помогает обойти лимит.
func TestLoginProxyIP(t *testing.T) {
	s := newTestServer(t, fastHash(t, "correct horse battery", 10_000))
	s.opt.TrustProxy = true
	for range 5 {
		login(s, "127.0.0.1:5000", "203.0.113.5", "wrong")
	}
	if c := login(s, "127.0.0.1:5000", "203.0.113.5", "correct horse battery"); c != 429 {
		t.Errorf("атакующий не заблокирован: %d", c)
	}
	if c := login(s, "127.0.0.1:5001", "10.0.0.1, 198.51.100.7", "correct horse battery"); c != 200 {
		t.Errorf("администратор заблокирован чужими попытками: %d", c)
	}
	// Подделка: заголовок от клиента не с loopback не учитывается.
	for i := range 5 {
		login(s, "192.0.2.9:6000", fmt.Sprintf("10.9.9.%d", i), "wrong")
	}
	if c := login(s, "192.0.2.9:6000", "10.9.9.200", "correct horse battery"); c != 429 {
		t.Errorf("X-Forwarded-For от не-прокси обходит лимит: %d", c)
	}
	// Без TrustProxy заголовок игнорируется даже с loopback.
	s2 := newTestServer(t, fastHash(t, "correct horse battery", 10_000))
	for i := range 5 {
		login(s2, "127.0.0.1:5000", fmt.Sprintf("10.8.8.%d", i), "wrong")
	}
	if c := login(s2, "127.0.0.1:5000", "10.8.8.100", "correct horse battery"); c != 429 {
		t.Errorf("X-Forwarded-For без прокси обходит лимит: %d", c)
	}
}

// TestLoginIPv6Prefix: смена адреса внутри /64 не сбрасывает лимит.
func TestLoginIPv6Prefix(t *testing.T) {
	s := newTestServer(t, fastHash(t, "correct horse battery", 10_000))
	for i := 1; i <= 5; i++ {
		login(s, fmt.Sprintf("[2001:db8:1:2::%x]:4000", i), "", "wrong")
	}
	if c := login(s, "[2001:db8:1:2::ffff]:4000", "", "correct horse battery"); c != 429 {
		t.Errorf("другой адрес той же /64: %d", c)
	}
	if c := login(s, "[2001:db8:1:3::1]:4000", "", "correct horse battery"); c != 200 {
		t.Errorf("соседняя /64: %d", c)
	}
}

// TestLimiterSweep: записи адресов, с которых больше не приходили,
// удаляются, а не копятся бесконечно.
func TestLimiterSweep(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Now()
	for i := range 1000 {
		l.begin(fmt.Sprintf("10.0.%d.%d", i/256, i%256), t0)
	}
	if len(l.fails) != 1000 {
		t.Fatalf("записей %d", len(l.fails))
	}
	l.begin("192.0.2.1", t0.Add(l.window+time.Minute))
	if len(l.fails) != 1 {
		t.Errorf("после окна осталось %d записей", len(l.fails))
	}
}

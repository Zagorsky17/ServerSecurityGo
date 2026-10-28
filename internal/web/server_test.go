package web

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/metrics"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/netload"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func newTestServer(t *testing.T, passwordHash string) *Server {
	t.Helper()
	return newTreeServer(t, fakeproc.Demo(time.Now()), passwordHash)
}

// newTreeServer — панель над заданным поддельным деревом.
func newTreeServer(t *testing.T, tree *fakeproc.Tree, passwordHash string) *Server {
	t.Helper()
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

// TestSessionIdle: сессия закрывается после простоя, даже если общий срок
// не истёк; запросы продлевают её.
func TestSessionIdle(t *testing.T) {
	st := newSessionStore(12 * time.Hour)
	t0 := time.Now()
	tok, _ := st.create(t0)
	if _, ok := st.get(tok, t0.Add(90*time.Minute)); !ok {
		t.Fatal("активная сессия закрыта")
	}
	if _, ok := st.get(tok, t0.Add(3*time.Hour)); !ok {
		t.Fatal("запрос через 90 минут не продлил сессию")
	}
	if _, ok := st.get(tok, t0.Add(3*time.Hour+sessionIdle+time.Second)); ok {
		t.Error("сессия пережила простой дольше sessionIdle")
	}
	// Абсолютный срок по-прежнему действует, даже при постоянной работе.
	tok2, _ := st.create(t0)
	for h := 1; h <= 12; h++ {
		st.get(tok2, t0.Add(time.Duration(h)*time.Hour))
	}
	if _, ok := st.get(tok2, t0.Add(12*time.Hour+time.Minute)); ok {
		t.Error("сессия пережила SSG_SESSION_TTL")
	}
	// Короткий TTL меньше простоя: простой не дольше TTL.
	if newSessionStore(30*time.Minute).idle != 30*time.Minute {
		t.Error("idle больше TTL")
	}
}

func TestTokenEqual(t *testing.T) {
	if !tokenEqual("abc", "abc") || tokenEqual("abd", "abc") || tokenEqual("", "") || tokenEqual("abc", "") {
		t.Error("tokenEqual")
	}
}

// TestHostCookie: при TLS cookie сессии с префиксом __Host- и вход работает.
func TestHostCookie(t *testing.T) {
	hash, _ := HashPassword("correct horse battery")
	s := newTestServer(t, hash)
	s.opt.SecureCookie = true
	w := do(s, "POST", "/api/login", "127.0.0.1", `{"password":"correct horse battery"}`, nil)
	var sess *http.Cookie
	for _, c := range w.Result().Cookies() {
		sess = c
	}
	if sess == nil || sess.Name != "__Host-ssg_session" || !sess.Secure || sess.Path != "/" || sess.Domain != "" {
		t.Fatalf("cookie: %+v", sess)
	}
	if w := do(s, "GET", "/api/status", "127.0.0.1", "", nil, sess); w.Code != 200 {
		t.Errorf("с __Host- cookie: %d", w.Code)
	}
	if w := do(s, "GET", "/api/status", "127.0.0.1", "", nil, &http.Cookie{Name: "ssg_session", Value: sess.Value}); w.Code != 401 {
		t.Errorf("cookie без префикса при TLS принята: %d", w.Code)
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

// TestCatalogEndpoint: каталог переводов доступен без входа (он нужен
// странице входа), отдаётся с ETag и только для известных языков.
func TestCatalogEndpoint(t *testing.T) {
	s := newTestServer(t, fastHash(t, "correct horse battery", 1000))
	w := do(s, "GET", "/i18n/en.json", "127.0.0.1:8090", "", nil)
	if w.Code != 200 {
		t.Fatalf("код %d", w.Code)
	}
	var cat map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &cat); err != nil || cat["web.login.submit"] != "Log in" {
		t.Fatalf("каталог: %v %q", err, cat["web.login.submit"])
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("нет ETag")
	}
	if w := do(s, "GET", "/i18n/en.json", "127.0.0.1:8090", "", map[string]string{"If-None-Match": etag}); w.Code != http.StatusNotModified {
		t.Errorf("повторный запрос с ETag: %d", w.Code)
	}
	if w := do(s, "GET", "/i18n/ru.json", "127.0.0.1:8090", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Войти") {
		t.Errorf("русский каталог: %d", w.Code)
	}
	for _, p := range []string{"/i18n/de.json", "/i18n/en", "/i18n/..%2fapp.js"} {
		if w := do(s, "GET", p, "127.0.0.1:8090", "", nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: код %d", p, w.Code)
		}
	}
}

// TestPageLang: язык страницы по умолчанию — SSG_LANG, иначе
// Accept-Language; ошибки API — на языке из X-SSG-Lang.
func TestPageLang(t *testing.T) {
	s := newTestServer(t, "")
	page := func(al string) string {
		w := do(s, "GET", "/", "127.0.0.1:8090", "", map[string]string{"Accept-Language": al})
		if w.Header().Get("Vary") != "Accept-Language" {
			t.Error("нет Vary: Accept-Language")
		}
		return w.Body.String()
	}
	if b := page("en-US,en;q=0.9"); !strings.Contains(b, `<html lang="en">`) {
		t.Errorf("английский браузер: %.80s", b)
	}
	if b := page("ru-RU"); !strings.Contains(b, `<html lang="ru">`) {
		t.Errorf("русский браузер: %.80s", b)
	}
	s.opt.Lang = i18n.EN
	if b := page("ru-RU"); !strings.Contains(b, `<html lang="en">`) {
		t.Errorf("SSG_LANG=en должен быть главнее браузера: %.80s", b)
	}
	w := do(s, "GET", "/api/process/nope", "127.0.0.1:8090", "", map[string]string{"X-SSG-Lang": "ru"})
	if !strings.Contains(w.Body.String(), "процесс не найден") {
		t.Errorf("ошибка на русском: %s", w.Body)
	}
	w = do(s, "GET", "/api/process/nope", "127.0.0.1:8090", "", nil)
	if !strings.Contains(w.Body.String(), "process not found") {
		t.Errorf("ошибка на английском (SSG_LANG): %s", w.Body)
	}
}

// TestStaticKeysAndSafety: разметка не использует innerHTML, а скрипты
// подключают i18n.js раньше страницы (они делят глобальные функции).
func TestStaticKeysAndSafety(t *testing.T) {
	for _, name := range []string{"app.js", "login.js", "i18n.js"} {
		data, err := staticFS.ReadFile("static/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), ".innerHTML") || strings.Contains(string(data), "insertAdjacentHTML") {
			t.Errorf("%s: innerHTML запрещён", name)
		}
	}
	for page, script := range map[string]string{"index.html": "app.js", "login.html": "login.js"} {
		data, _ := staticFS.ReadFile("static/" + page)
		i, j := strings.Index(string(data), "/static/i18n.js"), strings.Index(string(data), "/static/"+script)
		if i < 0 || j < 0 || i > j {
			t.Errorf("%s: i18n.js должен подключаться до %s", page, script)
		}
		if !strings.Contains(string(data), htmlLangAttr) {
			t.Errorf("%s: нет %s — сервер не сможет выставить язык", page, htmlLangAttr)
		}
	}
}

// TestExposureAPI: GET /api/exposure отдаёт порты демо-системы, требует
// входа при заданном пароле и не раскрывает окружение контейнеров.
func TestExposureAPI(t *testing.T) {
	s := newTestServer(t, "")
	w := do(s, "GET", "/api/exposure", "127.0.0.1:8090", "", nil)
	if w.Code != 200 {
		t.Fatalf("код %d: %s", w.Code, w.Body)
	}
	var resp struct {
		Exposure model.ExposureReport `json:"exposure"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	x := resp.Exposure
	if len(x.Entries) == 0 || x.Firewall.UFW != "active" || len(x.Addrs) == 0 || len(x.Bindings) != 2 {
		t.Errorf("ответ: %+v", x)
	}
	if strings.Contains(w.Body.String(), "SECRET=demo") {
		t.Error("окружение контейнера в ответе API")
	}
	// Счётчики для заголовка — в /api/status.
	w = do(s, "GET", "/api/status", "127.0.0.1:8090", "", nil)
	var st view.Status
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || st.Stats.PublicPorts == 0 || st.Stats.DangerousPorts == 0 {
		t.Errorf("статус: %v %+v", err, st.Stats)
	}
	// Только GET.
	if w := do(s, "POST", "/api/exposure", "127.0.0.1:8090", "", map[string]string{"X-CSRF-Token": s.noAuthCSRF}); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
	// С паролем — без входа 401, чужой Host — отказ.
	hash, _ := HashPassword("correct horse battery")
	sa := newTestServer(t, hash)
	if w := do(sa, "GET", "/api/exposure", "127.0.0.1:8090", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("без входа: %d", w.Code)
	}
	if w := do(s, "GET", "/api/exposure", "evil.example", "", nil); w.Code == 200 {
		t.Error("чужой Host пропущен")
	}
}

// fakeAudit — аудит для тестов панели.
type fakeAudit struct {
	rep     *model.AuditReport
	running bool
	runs    int
}

func (f *fakeAudit) Report() *model.AuditReport { return f.rep }
func (f *fakeAudit) Running() bool              { return f.running }
func (f *fakeAudit) Interval() time.Duration    { return time.Hour }
func (f *fakeAudit) RunNow() bool {
	if f.running {
		return false
	}
	f.runs++
	return true
}

func TestAuditAPI(t *testing.T) {
	// Аудит выключен: вкладка сообщает об этом, запуск — 409.
	s := newTestServer(t, "")
	w := do(s, "GET", "/api/audit", "127.0.0.1:8090", "", nil)
	var v view.AuditView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || w.Code != 200 || v.Enabled || v.Checks == nil {
		t.Fatalf("выключенный аудит: %d %v %+v", w.Code, err, v)
	}
	if w := do(s, "POST", "/api/audit/run", "127.0.0.1:8090", "", map[string]string{"X-CSRF-Token": s.noAuthCSRF}); w.Code != http.StatusConflict {
		t.Errorf("запуск выключенного аудита: %d", w.Code)
	}

	fa := &fakeAudit{rep: &model.AuditReport{Time: time.Now(), Checks: []model.AuditCheck{
		{ID: "ssh_password_auth", Group: "ssh", Title: i18n.L("x"), Status: model.AuditFail, Severity: model.RiskHigh},
		{ID: "ssh_port", Group: "ssh", Title: i18n.L("y"), Status: model.AuditInfo},
		{ID: "ssh_root_login", Group: "ssh", Title: i18n.L("z"), Status: model.AuditPass, Severity: model.RiskHigh},
	}}}
	s.opt.Audit = fa
	w = do(s, "GET", "/api/audit", "127.0.0.1:8090", "", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || !v.Enabled || !v.Ready || v.Passed != 1 || v.Total != 2 || v.Checks[0].Status != model.AuditFail {
		t.Fatalf("аудит: %v %+v", err, v)
	}
	// Счётчики в /api/status.
	var st view.Status
	_ = json.Unmarshal(do(s, "GET", "/api/status", "127.0.0.1:8090", "", nil).Body.Bytes(), &st)
	if !st.Audit.Ready || st.Audit.Fail != 1 || st.Audit.Warn != 0 {
		t.Errorf("статус: %+v", st.Audit)
	}
	// Запуск требует CSRF.
	if w := do(s, "POST", "/api/audit/run", "127.0.0.1:8090", "", nil); w.Code != http.StatusForbidden || fa.runs != 0 {
		t.Errorf("без CSRF: %d, запусков %d", w.Code, fa.runs)
	}
	w = do(s, "POST", "/api/audit/run", "127.0.0.1:8090", "", map[string]string{"X-CSRF-Token": s.noAuthCSRF})
	if w.Code != http.StatusAccepted || fa.runs != 1 || !strings.Contains(w.Body.String(), `"started":true`) {
		t.Errorf("запуск: %d %s", w.Code, w.Body)
	}
	// Во время проверки новая не запускается.
	fa.running = true
	w = do(s, "POST", "/api/audit/run", "127.0.0.1:8090", "", map[string]string{"X-CSRF-Token": s.noAuthCSRF})
	if !strings.Contains(w.Body.String(), `"started":false`) || fa.runs != 1 {
		t.Errorf("повторный запуск: %s", w.Body)
	}
	// С паролем — без входа 401.
	hash, _ := HashPassword("correct horse battery")
	sa := newTestServer(t, hash)
	sa.opt.Audit = fa
	if w := do(sa, "GET", "/api/audit", "127.0.0.1:8090", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("без входа: %d", w.Code)
	}
}

// TestFail2banAPI: /api/fail2ban отдаёт баны и статистику демо-системы,
// /api/status — краткую сводку; без fail2ban — только installed: false и
// никакой сводки в статусе (раздел не показывается).
func TestFail2banAPI(t *testing.T) {
	s := newTestServer(t, "")
	w := do(s, "GET", "/api/fail2ban", "127.0.0.1:8090", "", nil)
	if w.Code != 200 {
		t.Fatalf("код %d: %s", w.Code, w.Body)
	}
	var rep model.Fail2banReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !rep.Running || len(rep.Bans) == 0 || rep.Bans[0].UnbanCommand == "" || len(rep.Hourly) == 0 || len(rep.Jails) == 0 {
		t.Errorf("ответ: installed=%v running=%v bans=%d hourly=%d", rep.Installed, rep.Running, len(rep.Bans), len(rep.Hourly))
	}
	w = do(s, "GET", "/api/status", "127.0.0.1:8090", "", nil)
	var st view.Status
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || st.Fail2ban == nil || !st.Fail2ban.Installed || st.Fail2ban.Banned != len(rep.Bans) {
		t.Errorf("статус: %v %+v", err, st.Fail2ban)
	}
	hash, _ := HashPassword("correct horse battery")
	if w := do(newTestServer(t, hash), "GET", "/api/fail2ban", "127.0.0.1:8090", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("без входа: %d", w.Code)
	}
	if w := do(s, "GET", "/api/fail2ban", "evil.example", "", nil); w.Code == 200 {
		t.Error("чужой Host пропущен")
	}

	// Сервер без fail2ban.
	tree := fakeproc.Demo(time.Now())
	for k := range tree.HostFiles {
		if strings.Contains(k, "fail2ban") {
			delete(tree.HostFiles, k)
		}
	}
	procs := tree.Procs[:0]
	for _, p := range tree.Procs {
		if p.Comm != "fail2ban-server" {
			procs = append(procs, p)
		}
	}
	tree.Procs = procs
	s = newTreeServer(t, tree, "")
	w = do(s, "GET", "/api/fail2ban", "127.0.0.1:8090", "", nil)
	if strings.TrimSpace(w.Body.String()) != `{"installed":false}` {
		t.Errorf("без fail2ban: %s", w.Body)
	}
	w = do(s, "GET", "/api/status", "127.0.0.1:8090", "", nil)
	if strings.Contains(w.Body.String(), `"fail2ban"`) {
		t.Errorf("сводка fail2ban в статусе без fail2ban: %s", w.Body)
	}
}

// TestMetricsAPI: без сборщика раздел выключен, со сборщиком отдаются
// текущие значения и ряды выбранного окна.
func TestMetricsAPI(t *testing.T) {
	s := newTestServer(t, "")
	w := do(s, "GET", "/api/metrics", "127.0.0.1:8090", "", nil)
	var off metrics.View
	if err := json.Unmarshal(w.Body.Bytes(), &off); err != nil || off.Enabled {
		t.Fatalf("выключенные метрики: %v %+v", err, off)
	}
	// /api/status без сборщика сводку не присылает: по ней интерфейсы
	// решают, показывать ли вкладку.
	var st view.Status
	ws := do(s, "GET", "/api/status", "127.0.0.1:8090", "", nil)
	if err := json.Unmarshal(ws.Body.Bytes(), &st); err != nil || st.Metrics != nil {
		t.Errorf("сводка без сборщика: %v %+v", err, st.Metrics)
	}

	tree := fakeproc.Demo(time.Now())
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mc := metrics.New(metrics.Options{ProcRoot: procRoot, HostRoot: hostRoot, Interval: time.Second,
		DiskUsage: fakeproc.DemoUsage, Logger: log})
	if _, err := mc.Collect(time.Now()); err != nil {
		t.Fatal(err)
	}
	hist, _ := history.Open(history.Options{})
	sc := scanner.New(scanner.Options{FS: fakeproc.NewFS(procRoot, hostRoot), Detect: detect.DefaultConfig(), History: hist, Logger: log, Metrics: mc})
	if _, err := sc.ScanOnce(); err != nil {
		t.Fatal(err)
	}
	sm := New(Options{Scanner: sc, Logger: log, Version: "test", ListenAddr: "127.0.0.1:8090", Metrics: mc})
	w = do(sm, "GET", "/api/metrics?range=24h", "127.0.0.1:8090", "", nil)
	if w.Code != 200 {
		t.Fatalf("код %d: %s", w.Code, w.Body)
	}
	var mv metrics.View
	if err := json.Unmarshal(w.Body.Bytes(), &mv); err != nil {
		t.Fatal(err)
	}
	if !mv.Enabled || !mv.Ready || mv.Range != "24h" || mv.Now == nil {
		t.Fatalf("ответ: %+v", mv)
	}
	if !mv.VM {
		t.Error("демо-сервер — виртуальная машина (флаг hypervisor)")
	}
	if len(mv.Now.Parts) == 0 || mv.Now.NumCPU == 0 {
		t.Errorf("текущие значения: %+v", mv.Now)
	}
	// Неизвестное окно приводится к часу, а не отвергается.
	w = do(sm, "GET", "/api/metrics?range=zzz", "127.0.0.1:8090", "", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &mv); err != nil || mv.Range != "1h" {
		t.Errorf("окно по умолчанию: %v %q", err, mv.Range)
	}
	// Признак заполненного раздела из метрик попал в системные находки.
	ws = do(sm, "GET", "/api/system", "127.0.0.1:8090", "", nil)
	if !strings.Contains(ws.Body.String(), "disk_almost_full") {
		t.Errorf("признаки метрик не попали в /api/system: %s", ws.Body)
	}
	// Сводка для шапки.
	ws = do(sm, "GET", "/api/status", "127.0.0.1:8090", "", nil)
	if err := json.Unmarshal(ws.Body.Bytes(), &st); err != nil || st.Metrics == nil || !st.Metrics.Ready {
		t.Errorf("сводка метрик: %v %+v", err, st.Metrics)
	}
	if w := do(sm, "POST", "/api/metrics", "127.0.0.1:8090", "", map[string]string{"X-CSRF-Token": sm.noAuthCSRF}); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

// TestNetLoadAPI: без наблюдения раздел выключен, со наблюдением
// отдаются порты, источники и счётчики, а признаки попадают в систему.
func TestNetLoadAPI(t *testing.T) {
	s := newTestServer(t, "")
	w := do(s, "GET", "/api/netload", "127.0.0.1:8090", "", nil)
	var off view.NetLoadView
	if err := json.Unmarshal(w.Body.Bytes(), &off); err != nil || off.Enabled {
		t.Fatalf("выключенное наблюдение: %v %+v", err, off)
	}
	var st view.Status
	ws := do(s, "GET", "/api/status", "127.0.0.1:8090", "", nil)
	if err := json.Unmarshal(ws.Body.Bytes(), &st); err != nil || st.Net != nil {
		t.Errorf("сводка без наблюдения: %v %+v", err, st.Net)
	}

	tree := fakeproc.Demo(time.Now())
	procRoot, hostRoot, err := tree.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mc := metrics.New(metrics.Options{ProcRoot: procRoot, HostRoot: hostRoot, Interval: time.Second,
		DiskUsage: fakeproc.DemoUsage, Logger: log})
	nl := netload.New(netload.Options{ProcRoot: procRoot, Config: netload.Config{ConnPerIP: 200, SurgeFactor: 5,
		Trusted: fakeproc.DemoTrustedNets(), TrustedRaw: fakeproc.DemoTrustedRaw()}, Baseline: mc.Median})
	mc.SetExtra(nl)
	if _, err := mc.Collect(time.Now()); err != nil {
		t.Fatal(err)
	}
	hist, _ := history.Open(history.Options{})
	fs := fakeproc.NewFS(procRoot, hostRoot)
	sc := scanner.New(scanner.Options{FS: fs, Detect: detect.DefaultConfig(), History: hist, Logger: log, Metrics: mc, NetLoad: nl})
	// Два сканирования: признаки по соединениям требуют двух подряд.
	for range 2 {
		if _, err := sc.ScanOnce(); err != nil {
			t.Fatal(err)
		}
	}
	sn := New(Options{Scanner: sc, Logger: log, Version: "test", ListenAddr: "127.0.0.1:8090", Metrics: mc, NetLoad: nl})
	w = do(sn, "GET", "/api/netload", "127.0.0.1:8090", "", nil)
	if w.Code != 200 {
		t.Fatalf("код %d: %s", w.Code, w.Body)
	}
	var nv view.NetLoadView
	if err := json.Unmarshal(w.Body.Bytes(), &nv); err != nil {
		t.Fatal(err)
	}
	if !nv.Enabled || !nv.Ready || nv.NetLoadReport == nil {
		t.Fatalf("ответ: %+v", nv)
	}
	p443, ok := func() (model.PortLoad, bool) {
		for _, p := range nv.Listen {
			if p.Port == 443 {
				return p, true
			}
		}
		return model.PortLoad{}, false
	}()
	if !ok || p443.HalfOpen < 500 || p443.Backlog != 1024 {
		t.Errorf("порт 443: %+v", p443)
	}
	// Демо: флуд из 203.0.113.0/24 и доверенная сеть 198.51.100.0/24.
	var flood, trusted bool
	for _, src := range nv.TopSources {
		if src.Addr == "203.0.113.0/24" && src.Conns > 500 {
			flood = true
		}
		if src.Trusted {
			trusted = true
		}
	}
	if !flood || !trusted {
		t.Errorf("источники: %+v", nv.TopSources)
	}
	if nv.Conntrack == nil || nv.Conntrack.Percent < 90 {
		t.Errorf("conntrack: %+v", nv.Conntrack)
	}
	if len(nv.Active) == 0 {
		t.Errorf("признаки: %+v", nv.Active)
	}
	// Признаки сетевой нагрузки попали в системные находки и в сводку.
	ws = do(sn, "GET", "/api/system", "127.0.0.1:8090", "", nil)
	if !strings.Contains(ws.Body.String(), "net_") {
		t.Errorf("признаки netload не попали в /api/system: %s", ws.Body)
	}
	ws = do(sn, "GET", "/api/status", "127.0.0.1:8090", "", nil)
	if err := json.Unmarshal(ws.Body.Bytes(), &st); err != nil || st.Net == nil || st.Net.Alerts == 0 {
		t.Errorf("сводка сетевой нагрузки: %v %+v", err, st.Net)
	}
	if w := do(sn, "POST", "/api/netload", "127.0.0.1:8090", "", map[string]string{"X-CSRF-Token": sn.noAuthCSRF}); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

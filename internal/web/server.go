// Пакет web — локальный веб-сервер: JSON API и встроенный (embed)
// русскоязычный интерфейс без внешних зависимостей и CDN.
//
// Защита:
//   - по умолчанию слушает 127.0.0.1 (проверяется в config.ValidateSecurity);
//   - проверка заголовка Host защищает от DNS rebinding: чужой сайт не
//     сможет из браузера пользователя прочитать список процессов с
//     127.0.0.1;
//   - при заданном пароле — вход по форме, серверные сессии, cookie
//     HttpOnly + SameSite=Strict (+Secure при TLS), ограничение попыток;
//   - все изменяющие запросы (POST) требуют CSRF-токен в заголовке;
//   - строгая CSP без inline-скриптов; интерфейс выводит данные только
//     через textContent, поэтому имена и cmdline процессов (их
//     контролирует потенциальный злоумышленник) не исполняются как HTML.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/metrics"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

//go:embed static
var staticFS embed.FS

const cookieName = "ssg_session"

// cookie — имя cookie сессии. При TLS — с префиксом __Host-: браузер
// примет её только с Secure, Path=/ и без Domain, поэтому соседний
// поддомен или страница по HTTP не подменят и не перехватят сессию.
func (s *Server) cookie() string {
	if s.opt.SecureCookie {
		return "__Host-" + cookieName
	}
	return cookieName
}

// Options — параметры веб-сервера.
type Options struct {
	Scanner      *scanner.Scanner
	Logger       *slog.Logger
	Version      string
	ListenAddr   string
	PasswordHash string // пусто — без авторизации (только для loopback)
	SessionTTL   time.Duration
	SecureCookie bool // TLS включён (свой или на прокси)
	// TrustProxy — панель за reverse proxy (SSG_TRUST_PROXY_TLS): адрес
	// клиента для ограничения попыток входа берётся из X-Forwarded-For.
	TrustProxy   bool
	AllowedHosts []string // дополнительные допустимые значения Host
	Demo         bool
	// CheckPeer — без пароля пускать только пользователей LocalUIDs: UID
	// владельца клиентского сокета кладёт в контекст PeerContext. Иначе
	// любой локальный пользователь (например, взломанный www-data) читал
	// бы через 127.0.0.1 данные, которые служба собирает от root.
	CheckPeer bool
	LocalUIDs []int
	// Lang — язык панели по умолчанию (SSG_LANG). Пусто — по заголовку
	// Accept-Language браузера. Пользователь может переключить язык в
	// панели, выбор хранится в его браузере.
	Lang i18n.Lang
	// Audit — аудит настроек безопасности (audit.Runner); nil — выключен
	// (SSG_AUDIT_ENABLED=false).
	Audit AuditRunner
	// Metrics — метрики сервера (metrics.Collector); nil — выключены
	// (SSG_METRICS_ENABLED=false).
	Metrics MetricsSource
}

// MetricsSource — то, что панели нужно от метрик сервера.
type MetricsSource interface {
	View(rng string) metrics.View
	Brief() *metrics.Brief
}

// AuditRunner — то, что панели нужно от аудита конфигурации.
type AuditRunner interface {
	Report() *model.AuditReport
	Running() bool
	RunNow() bool
	Interval() time.Duration
}

// Server — HTTP-обработчик приложения.
type Server struct {
	opt      Options
	sessions *sessionStore
	limiter  *loginLimiter
	// noAuthCSRF — CSRF-токен для режима без пароля (один на процесс).
	noAuthCSRF string
	hosts      map[string]bool
	mux        *http.ServeMux
	// catalogs — готовые JSON-каталоги переводов для веб-панели и их ETag.
	catalogs map[i18n.Lang]catalogFile
}

type catalogFile struct {
	data []byte
	etag string
}

// New создаёт сервер.
func New(opt Options) *Server {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.SessionTTL <= 0 {
		opt.SessionTTL = 12 * time.Hour
	}
	s := &Server{opt: opt, sessions: newSessionStore(opt.SessionTTL), limiter: newLoginLimiter(), noAuthCSRF: randomToken(), mux: http.NewServeMux()}
	s.hosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	if h, _, err := net.SplitHostPort(opt.ListenAddr); err == nil && h != "" && h != "0.0.0.0" && h != "::" {
		s.hosts[strings.ToLower(h)] = true
	}
	for _, h := range opt.AllowedHosts {
		s.hosts[strings.ToLower(h)] = true
	}
	s.catalogs = make(map[i18n.Lang]catalogFile, len(i18n.Langs))
	for _, l := range i18n.Langs {
		data, _ := json.Marshal(i18n.Catalog(l))
		sum := sha256.Sum256(data)
		s.catalogs[l] = catalogFile{data: data, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
	}
	s.routes()
	return s
}

// lang — язык ответа: заголовок X-SSG-Lang (его шлёт панель, когда
// пользователь выбрал язык), затем SSG_LANG, затем Accept-Language.
func (s *Server) lang(r *http.Request) i18n.Lang {
	if l, ok := i18n.Parse(r.Header.Get("X-SSG-Lang")); ok {
		return l
	}
	return s.defaultLang(r)
}

// defaultLang — язык страницы, пока пользователь не выбрал свой.
func (s *Server) defaultLang(r *http.Request) i18n.Lang {
	if s.opt.Lang != "" {
		return s.opt.Lang
	}
	return i18n.FromAcceptLanguage(r.Header.Get("Accept-Language"))
}

// tr — строка каталога на языке запроса (тексты ошибок API).
func (s *Server) tr(r *http.Request, key string, args ...any) string {
	return i18n.T(key, args...).In(s.lang(r))
}

// errJSON — ответ API с ошибкой на языке запроса.
func (s *Server) errJSON(w http.ResponseWriter, r *http.Request, code int, key string) {
	writeJSON(w, code, map[string]string{"error": s.tr(r, key)})
}

// handleCatalog отдаёт каталог переводов одного языка. Он публичный:
// нужен и странице входа, а секретов в нём нет.
func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	l, ok := i18n.Parse(strings.TrimSuffix(r.PathValue("file"), ".json"))
	if !ok || !strings.HasSuffix(r.PathValue("file"), ".json") {
		http.NotFound(w, r)
		return
	}
	c := s.catalogs[l]
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", c.etag)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(c.data))
}

func (s *Server) authEnabled() bool { return s.opt.PasswordHash != "" }

func (s *Server) routes() {
	static, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(static)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.opt.Scanner.Snapshot() == nil {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", files))
	s.mux.HandleFunc("GET /i18n/{file}", s.handleCatalog)
	s.mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) { s.serveFile(w, r, static, "login.html") })
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("GET /{$}", s.page(static, "index.html"))
	s.mux.HandleFunc("GET /api/status", s.api(s.handleStatus))
	s.mux.HandleFunc("GET /api/processes", s.api(s.handleProcesses))
	s.mux.HandleFunc("GET /api/process/{key}", s.api(s.handleProcess))
	s.mux.HandleFunc("GET /api/tree", s.api(s.handleTree))
	s.mux.HandleFunc("GET /api/connections", s.api(s.handleConnections))
	s.mux.HandleFunc("GET /api/exposure", s.api(s.handleExposure))
	s.mux.HandleFunc("GET /api/fail2ban", s.api(s.handleFail2ban))
	s.mux.HandleFunc("GET /api/events", s.api(s.handleEvents))
	s.mux.HandleFunc("GET /api/system", s.api(s.handleSystem))
	s.mux.HandleFunc("GET /api/metrics", s.api(s.handleMetrics))
	s.mux.HandleFunc("POST /api/rescan", s.api(s.handleRescan))
	s.mux.HandleFunc("GET /api/audit", s.api(s.handleAudit))
	s.mux.HandleFunc("POST /api/audit/run", s.api(s.handleAuditRun))
}

// ServeHTTP применяет общие проверки и заголовки безопасности.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if s.opt.SecureCookie {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if !trusted(r) && !s.hostAllowed(r.Host) {
		http.Error(w, s.tr(r, "web.err.host"), http.StatusMisdirectedRequest)
		return
	}
	// /healthz открыт всем: он не раскрывает данных, а по нему скрипты
	// проверяют запуск службы.
	if s.opt.CheckPeer && !s.authEnabled() && !trusted(r) && r.URL.Path != "/healthz" {
		if uid, ok := peerUID(r.Context()); !ok || !slices.Contains(s.opt.LocalUIDs, uid) {
			who := "unknown"
			if ok {
				who = strconv.Itoa(uid)
			}
			s.opt.Logger.Warn(i18n.S("log.peer_denied"), "uid", who, "remote", r.RemoteAddr)
			http.Error(w, s.tr(r, "web.err.peer"), http.StatusForbidden)
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

// peerKey — UID владельца клиентского сокета в контексте соединения.
type peerKey struct{}

type peerInfo struct {
	uid int
	ok  bool
}

// PeerContext возвращает функцию для http.Server.ConnContext: при
// подключении она определяет UID владельца клиентского сокета через
// owner (procfs.FS.SocketOwner) и кладёт его в контекст соединения.
func PeerContext(owner func(local, remote netip.AddrPort) (int, bool)) func(context.Context, net.Conn) context.Context {
	return func(ctx context.Context, c net.Conn) context.Context {
		var info peerInfo
		client, err1 := netip.ParseAddrPort(c.RemoteAddr().String())
		server, err2 := netip.ParseAddrPort(c.LocalAddr().String())
		if err1 == nil && err2 == nil {
			info.uid, info.ok = owner(client, server)
		}
		return context.WithValue(ctx, peerKey{}, info)
	}
}

func peerUID(ctx context.Context) (int, bool) {
	info, _ := ctx.Value(peerKey{}).(peerInfo)
	return info.uid, info.ok
}

// trustedKey помечает запросы, пришедшие через локальный Unix-сокет.
type trustedKey struct{}

// LocalHandler — обработчик для локального Unix-сокета службы. Сокет
// доступен только root (права 0600 в каталоге 0700), поэтому права файла
// и есть авторизация: вход по паролю, проверка Host и CSRF не нужны —
// браузер к Unix-сокету обратиться не может. Через сокет работает
// терминальный интерфейс (serversecuritygo tui).
func (s *Server) LocalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), trustedKey{}, true)))
	})
}

func trusted(r *http.Request) bool {
	v, _ := r.Context().Value(trustedKey{}).(bool)
	return v
}

func (s *Server) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return s.hosts[host]
}

// session возвращает текущую сессию; в режиме без пароля — всегда
// успешно с общим CSRF-токеном.
func (s *Server) session(r *http.Request) (session, bool) {
	if !s.authEnabled() || trusted(r) {
		return session{csrf: s.noAuthCSRF}, true
	}
	c, err := r.Cookie(s.cookie())
	if err != nil {
		return session{}, false
	}
	return s.sessions.get(c.Value, time.Now())
}

// page отдаёт HTML-страницу или перенаправляет на вход.
func (s *Server) page(static fs.FS, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s.serveFile(w, r, static, name)
	}
}

// htmlLangAttr — атрибут языка в embed-страницах; при отдаче он
// заменяется языком по умолчанию, по которому панель выбирает перевод,
// пока пользователь не выбрал свой.
const htmlLangAttr = `<html lang="ru">`

func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, static fs.FS, name string) {
	data, err := fs.ReadFile(static, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data = bytes.Replace(data, []byte(htmlLangAttr), []byte(`<html lang="`+string(s.defaultLang(r))+`">`), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Accept-Language")
	w.Write(data)
}

// api оборачивает обработчик API: авторизация и CSRF для POST.
func (s *Server) api(h func(w http.ResponseWriter, r *http.Request, sess session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			s.errJSON(w, r, http.StatusUnauthorized, "web.err.login_required")
			return
		}
		if r.Method != http.MethodGet && !trusted(r) && !tokenEqual(r.Header.Get("X-CSRF-Token"), sess.csrf) {
			s.errJSON(w, r, http.StatusForbidden, "web.err.csrf")
			return
		}
		h(w, r, sess)
	}
}

// tokenEqual сравнивает CSRF-токены за постоянное время: обычное
// сравнение строк выходит на первом несовпавшем байте, и по времени
// ответа токен можно было бы подбирать посимвольно.
func tokenEqual(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// clientIP — адрес клиента для ограничения попыток входа. За reverse
// proxy все запросы приходят с его адреса, и общий счётчик позволял
// любому заблокировать вход администратору пятью неверными паролями.
// Поэтому при trustProxy и подключении с loopback берётся крайний правый
// адрес X-Forwarded-For — его дописывает сам прокси, подделать его
// клиент не может. Без прокси заголовок игнорируется.
func clientIP(r *http.Request, trustProxy bool) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	if ip, err := netip.ParseAddr(host); trustProxy && err == nil && ip.IsLoopback() {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if fwd, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				host = fwd.String()
			}
		}
	}
	return host
}

// limitKey — ключ счётчика попыток: IPv4 целиком, IPv6 — сеть /64
// (провайдер выдаёт клиенту целую /64, и смена адреса внутри неё не
// должна сбрасывать лимит).
func limitKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled() {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	ip := clientIP(r, s.opt.TrustProxy)
	key := limitKey(ip)
	now := time.Now()
	var req struct {
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errJSON(w, r, http.StatusBadRequest, "web.err.bad_request")
		return
	}
	if !s.limiter.begin(key, now) {
		s.opt.Logger.Warn(i18n.S("log.login_blocked"), "ip", ip)
		s.errJSON(w, r, http.StatusTooManyRequests, "web.err.too_many")
		return
	}
	if !s.limiter.acquire(3 * time.Second) {
		s.errJSON(w, r, http.StatusTooManyRequests, "web.err.busy")
		return
	}
	ok := VerifyPassword(s.opt.PasswordHash, req.Password)
	s.limiter.release()
	if !ok {
		// Пароль в журнал не пишем никогда — только факт и адрес.
		s.opt.Logger.Warn(i18n.S("log.login_failed"), "ip", ip)
		s.errJSON(w, r, http.StatusUnauthorized, "web.err.bad_password")
		return
	}
	s.limiter.reset(key)
	tok, _ := s.sessions.create(now)
	http.SetCookie(w, &http.Cookie{Name: s.cookie(), Value: tok, Path: "/", HttpOnly: true, Secure: s.opt.SecureCookie,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.opt.SessionTTL.Seconds())})
	s.opt.Logger.Info(i18n.S("log.login_ok"), "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r)
	if ok && s.authEnabled() && tokenEqual(r.Header.Get("X-CSRF-Token"), sess.csrf) {
		if c, err := r.Cookie(s.cookie()); err == nil {
			s.sessions.delete(c.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookie(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.opt.SecureCookie, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// snapshot возвращает текущий снимок или пишет 503.
func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) *model.Snapshot {
	snap := s.opt.Scanner.Snapshot()
	if snap == nil {
		s.errJSON(w, r, http.StatusServiceUnavailable, "err.first_scan_running")
	}
	return snap
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, sess session) {
	st := view.Status{Version: s.opt.Version, Auth: s.authEnabled(), CSRF: sess.csrf, Demo: s.opt.Demo, Interval: s.opt.Scanner.Interval().Seconds()}
	st = view.BuildStatus(st, s.opt.Scanner.Snapshot())
	if a := s.opt.Audit; a != nil {
		st.Audit = view.BuildAuditBrief(true, a.Running(), a.Report())
	}
	if m := s.opt.Metrics; m != nil {
		st.Metrics = m.Brief()
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w, r)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"time": snap.Time, "seq": snap.Seq, "processes": view.SummarizeAll(snap)})
}

func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w, r)
	if snap == nil {
		return
	}
	d, ok := view.BuildDetail(snap, s.opt.Scanner.History(), r.PathValue("key"))
	if !ok {
		s.errJSON(w, r, http.StatusNotFound, "err.process_not_found")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleTree(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w, r)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roots": view.BuildTree(snap)})
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w, r)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sockets": snap.Sockets})
}

// handleExposure отдаёт внешнюю поверхность атаки: слушающие порты с
// областью видимости, узнанные сервисы, состояние ufw и порты Docker.
func (s *Server) handleExposure(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w, r)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"time": snap.Time, "seq": snap.Seq, "exposure": view.Exposure(snap)})
}

// handleFail2ban отдаёт состояние fail2ban и статистику перебора паролей.
// Если fail2ban не установлен — только {"installed": false}: панель и
// терминал по этому флагу раздел не показывают.
func (s *Server) handleFail2ban(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w, r)
	if snap == nil {
		return
	}
	rep := view.Fail2ban(snap)
	if !rep.Installed {
		writeJSON(w, http.StatusOK, map[string]bool{"installed": false})
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleMetrics отдаёт метрики сервера: текущие значения и ряды за
// окно (range=1h|24h|30d). Если сбор выключен — {"enabled": false}:
// панель и терминал по этому флагу раздел не показывают.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request, _ session) {
	if s.opt.Metrics == nil {
		writeJSON(w, http.StatusOK, metrics.View{Series: map[string][]metrics.Point{}, Alerts: []string{}})
		return
	}
	writeJSON(w, http.StatusOK, s.opt.Metrics.View(r.URL.Query().Get("range")))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, _ session) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	ev := s.opt.Scanner.History().Events(limit)
	slices.Reverse(ev) // новые сверху
	writeJSON(w, http.StatusOK, map[string]any{"events": ev})
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w, r)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": view.SortedSystem(snap), "host": snap.Host, "warnings": snap.Warnings})
}

// auditView — текущее состояние аудита конфигурации.
func (s *Server) auditView() view.AuditView {
	if s.opt.Audit == nil {
		return view.BuildAudit(false, false, 0, nil)
	}
	a := s.opt.Audit
	return view.BuildAudit(true, a.Running(), a.Interval(), a.Report())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ session) {
	writeJSON(w, http.StatusOK, s.auditView())
}

// handleAuditRun — «Проверить сейчас». Если проверка уже идёт, новая не
// запускается (started: false).
func (s *Server) handleAuditRun(w http.ResponseWriter, r *http.Request, _ session) {
	if s.opt.Audit == nil {
		s.errJSON(w, r, http.StatusConflict, "web.err.audit_disabled")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"started": s.opt.Audit.RunNow()})
}

func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request, _ session) {
	s.opt.Scanner.Rescan()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

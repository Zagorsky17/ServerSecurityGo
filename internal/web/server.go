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
	"context"
	"crypto/subtle"
	"embed"
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
	s.routes()
	return s
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
	s.mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) { serveFile(w, r, static, "login.html") })
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("GET /{$}", s.page(static, "index.html"))
	s.mux.HandleFunc("GET /api/status", s.api(s.handleStatus))
	s.mux.HandleFunc("GET /api/processes", s.api(s.handleProcesses))
	s.mux.HandleFunc("GET /api/process/{key}", s.api(s.handleProcess))
	s.mux.HandleFunc("GET /api/tree", s.api(s.handleTree))
	s.mux.HandleFunc("GET /api/connections", s.api(s.handleConnections))
	s.mux.HandleFunc("GET /api/events", s.api(s.handleEvents))
	s.mux.HandleFunc("GET /api/system", s.api(s.handleSystem))
	s.mux.HandleFunc("POST /api/rescan", s.api(s.handleRescan))
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
		http.Error(w, "недопустимый заголовок Host (см. SSG_ALLOWED_HOSTS)", http.StatusMisdirectedRequest)
		return
	}
	// /healthz открыт всем: он не раскрывает данных, а по нему скрипты
	// проверяют запуск службы.
	if s.opt.CheckPeer && !s.authEnabled() && !trusted(r) && r.URL.Path != "/healthz" {
		if uid, ok := peerUID(r.Context()); !ok || !slices.Contains(s.opt.LocalUIDs, uid) {
			who := "неизвестен"
			if ok {
				who = strconv.Itoa(uid)
			}
			s.opt.Logger.Warn("отклонён доступ к панели без пароля: пользователь не в SSG_LOCAL_UIDS", "uid", who, "remote", r.RemoteAddr)
			http.Error(w, "без пароля панель доступна только root (SSG_LOCAL_UIDS); задайте пароль или подключитесь через SSH-туннель под root", http.StatusForbidden)
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
		serveFile(w, r, static, name)
	}
}

func serveFile(w http.ResponseWriter, r *http.Request, static fs.FS, name string) {
	data, err := fs.ReadFile(static, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

// api оборачивает обработчик API: авторизация и CSRF для POST.
func (s *Server) api(h func(w http.ResponseWriter, r *http.Request, sess session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "требуется вход"})
			return
		}
		if r.Method != http.MethodGet && !trusted(r) && !tokenEqual(r.Header.Get("X-CSRF-Token"), sess.csrf) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "неверный CSRF-токен, обновите страницу"})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный запрос"})
		return
	}
	if !s.limiter.begin(key, now) {
		s.opt.Logger.Warn("вход заблокирован: слишком много попыток", "ip", ip)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "слишком много неудачных попыток, повторите через 15 минут"})
		return
	}
	if !s.limiter.acquire(3 * time.Second) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "сервер занят проверкой других попыток входа, повторите через несколько секунд"})
		return
	}
	ok := VerifyPassword(s.opt.PasswordHash, req.Password)
	s.limiter.release()
	if !ok {
		// Пароль в журнал не пишем никогда — только факт и адрес.
		s.opt.Logger.Warn("неудачная попытка входа", "ip", ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "неверный пароль"})
		return
	}
	s.limiter.reset(key)
	tok, _ := s.sessions.create(now)
	http.SetCookie(w, &http.Cookie{Name: s.cookie(), Value: tok, Path: "/", HttpOnly: true, Secure: s.opt.SecureCookie,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.opt.SessionTTL.Seconds())})
	s.opt.Logger.Info("успешный вход", "ip", ip)
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
func (s *Server) snapshot(w http.ResponseWriter) *model.Snapshot {
	snap := s.opt.Scanner.Snapshot()
	if snap == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "первое сканирование ещё выполняется"})
	}
	return snap
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, sess session) {
	st := view.Status{Version: s.opt.Version, Auth: s.authEnabled(), CSRF: sess.csrf, Demo: s.opt.Demo, Interval: s.opt.Scanner.Interval().Seconds()}
	writeJSON(w, http.StatusOK, view.BuildStatus(st, s.opt.Scanner.Snapshot()))
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"time": snap.Time, "seq": snap.Seq, "processes": view.SummarizeAll(snap)})
}

func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w)
	if snap == nil {
		return
	}
	d, ok := view.BuildDetail(snap, s.opt.Scanner.History(), r.PathValue("key"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "процесс не найден"})
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleTree(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roots": view.BuildTree(snap)})
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sockets": snap.Sockets})
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
	snap := s.snapshot(w)
	if snap == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": view.SortedSystem(snap), "host": snap.Host, "warnings": snap.Warnings})
}

func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request, _ session) {
	s.opt.Scanner.Rescan()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

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
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
)

//go:embed static
var staticFS embed.FS

const cookieName = "ssg_session"

// Options — параметры веб-сервера.
type Options struct {
	Scanner      *scanner.Scanner
	Logger       *slog.Logger
	Version      string
	ListenAddr   string
	PasswordHash string // пусто — без авторизации (только для loopback)
	SessionTTL   time.Duration
	SecureCookie bool     // TLS включён (свой или на прокси)
	AllowedHosts []string // дополнительные допустимые значения Host
	Demo         bool
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
	if !s.hostAllowed(r.Host) {
		http.Error(w, "недопустимый заголовок Host (см. SSG_ALLOWED_HOSTS)", http.StatusMisdirectedRequest)
		return
	}
	s.mux.ServeHTTP(w, r)
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
	if !s.authEnabled() {
		return session{csrf: s.noAuthCSRF}, true
	}
	c, err := r.Cookie(cookieName)
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
		if r.Method != http.MethodGet && r.Header.Get("X-CSRF-Token") != sess.csrf {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "неверный CSRF-токен, обновите страницу"})
			return
		}
		h(w, r, sess)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled() {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	ip := clientIP(r)
	now := time.Now()
	if s.limiter.blocked(ip, now) {
		s.opt.Logger.Warn("вход заблокирован: слишком много попыток", "ip", ip)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "слишком много неудачных попыток, повторите через 15 минут"})
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "неверный запрос"})
		return
	}
	if !VerifyPassword(s.opt.PasswordHash, req.Password) {
		s.limiter.fail(ip, now)
		// Пароль в журнал не пишем никогда — только факт и адрес.
		s.opt.Logger.Warn("неудачная попытка входа", "ip", ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "неверный пароль"})
		return
	}
	s.limiter.reset(ip)
	tok, _ := s.sessions.create(now)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.opt.SecureCookie,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.opt.SessionTTL.Seconds())})
	s.opt.Logger.Info("успешный вход", "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r)
	if ok && s.authEnabled() && r.Header.Get("X-CSRF-Token") == sess.csrf {
		if c, err := r.Cookie(cookieName); err == nil {
			s.sessions.delete(c.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.opt.SecureCookie, SameSite: http.SameSiteStrictMode})
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
	resp := map[string]any{
		"version": s.opt.Version, "auth": s.authEnabled(), "csrf": sess.csrf, "demo": s.opt.Demo,
		"interval": s.opt.Scanner.Interval().Seconds(),
	}
	if snap := s.opt.Scanner.Snapshot(); snap != nil {
		resp["ready"] = true
		resp["time"] = snap.Time
		resp["seq"] = snap.Seq
		resp["durationMs"] = snap.Duration.Milliseconds()
		resp["host"] = snap.Host
		resp["stats"] = snap.Stats
		resp["warnings"] = snap.Warnings
		sysCount := 0
		for _, f := range snap.System {
			if f.Risk >= model.RiskLow {
				sysCount++
			}
		}
		resp["systemFindings"] = sysCount
	}
	writeJSON(w, http.StatusOK, resp)
}

// procSummary — облегчённое представление процесса для таблиц.
type procSummary struct {
	Key             string         `json:"key"`
	PID             int            `json:"pid"`
	PPID            int            `json:"ppid"`
	Name            string         `json:"name"`
	User            string         `json:"user"`
	UID             int            `json:"uid"`
	Exe             string         `json:"exe"`
	ExeDeleted      bool           `json:"exeDeleted"`
	Cmdline         string         `json:"cmdline"`
	StartTime       time.Time      `json:"startTime"`
	CPUPercent      float64        `json:"cpuPercent"`
	CPUAverage      bool           `json:"cpuAverage"`
	MemPercent      float64        `json:"memPercent"`
	RSSBytes        uint64         `json:"rssBytes"`
	Threads         int            `json:"threads"`
	Kernel          bool           `json:"kernel"`
	Container       string         `json:"container,omitempty"`
	Risk            model.Risk     `json:"risk"`
	Score           int            `json:"score"`
	Findings        []findingBrief `json:"findings"`
	Explanation     string         `json:"explanation,omitempty"`
	Recommendations []string       `json:"recommendations,omitempty"`
	FirstSeen       time.Time      `json:"firstSeen"`
	LastSeen        time.Time      `json:"lastSeen"`
	Sockets         int            `json:"sockets"`
	Restricted      bool           `json:"restricted"`
}

type findingBrief struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Category   string `json:"category"`
	Weight     int    `json:"weight"`
	Strong     bool   `json:"strong"`
	Suppressed bool   `json:"suppressed,omitempty"`
}

func summarize(p *model.Process) procSummary {
	ps := procSummary{Key: p.Key, PID: p.PID, PPID: p.PPID, Name: p.Name, User: p.User, UID: p.UID, Exe: p.Exe, ExeDeleted: p.ExeDeleted,
		Cmdline: p.Cmdline, StartTime: p.StartTime, CPUPercent: p.CPUPercent, CPUAverage: p.CPUAverage, MemPercent: p.MemPercent, RSSBytes: p.RSSBytes,
		Threads: p.Threads, Kernel: p.Kernel, Container: p.Container, Risk: p.Risk, Score: p.Score, FirstSeen: p.FirstSeen, LastSeen: p.LastSeen,
		Restricted: len(p.Access) > 0, Findings: []findingBrief{}}
	if p.ContainerRuntime != "" && ps.Container == "" {
		ps.Container = p.ContainerRuntime
	}
	for _, sk := range p.Sockets {
		if sk.Proto != "unix" {
			ps.Sockets++
		}
	}
	for _, f := range p.Findings {
		if f.Category == model.CatInfo {
			continue
		}
		ps.Findings = append(ps.Findings, findingBrief{ID: f.ID, Title: f.Title, Category: f.Category, Weight: f.Weight, Strong: f.Strong, Suppressed: f.Suppressed})
	}
	if p.Risk >= model.RiskLow {
		ps.Explanation = p.Explanation
		ps.Recommendations = p.Recommendations
	}
	return ps
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w)
	if snap == nil {
		return
	}
	out := make([]procSummary, 0, len(snap.Processes))
	for _, p := range snap.Processes {
		out = append(out, summarize(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"time": snap.Time, "seq": snap.Seq, "processes": out})
}

func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w)
	if snap == nil {
		return
	}
	key := r.PathValue("key")
	p := snap.ByKey[key]
	if p == nil {
		// Процесс мог завершиться: отдаём последние сведения из истории.
		if t, ok := s.opt.Scanner.History().Track(key); ok {
			writeJSON(w, http.StatusOK, map[string]any{"exited": true, "track": t, "events": s.opt.Scanner.History().EventsFor(key)})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "процесс не найден"})
		return
	}
	// Цепочка предков от процесса к корню.
	byPID := map[int]*model.Process{}
	for _, q := range snap.Processes {
		byPID[q.PID] = q
	}
	type link struct {
		Key  string     `json:"key"`
		PID  int        `json:"pid"`
		Name string     `json:"name"`
		User string     `json:"user"`
		Exe  string     `json:"exe"`
		Risk model.Risk `json:"risk"`
	}
	var ancestors []link
	seen := map[int]bool{p.PID: true}
	for cur := byPID[p.PPID]; cur != nil && !seen[cur.PID]; cur = byPID[cur.PPID] {
		seen[cur.PID] = true
		ancestors = append(ancestors, link{cur.Key, cur.PID, cur.Name, cur.User, cur.Exe, cur.Risk})
	}
	var children []link
	for _, c := range p.Children {
		if q := byPID[c]; q != nil {
			children = append(children, link{q.Key, q.PID, q.Name, q.User, q.Exe, q.Risk})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"process": p, "ancestors": ancestors, "children": children, "events": s.opt.Scanner.History().EventsFor(key)})
}

// treeNode — узел дерева процессов.
type treeNode struct {
	Key      string      `json:"key"`
	PID      int         `json:"pid"`
	Name     string      `json:"name"`
	User     string      `json:"user"`
	Exe      string      `json:"exe"`
	Cmdline  string      `json:"cmdline"`
	Risk     model.Risk  `json:"risk"`
	Kernel   bool        `json:"kernel"`
	Children []*treeNode `json:"children"`
}

func (s *Server) handleTree(w http.ResponseWriter, r *http.Request, _ session) {
	snap := s.snapshot(w)
	if snap == nil {
		return
	}
	nodes := map[int]*treeNode{}
	for _, p := range snap.Processes {
		nodes[p.PID] = &treeNode{Key: p.Key, PID: p.PID, Name: p.Name, User: p.User, Exe: p.Exe, Cmdline: p.Cmdline, Risk: p.Risk, Kernel: p.Kernel, Children: []*treeNode{}}
	}
	var roots []*treeNode
	for _, p := range snap.Processes {
		n := nodes[p.PID]
		if par, ok := nodes[p.PPID]; ok && p.PPID != p.PID {
			par.Children = append(par.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].PID < roots[j].PID })
	writeJSON(w, http.StatusOK, map[string]any{"roots": roots})
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
	sys := slices.Clone(snap.System)
	sort.SliceStable(sys, func(i, j int) bool { return sys[i].Risk > sys[j].Risk })
	writeJSON(w, http.StatusOK, map[string]any{"findings": sys, "host": snap.Host, "warnings": snap.Warnings})
}

func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request, _ session) {
	s.opt.Scanner.Rescan()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

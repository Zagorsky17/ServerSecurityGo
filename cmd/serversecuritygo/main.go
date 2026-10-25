// Команда serversecuritygo — мониторинг процессов Linux-сервера.
//
// Подкоманды:
//
//	(без аргументов) терминальный интерфейс, если запущено в терминале
//	tui            терминальный интерфейс (данные службы или собственный сканер)
//	serve          запустить сканер и веб-панель (режим службы)
//	scan           разовое сканирование с выводом в консоль (таблица или JSON)
//	demo           веб-панель на демонстрационных данных (работает и не на Linux)
//	hash-password  получить хеш пароля для SSG_AUTH_PASSWORD_HASH
//	version        показать версию
//
// Приложение только наблюдает: оно не завершает процессы, не удаляет
// файлы и не блокирует соединения.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/audit"
	"github.com/Zagorsky17/ServerSecurityGo/internal/config"
	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/report"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/tui"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
	"github.com/Zagorsky17/ServerSecurityGo/internal/web"
)

// version подставляется при сборке: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func usage() {
	fmt.Fprint(os.Stderr, i18n.S("cli.usage", version))
}

func main() {
	// Язык вывода: SSG_LANG, иначе локаль терминала. После чтения
	// --env-file язык уточняется в loadConfig.
	i18n.SetDefault(i18n.FromEnv())
	if len(os.Args) < 2 {
		// Без аргументов в терминале сразу открываем интерфейс — так
		// удобнее всего для быстрой диагностики на сервере.
		if tui.IsTerminal() {
			if err := cmdTUI(nil); err != nil {
				fmt.Fprintln(os.Stderr, i18n.S("cli.error", err))
				os.Exit(1)
			}
			return
		}
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "tui":
		err = cmdTUI(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "scan":
		err = cmdScan(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "demo":
		err = cmdDemo(os.Args[2:])
	case "hash-password":
		err = cmdHashPassword()
	case "version", "--version", "-v":
		fmt.Printf("serversecuritygo %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		var st exitStatus
		if errors.As(err, &st) {
			os.Exit(int(st)) // итог проверки, а не ошибка: сообщение не нужно
		}
		fmt.Fprintln(os.Stderr, i18n.S("cli.error", err))
		// scan и audit возвращают ошибку с кодом 2: у них 1 — «есть находки».
		var ce *report.CodeError
		if errors.As(err, &ce) {
			os.Exit(ce.Code)
		}
		os.Exit(1)
	}
}

// loadConfig читает --env-file (если задан) и переменные окружения.
func loadConfig(envFile string) (config.Config, error) {
	if envFile != "" {
		if err := config.LoadEnvFile(envFile); err != nil {
			return config.Config{}, i18n.Errorf("err.env_file", err)
		}
	}
	cfg, err := config.FromEnv()
	if err == nil && cfg.Lang != "" {
		i18n.SetDefault(cfg.Lang)
	}
	return cfg, err
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	// Время не пишем: его добавляет journald.
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Attr{}
		}
		return a
	}}))
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	envFile := fs.String("env-file", "", i18n.S("cli.flag.env_file_manual"))
	_ = fs.Parse(args)

	cfg, err := loadConfig(*envFile)
	if err != nil {
		return err
	}
	if err := cfg.ValidateSecurity(); err != nil {
		return err
	}
	if cfg.AuthPasswordHash != "" && !web.ValidHash(cfg.AuthPasswordHash) {
		return i18n.Errorf("err.bad_hash")
	}
	if !cfg.IsLoopback() && len(cfg.AllowedHosts) == 0 {
		return i18n.Errorf("err.need_allowed_hosts")
	}
	log := newLogger(cfg.LogLevel)
	if runtime.GOOS != "linux" {
		log.Warn(i18n.S("log.not_linux"))
	}
	if os.Geteuid() != 0 {
		log.Warn(i18n.S("log.not_root"))
	}
	detCfg, err := cfg.DetectConfig()
	if err != nil {
		return err
	}
	for _, w := range detect.WeakAllowRules(detCfg.Allow) {
		log.Warn(i18n.S("log.weak_allow"), "rule", w)
	}
	hist, err := history.Open(history.Options{Dir: cfg.DataDir, Retention: cfg.Retention, MaxEventsBytes: int64(cfg.EventsMaxMB) << 20,
		CPUThreshold: cfg.CPUThreshold, MemThreshold: cfg.MemThreshold})
	if err != nil {
		return err
	}
	pfs := procfs.New(cfg.ProcRoot, cfg.HostRoot)
	pfs.MaxFiles = cfg.MaxFiles
	sc := scanner.New(scanner.Options{FS: pfs, Detect: detCfg, History: hist, Interval: cfg.ScanInterval, Logger: log, LogDays: cfg.LogDays})

	// Без пароля панель только для LocalUIDs: владельца подключения служба
	// определяет по /proc/net/tcp (см. web.Options.CheckPeer).
	noAuth := cfg.AuthPasswordHash == ""
	opts := web.Options{Scanner: sc, Logger: log, Version: version, ListenAddr: cfg.ListenAddr, PasswordHash: cfg.AuthPasswordHash,
		SessionTTL: cfg.SessionTTL, SecureCookie: cfg.TLSEnabled() || cfg.TrustProxyTLS, TrustProxy: cfg.TrustProxyTLS, AllowedHosts: cfg.AllowedHosts,
		CheckPeer: noAuth, LocalUIDs: cfg.LocalUIDs, Lang: cfg.Lang}
	ar := auditRunner(cfg, hist, log)
	if ar != nil {
		opts.Audit = ar // интерфейс: nil-указатель сюда не попадает
	}
	srv := web.New(opts)
	var connCtx func(context.Context, net.Conn) context.Context
	if noAuth {
		connCtx = web.PeerContext(pfs.SocketOwner)
	}
	log.Info(i18n.S("log.start"), "version", version, "listen", cfg.ListenAddr, "interval", cfg.ScanInterval.String(), "data", cfg.DataDir,
		"auth", !noAuth, "local_uids", fmt.Sprint(cfg.LocalUIDs), "tls", cfg.TLSEnabled(), "allowlist_rules", len(detCfg.Allow),
		"audit", cfg.AuditEnabled, "audit_interval", cfg.AuditInterval.String())
	var bg []func(context.Context)
	if ar != nil {
		bg = append(bg, ar.Run)
	}
	return run(sc, srv, srv.LocalHandler(), connCtx, cfg, log, func() { _ = hist.Flush(time.Now()) }, bg...)
}

// auditRunner создаёт фоновый аудит настроек службы (nil, если он
// выключен через SSG_AUDIT_ENABLED=false).
func auditRunner(cfg config.Config, hist *history.Store, log *slog.Logger) *audit.Runner {
	if !cfg.AuditEnabled {
		return nil
	}
	return audit.NewRunner(audit.RunnerOptions{HostRoot: cfg.HostRoot, Interval: cfg.AuditInterval, StateDir: cfg.DataDir,
		Record: hist.RecordAudit, Logger: log})
}

// run запускает сканер и HTTP-сервер и корректно останавливает их по
// SIGINT/SIGTERM.
// connCtx (может быть nil) — http.Server.ConnContext для TCP-панели.
// bg — фоновые задачи (аудит): получают тот же контекст, при остановке
// их завершения ждём до 5 секунд, чтобы не оборвать запись состояния.
func run(sc *scanner.Scanner, handler, local http.Handler, connCtx func(context.Context, net.Conn) context.Context, cfg config.Config, log *slog.Logger, onStop func(), bg ...func(context.Context)) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return i18n.Errorf("err.listen", cfg.ListenAddr, err)
	}
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		ConnContext:       connCtx,
	}
	if cfg.TLSEnabled() {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	go sc.Run(ctx)
	var wg sync.WaitGroup
	for _, f := range bg {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(ctx)
		}()
	}
	var localSrv *http.Server
	if local != nil && cfg.SocketPath != "" {
		if lnU, err := listenSocket(cfg.SocketPath); err != nil {
			log.Warn(i18n.S("log.socket_failed"), "path", cfg.SocketPath, "err", err)
		} else {
			localSrv = &http.Server{Handler: local, ReadHeaderTimeout: 10 * time.Second}
			go func() { _ = localSrv.Serve(lnU) }()
			defer os.Remove(cfg.SocketPath)
			log.Info(i18n.S("log.socket"), "path", cfg.SocketPath)
		}
	}
	errCh := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLSEnabled() {
			err = httpSrv.ServeTLS(ln, cfg.TLSCert, cfg.TLSKey)
		} else {
			err = httpSrv.Serve(ln)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	scheme := "http"
	if cfg.TLSEnabled() {
		scheme = "https"
	}
	log.Info(i18n.S("log.panel_url"), "url", scheme+"://"+cfg.ListenAddr+"/")

	select {
	case <-ctx.Done():
		log.Info(i18n.S("log.stop_signal"))
	case err := <-errCh:
		if err != nil {
			return err
		}
	}
	stop() // при ошибке HTTP-сервера контекст ещё не отменён
	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shCtx)
	if localSrv != nil {
		_ = localSrv.Shutdown(shCtx)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-shCtx.Done():
	}
	if onStop != nil {
		onStop()
	}
	return nil
}

// listenSocket открывает Unix-сокет с правами 0600 в каталоге 0700.
// Права файла — единственная авторизация для запросов через сокет,
// поэтому доступ имеет только root (владелец службы).
func listenSocket(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm()&0o077 != 0 {
		return nil, i18n.Errorf("err.dir_mode", dir)
	}
	if _, err := os.Lstat(path); err == nil {
		// Сокет остался от прошлого запуска? Если на нём кто-то отвечает —
		// работает другой экземпляр, его не трогаем.
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, i18n.Errorf("err.socket_busy")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// cmdTUI запускает терминальный интерфейс. По умолчанию он берёт данные
// у запущенной службы через Unix-сокет (полная история); если служба не
// запущена — сканирует сам, и история хранится только в памяти.
func cmdTUI(args []string) error {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	envFile := fs.String("env-file", "", i18n.S("cli.flag.env_file_tui"))
	socket := fs.String("socket", "", i18n.S("cli.flag.socket", config.DefaultSocketPath))
	local := fs.Bool("local", false, i18n.S("cli.flag.local"))
	interval := fs.Duration("interval", 5*time.Second, i18n.S("cli.flag.interval_local"))
	refresh := fs.Duration("refresh", 5*time.Second, i18n.S("cli.flag.refresh"))
	_ = fs.Parse(args)

	if !tui.IsTerminal() {
		return i18n.Errorf("err.tui_needs_terminal")
	}
	if *envFile == "" {
		if _, err := os.Stat("/opt/serversecuritygo/.env"); err == nil {
			*envFile = "/opt/serversecuritygo/.env"
		}
	}
	if *envFile != "" {
		if err := config.LoadEnvFile(*envFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			// Нет прав на .env (запуск не от root) — работаем со значениями по умолчанию.
			if !errors.Is(err, os.ErrPermission) {
				return i18n.Errorf("err.env_file", err)
			}
		}
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if cfg.Lang != "" {
		i18n.SetDefault(cfg.Lang)
	}
	if *socket == "" {
		*socket = cfg.SocketPath
	}

	var src tui.Source
	note := i18n.T("tui.source_local")
	if !*local && *socket != "" {
		if rs, err := tui.DialSocket(*socket); err == nil {
			src = rs
		} else {
			note = i18n.T("tui.source_nosvc")
		}
	}
	if src == nil {
		ls, err := newLocalTUISource(cfg, *interval, note)
		if err != nil {
			return err
		}
		src = ls
	}
	defer src.Close()
	return tui.New(tui.Options{Source: src, Refresh: *refresh}).Run()
}

// newLocalTUISource создаёт локальный сканер для интерфейса. Журнал
// отключён (он испортил бы экран), история — только в памяти, чтобы не
// мешать файлам истории службы.
func newLocalTUISource(cfg config.Config, interval time.Duration, note i18n.Msg) (*tui.LocalSource, error) {
	detCfg, err := cfg.DetectConfig()
	if err != nil {
		return nil, err
	}
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	hist, _ := history.Open(history.Options{CPUThreshold: cfg.CPUThreshold, MemThreshold: cfg.MemThreshold})
	pfs := procfs.New(cfg.ProcRoot, cfg.HostRoot)
	pfs.MaxFiles = cfg.MaxFiles
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	sc := scanner.New(scanner.Options{FS: pfs, Detect: detCfg, History: hist, Interval: interval, Logger: quiet, LogDays: cfg.LogDays})
	// Аудит без каталога данных: базовая линия только на время сеанса,
	// файлы службы не трогаются.
	var ar *audit.Runner
	if cfg.AuditEnabled {
		ar = audit.NewRunner(audit.RunnerOptions{HostRoot: cfg.HostRoot, Interval: cfg.AuditInterval, Record: hist.RecordAudit, Logger: quiet})
	}
	return tui.NewLocalSource(sc, ar, version, false, note)
}

// cmdScan — разовое сканирование процессов с отчётом в консоль или файл.
// Код выхода зависит от находок (--fail-on), см. report.ExitCode; ошибки
// возвращаются с кодом 2 (report.AsRunError).
func cmdScan(args []string) error {
	code, err := runScan(args)
	if err != nil {
		return report.AsRunError(err)
	}
	return exitCode(code)
}

func runScan(args []string) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	envFile := fs.String("env-file", "", i18n.S("cli.flag.env_file"))
	format := fs.String("format", "text", i18n.S("cli.flag.format"))
	output := fs.String("output", "", i18n.S("cli.flag.output"))
	failOn := fs.String("fail-on", "HIGH", i18n.S("cli.flag.fail_on"))
	minRisk := fs.String("min-risk", "LOW", i18n.S("cli.flag.min_risk"))
	sample := fs.Duration("sample", 0, i18n.S("cli.flag.sample"))
	_ = fs.Parse(args)

	min, ok := model.ParseRisk(*minRisk)
	if !ok {
		return 0, i18n.Errorf("err.unknown_level", strconv.Quote(*minRisk))
	}
	f, err := report.ParseFormat(*format)
	if err != nil {
		return 0, err
	}
	fail, err := report.ParseFailOn(*failOn)
	if err != nil {
		return 0, err
	}
	cfg, err := loadConfig(*envFile)
	if err != nil {
		return 0, err
	}
	detCfg, err := cfg.DetectConfig()
	if err != nil {
		return 0, err
	}
	// Разовый запуск не трогает историю службы — только память.
	hist, _ := history.Open(history.Options{CPUThreshold: cfg.CPUThreshold, MemThreshold: cfg.MemThreshold})
	pfs := procfs.New(cfg.ProcRoot, cfg.HostRoot)
	pfs.MaxFiles = cfg.MaxFiles
	sc := scanner.New(scanner.Options{FS: pfs, Detect: detCfg, History: hist, Interval: cfg.ScanInterval, Logger: newLogger("error"), LogDays: cfg.LogDays})
	snap, err := sc.ScanOnce()
	if err != nil {
		return 0, err
	}
	if *sample > 0 {
		time.Sleep(*sample)
		if snap, err = sc.ScanOnce(); err != nil {
			return 0, err
		}
	}
	rep := report.NewScan(snap, min, version)
	if err := report.Write(*output, func(w io.Writer) error { return rep.Render(w, f, i18n.Default()) }); err != nil {
		return 0, err
	}
	return rep.ExitCode(fail), nil
}

// cmdAudit — разовая проверка настроек безопасности (SSH, учётные
// записи, sudo). Без службы проверки изменений (новые пользователи,
// правка sudoers) недоступны — сравнивать не с чем.
func cmdAudit(args []string) error {
	code, err := runAudit(args)
	if err != nil {
		return report.AsRunError(err)
	}
	return exitCode(code)
}

func runAudit(args []string) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	envFile := fs.String("env-file", "", i18n.S("cli.flag.env_file"))
	format := fs.String("format", "text", i18n.S("cli.flag.format"))
	output := fs.String("output", "", i18n.S("cli.flag.output"))
	failOn := fs.String("fail-on", "HIGH", i18n.S("cli.flag.fail_on"))
	all := fs.Bool("all", false, i18n.S("cli.flag.all_checks"))
	_ = fs.Parse(args)
	f, err := report.ParseFormat(*format)
	if err != nil {
		return 0, err
	}
	fail, err := report.ParseFailOn(*failOn)
	if err != nil {
		return 0, err
	}
	cfg, err := loadConfig(*envFile)
	if err != nil {
		return 0, err
	}
	checks, _ := audit.Run(audit.Options{HostRoot: cfg.HostRoot})
	host, _ := os.Hostname()
	rep := &report.Audit{View: view.BuildAudit(true, false, 0, &model.AuditReport{Time: time.Now(), Checks: checks}), Hostname: host, Version: version, All: *all}
	if err := report.Write(*output, func(w io.Writer) error { return rep.Render(w, f, i18n.Default()) }); err != nil {
		return 0, err
	}
	return rep.ExitCode(fail), nil
}

// exitStatus — команда завершилась успешно, но с особым кодом выхода
// (scan и audit: 1 — есть находки, 3 — проверка неполная).
type exitStatus int

func (e exitStatus) Error() string { return "exit status " + strconv.Itoa(int(e)) }

// exitCode — nil для кода 0, иначе exitStatus.
func exitCode(code int) error {
	if code == 0 {
		return nil
	}
	return exitStatus(code)
}

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8090", i18n.S("cli.flag.listen"))
	interval := fs.Duration("interval", 5*time.Second, i18n.S("cli.flag.interval"))
	useTUI := fs.Bool("tui", false, i18n.S("cli.flag.demo_tui"))
	_ = fs.Parse(args)

	cfg := config.Default()
	cfg.ListenAddr = *listen
	cfg.ScanInterval = *interval
	if !cfg.IsLoopback() {
		return i18n.Errorf("err.demo_loopback")
	}
	dir, err := os.MkdirTemp("", "ssg-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	tree := fakeproc.Demo(time.Now())
	procRoot, hostRoot, err := tree.Write(dir)
	if err != nil {
		return err
	}
	log := newLogger("info")
	if *useTUI {
		log = slog.New(slog.NewTextHandler(io.Discard, nil)) // журнал испортил бы экран
	}
	det, _ := config.Default().DetectConfig()
	det.Allow = nil
	det.CPUSustainScan = 3 // в демо признак длительной нагрузки появляется быстрее
	hist, _ := history.Open(history.Options{CPUThreshold: cfg.CPUThreshold, MemThreshold: cfg.MemThreshold})
	anim := fakeproc.NewAnimator(tree, procRoot)
	sc := scanner.New(scanner.Options{FS: fakeproc.NewFS(procRoot, hostRoot), Detect: det, History: hist, Interval: cfg.ScanInterval, Logger: log,
		BeforeScan: anim.Step, Hostname: "demo-server", Demo: true})
	// Демо-файлы принадлежат текущему пользователю: он и считается root.
	ar := audit.NewRunner(audit.RunnerOptions{HostRoot: hostRoot, RootUID: os.Getuid(), Interval: time.Minute, Record: hist.RecordAudit, Logger: log})
	if *useTUI {
		if !tui.IsTerminal() {
			return i18n.Errorf("err.demo_tui_terminal")
		}
		ls, err := tui.NewLocalSource(sc, ar, version+" (demo)", true, i18n.T("tui.source_demo"))
		if err != nil {
			return err
		}
		defer ls.Close()
		return tui.New(tui.Options{Source: ls, Refresh: *interval}).Run()
	}
	srv := web.New(web.Options{Scanner: sc, Logger: log, Version: version + " (demo)", ListenAddr: cfg.ListenAddr, Demo: true, Audit: ar})
	log.Info(i18n.S("log.demo"), "dir", dir)
	return run(sc, srv, nil, nil, cfg, log, nil, ar.Run)
}

func cmdHashPassword() error {
	fmt.Fprint(os.Stderr, i18n.S("cli.pw.prompt"))
	pw, err := readSecret()
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "\n"+i18n.S("cli.pw.repeat"))
	pw2, err := readSecret()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr)
	if pw != pw2 {
		return i18n.Errorf("err.pw_mismatch")
	}
	h, err := web.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, i18n.S("cli.pw.add_line"))
	fmt.Printf("SSG_AUTH_PASSWORD_HASH=%s\n", h)
	return nil
}

// stdinReader — общий буфер stdin: при вводе из канала оба пароля
// приходят одним блоком, и второй вызов должен читать из того же буфера.
var stdinReader = bufio.NewReader(os.Stdin)

// readSecret читает строку без эха, если stdin — терминал (через stty,
// чтобы не тянуть внешние зависимости). Из канала читает как есть.
func readSecret() (string, error) {
	fi, _ := os.Stdin.Stat()
	tty := fi != nil && fi.Mode()&os.ModeCharDevice != 0
	if tty {
		c := exec.Command("stty", "-echo")
		c.Stdin = os.Stdin
		if c.Run() == nil {
			defer func() {
				r := exec.Command("stty", "echo")
				r.Stdin = os.Stdin
				_ = r.Run()
			}()
		}
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

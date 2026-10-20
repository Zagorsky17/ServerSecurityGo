// Команда serversecuritygo — мониторинг процессов Linux-сервера.
//
// Подкоманды:
//
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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/config"
	"github.com/Zagorsky17/ServerSecurityGo/internal/fakeproc"
	"github.com/Zagorsky17/ServerSecurityGo/internal/history"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/web"
)

// version подставляется при сборке: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `ServerSecurityGo %s — мониторинг и анализ процессов Linux-сервера

Использование:
  serversecuritygo serve [--env-file PATH]          запустить сканер и веб-панель
  serversecuritygo scan [--format table|json] [--min-risk LOW] [--env-file PATH]
  serversecuritygo demo [--listen 127.0.0.1:8090]   панель на демонстрационных данных
  serversecuritygo hash-password                    хеш пароля для SSG_AUTH_PASSWORD_HASH
  serversecuritygo version

Настройки задаются переменными окружения SSG_* (см. .env.example).
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "scan":
		err = cmdScan(os.Args[2:])
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
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

// loadConfig читает --env-file (если задан) и переменные окружения.
func loadConfig(envFile string) (config.Config, error) {
	if envFile != "" {
		if err := config.LoadEnvFile(envFile); err != nil {
			return config.Config{}, fmt.Errorf("файл настроек: %w", err)
		}
	}
	return config.FromEnv()
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
	envFile := fs.String("env-file", "", "файл с переменными SSG_* (для ручного запуска)")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*envFile)
	if err != nil {
		return err
	}
	if err := cfg.ValidateSecurity(); err != nil {
		return err
	}
	if cfg.AuthPasswordHash != "" && !web.ValidHash(cfg.AuthPasswordHash) {
		return errors.New("SSG_AUTH_PASSWORD_HASH имеет неверный формат; получите его командой serversecuritygo hash-password")
	}
	if !cfg.IsLoopback() && len(cfg.AllowedHosts) == 0 {
		return errors.New("для доступа из сети задайте SSG_ALLOWED_HOSTS — доменное имя или IP, по которому открывается панель (защита от DNS rebinding)")
	}
	log := newLogger(cfg.LogLevel)
	if runtime.GOOS != "linux" {
		log.Warn("приложение рассчитано на Linux; на этой ОС нет /proc — используйте режим demo")
	}
	if os.Geteuid() != 0 {
		log.Warn("запуск не от root: данные о процессах других пользователей будут неполными")
	}
	detCfg, err := cfg.DetectConfig()
	if err != nil {
		return err
	}
	hist, err := history.Open(history.Options{Dir: cfg.DataDir, Retention: cfg.Retention, MaxEventsBytes: int64(cfg.EventsMaxMB) << 20,
		CPUThreshold: cfg.CPUThreshold, MemThreshold: cfg.MemThreshold})
	if err != nil {
		return err
	}
	pfs := procfs.New(cfg.ProcRoot, cfg.HostRoot)
	pfs.MaxFiles = cfg.MaxFiles
	sc := scanner.New(scanner.Options{FS: pfs, Detect: detCfg, History: hist, Interval: cfg.ScanInterval, Logger: log})

	srv := web.New(web.Options{Scanner: sc, Logger: log, Version: version, ListenAddr: cfg.ListenAddr, PasswordHash: cfg.AuthPasswordHash,
		SessionTTL: cfg.SessionTTL, SecureCookie: cfg.TLSEnabled() || cfg.TrustProxyTLS, AllowedHosts: cfg.AllowedHosts})
	log.Info("запуск", "version", version, "listen", cfg.ListenAddr, "interval", cfg.ScanInterval.String(), "data", cfg.DataDir,
		"auth", cfg.AuthPasswordHash != "", "tls", cfg.TLSEnabled(), "allowlist_rules", len(detCfg.Allow))
	return run(sc, srv, cfg, log, func() { _ = hist.Flush(time.Now()) })
}

// run запускает сканер и HTTP-сервер и корректно останавливает их по
// SIGINT/SIGTERM.
func run(sc *scanner.Scanner, handler http.Handler, cfg config.Config, log *slog.Logger, onStop func()) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("не удалось открыть %s: %w", cfg.ListenAddr, err)
	}
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if cfg.TLSEnabled() {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	go sc.Run(ctx)
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
	log.Info("веб-панель доступна", "url", scheme+"://"+cfg.ListenAddr+"/")

	select {
	case <-ctx.Done():
		log.Info("остановка по сигналу")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}
	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shCtx)
	if onStop != nil {
		onStop()
	}
	return nil
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	envFile := fs.String("env-file", "", "файл с переменными SSG_*")
	format := fs.String("format", "table", "формат вывода: table или json")
	minRisk := fs.String("min-risk", "LOW", "минимальный уровень для вывода: INFO, LOW, MEDIUM, HIGH, CRITICAL")
	sample := fs.Duration("sample", 0, "сделать два замера с этим интервалом для точного CPU% (например, 2s)")
	_ = fs.Parse(args)

	min, ok := model.ParseRisk(*minRisk)
	if !ok {
		return fmt.Errorf("неизвестный уровень %q", *minRisk)
	}
	cfg, err := loadConfig(*envFile)
	if err != nil {
		return err
	}
	detCfg, err := cfg.DetectConfig()
	if err != nil {
		return err
	}
	// Разовый запуск не трогает историю службы — только память.
	hist, _ := history.Open(history.Options{CPUThreshold: cfg.CPUThreshold, MemThreshold: cfg.MemThreshold})
	pfs := procfs.New(cfg.ProcRoot, cfg.HostRoot)
	pfs.MaxFiles = cfg.MaxFiles
	sc := scanner.New(scanner.Options{FS: pfs, Detect: detCfg, History: hist, Interval: cfg.ScanInterval, Logger: newLogger("error")})
	snap, err := sc.ScanOnce()
	if err != nil {
		return err
	}
	if *sample > 0 {
		time.Sleep(*sample)
		if snap, err = sc.ScanOnce(); err != nil {
			return err
		}
	}

	var procs []*model.Process
	for _, p := range snap.Processes {
		if p.Risk >= min {
			procs = append(procs, p)
		}
	}
	// Сортировка: сначала самые рискованные.
	sortByRisk(procs)
	var sys []model.SystemFinding
	for _, f := range snap.System {
		if f.Risk >= min {
			sys = append(sys, f)
		}
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"time": snap.Time, "host": snap.Host, "stats": snap.Stats, "warnings": snap.Warnings, "processes": procs, "system": sys})
	}

	fmt.Printf("Хост: %s, %s, ядро %s. Процессов: %d, сокетов: %d, сканирование %s\n",
		snap.Host.Hostname, snap.Host.OS, snap.Host.Kernel, snap.Stats.Total, snap.Stats.Sockets, snap.Duration.Round(time.Millisecond))
	for _, w := range snap.Warnings {
		fmt.Println("! " + w)
	}
	fmt.Printf("По уровням: CRITICAL %d, HIGH %d, MEDIUM %d, LOW %d, INFO %d\n\n",
		snap.Stats.ByRisk["CRITICAL"], snap.Stats.ByRisk["HIGH"], snap.Stats.ByRisk["MEDIUM"], snap.Stats.ByRisk["LOW"], snap.Stats.ByRisk["INFO"])
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "РИСК\tБАЛЛЫ\tPID\tПОЛЬЗОВАТЕЛЬ\tИМЯ\tПУТЬ\tПРИЗНАКИ")
	for _, p := range procs {
		var titles []string
		for _, f := range p.Findings {
			if f.Category != model.CatInfo && !f.Suppressed {
				titles = append(titles, f.Title)
			}
		}
		exe := p.Exe
		if p.ExeDeleted {
			exe += " (удалён)"
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t%s\n", p.Risk, p.Score, p.PID, p.User, p.Name, exe, strings.Join(titles, "; "))
	}
	tw.Flush()
	if len(procs) == 0 {
		fmt.Printf("Процессов с уровнем %s и выше нет.\n", min)
	}
	if len(sys) > 0 {
		fmt.Println("\nСистемные проверки:")
		for _, f := range sys {
			fmt.Printf("  [%s] %s — %s\n", f.Risk, f.Title, f.Path)
			for _, e := range f.Evidence {
				fmt.Println("      " + e)
			}
		}
	}
	fmt.Println("\nОценка основана на косвенных признаках и не является доказательством компрометации. Подробности: --format json или веб-панель.")
	return nil
}

func sortByRisk(procs []*model.Process) {
	sort.SliceStable(procs, func(i, j int) bool {
		if procs[i].Risk != procs[j].Risk {
			return procs[i].Risk > procs[j].Risk
		}
		return procs[i].Score > procs[j].Score
	})
}

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8090", "адрес веб-панели (только loopback)")
	interval := fs.Duration("interval", 5*time.Second, "период сканирования")
	_ = fs.Parse(args)

	cfg := config.Default()
	cfg.ListenAddr = *listen
	cfg.ScanInterval = *interval
	if !cfg.IsLoopback() {
		return errors.New("демо-режим работает только на 127.0.0.1")
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
	det, _ := config.Default().DetectConfig()
	det.Allow = nil
	det.CPUSustainScan = 3 // в демо признак длительной нагрузки появляется быстрее
	hist, _ := history.Open(history.Options{CPUThreshold: cfg.CPUThreshold, MemThreshold: cfg.MemThreshold})
	anim := fakeproc.NewAnimator(tree, procRoot)
	sc := scanner.New(scanner.Options{FS: fakeproc.NewFS(procRoot, hostRoot), Detect: det, History: hist, Interval: cfg.ScanInterval, Logger: log,
		BeforeScan: anim.Step, Hostname: "demo-server", Demo: true})
	srv := web.New(web.Options{Scanner: sc, Logger: log, Version: version + " (демо)", ListenAddr: cfg.ListenAddr, Demo: true})
	log.Info("демо-режим: данные вымышленные", "dir", dir)
	return run(sc, srv, cfg, log, nil)
}

func cmdHashPassword() error {
	fmt.Fprint(os.Stderr, "Пароль (не короче 12 символов): ")
	pw, err := readSecret()
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "\nПовторите пароль: ")
	pw2, err := readSecret()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr)
	if pw != pw2 {
		return errors.New("пароли не совпадают")
	}
	h, err := web.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Добавьте строку в /opt/serversecuritygo/.env:")
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

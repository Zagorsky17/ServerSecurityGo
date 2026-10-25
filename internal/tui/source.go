package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/audit"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

// Data — всё, что нужно интерфейсу для одного кадра.
type Data struct {
	Status  view.Status
	Procs   []view.Summary
	Sockets []model.Socket
	Events  []model.Event // новые первыми
	System  []model.SystemFinding
	// Exposure — открытые порты; nil, если служба старой версии без
	// /api/exposure.
	Exposure *model.ExposureReport
	// Audit — настройки безопасности; nil, если служба старой версии без
	// /api/audit.
	Audit *view.AuditView
}

// Source — откуда интерфейс берёт данные: из запущенной службы (через
// Unix-сокет) или из собственного сканера (служба не запущена, демо).
type Source interface {
	Fetch() (*Data, error)
	Detail(key string) (*view.Detail, error)
	Rescan() error
	// RunAudit — «Проверить сейчас» для настроек безопасности.
	RunAudit() error
	// Describe — короткое описание источника для строки состояния.
	Describe() i18n.Msg
	Close()
}

// ---------------------------------------------------------------------
// Локальный источник: собственный сканер в этом же процессе
// ---------------------------------------------------------------------

// LocalSource сканирует процессы сам. История хранится только в памяти
// и живёт, пока открыт интерфейс: файлы истории службы не трогаются,
// чтобы не мешать ей.
type LocalSource struct {
	sc      *scanner.Scanner
	audit   *audit.Runner // nil — аудит выключен
	cancel  context.CancelFunc
	version string
	demo    bool
	note    i18n.Msg
}

// NewLocalSource запускает сканер в фоне и ждёт первого снимка. Аудит
// (ar может быть nil) выполняется сразу и затем только по клавише r: он
// быстрый, а отдельная горутина интерфейсу не нужна.
func NewLocalSource(sc *scanner.Scanner, ar *audit.Runner, version string, demo bool, note i18n.Msg) (*LocalSource, error) {
	if _, err := sc.ScanOnce(); err != nil {
		return nil, err
	}
	if ar != nil {
		ar.RunOnce()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Первый снимок уже есть: ждём интервал, затем Run сканирует сразу
		// и дальше по таймеру.
		select {
		case <-ctx.Done():
			return
		case <-time.After(sc.Interval()):
		}
		sc.Run(ctx)
	}()
	return &LocalSource{sc: sc, audit: ar, cancel: cancel, version: version, demo: demo, note: note}, nil
}

func (l *LocalSource) Fetch() (*Data, error) {
	snap := l.sc.Snapshot()
	if snap == nil {
		return nil, i18n.Errorf("err.first_scan_running")
	}
	st := view.BuildStatus(view.Status{Version: l.version, Demo: l.demo, Interval: l.sc.Interval().Seconds()}, snap)
	ev := l.sc.History().Events(2000)
	slices.Reverse(ev)
	av := view.BuildAudit(false, false, 0, nil)
	if l.audit != nil {
		av = view.BuildAudit(true, l.audit.Running(), l.audit.Interval(), l.audit.Report())
	}
	st.Audit = av.Brief()
	return &Data{Status: st, Procs: view.SummarizeAll(snap), Sockets: snap.Sockets, Events: ev, System: view.SortedSystem(snap), Exposure: view.Exposure(snap), Audit: &av}, nil
}

func (l *LocalSource) RunAudit() error {
	if l.audit == nil {
		return i18n.Errorf("web.err.audit_disabled")
	}
	l.audit.RunOnce()
	return nil
}

func (l *LocalSource) Detail(key string) (*view.Detail, error) {
	snap := l.sc.Snapshot()
	if snap == nil {
		return nil, i18n.Errorf("err.no_data")
	}
	d, ok := view.BuildDetail(snap, l.sc.History(), key)
	if !ok {
		return nil, i18n.Errorf("err.process_not_found")
	}
	return &d, nil
}

func (l *LocalSource) Rescan() error {
	_, err := l.sc.ScanOnce()
	return err
}

func (l *LocalSource) Describe() i18n.Msg { return l.note }

func (l *LocalSource) Close() { l.cancel() }

// ---------------------------------------------------------------------
// Источник-служба: API запущенной службы через локальный Unix-сокет
// ---------------------------------------------------------------------

// RemoteSource читает данные у службы. Так интерфейс видит полную
// историю (с момента установки), а не только текущий сеанс.
type RemoteSource struct {
	path   string
	client *http.Client
	// audit — последний полученный /api/audit: он меняется раз в час или
	// по «Проверить сейчас», поэтому заново запрашивается, только когда
	// сводка в /api/status говорит, что результат другой.
	audit *view.AuditView
}

// DialSocket подключается к Unix-сокету службы и проверяет, что она
// отвечает. Ошибка означает, что служба не запущена (или старой версии
// без сокета) — тогда используется локальный сканер.
func DialSocket(path string) (*RemoteSource, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		MaxIdleConns: 2,
	}
	r := &RemoteSource{path: path, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}}
	var st view.Status
	if err := r.get("/api/status", &st); err != nil {
		return nil, err
	}
	return r, nil
}

// errNotFound — у службы нет такого метода API (старая версия).
var errNotFound = errors.New("not found")

// get выполняет GET и декодирует JSON. Хост в URL условный: соединение
// всё равно идёт в Unix-сокет.
func (r *RemoteSource) get(path string, v any) error {
	resp, err := r.client.Get("http://serversecuritygo" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && !strings.HasPrefix(path, "/api/process/") {
		return errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return errors.New(e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (r *RemoteSource) Fetch() (*Data, error) {
	d := &Data{}
	if err := r.get("/api/status", &d.Status); err != nil {
		return nil, err
	}
	if !d.Status.Ready {
		return nil, i18n.Errorf("err.service_first_scan")
	}
	var procs struct {
		Processes []view.Summary `json:"processes"`
	}
	var conns struct {
		Sockets []model.Socket `json:"sockets"`
	}
	var evs struct {
		Events []model.Event `json:"events"`
	}
	var sys struct {
		Findings []model.SystemFinding `json:"findings"`
	}
	for _, q := range []struct {
		path string
		v    any
	}{{"/api/processes", &procs}, {"/api/connections", &conns}, {"/api/events?limit=2000", &evs}, {"/api/system", &sys}} {
		if err := r.get(q.path, q.v); err != nil {
			return nil, fmt.Errorf("%s: %w", q.path, err)
		}
	}
	d.Procs, d.Sockets, d.Events, d.System = procs.Processes, conns.Sockets, evs.Events, sys.Findings
	// Открытые порты появились в новой версии: служба, обновлённая
	// позже терминала, отвечает 404 — тогда панель просто пустая.
	var exp struct {
		Exposure *model.ExposureReport `json:"exposure"`
	}
	if err := r.get("/api/exposure", &exp); err != nil && !errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("/api/exposure: %w", err)
	}
	d.Exposure = exp.Exposure
	if c, b := r.audit, d.Status.Audit; c != nil && c.Enabled == b.Enabled && c.Running == b.Running && c.Time.Equal(b.Time) {
		d.Audit = c
		return d, nil
	}
	var av view.AuditView
	if err := r.get("/api/audit", &av); err == nil {
		d.Audit, r.audit = &av, &av
	} else if !errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("/api/audit: %w", err)
	}
	return d, nil
}

func (r *RemoteSource) Detail(key string) (*view.Detail, error) {
	var d view.Detail
	if err := r.get("/api/process/"+url.PathEscape(key), &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *RemoteSource) Rescan() error {
	resp, err := r.client.Post("http://serversecuritygo/api/rescan", "application/json", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return errors.New(resp.Status)
	}
	return nil
}

func (r *RemoteSource) RunAudit() error {
	resp, err := r.client.Post("http://serversecuritygo/api/audit/run", "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return errors.New(e.Error)
	}
	return nil
}

func (r *RemoteSource) Describe() i18n.Msg { return i18n.T("tui.source_service", r.path) }

func (r *RemoteSource) Close() { r.client.CloseIdleConnections() }

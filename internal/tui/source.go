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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/audit"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/investigate"
	"github.com/Zagorsky17/ServerSecurityGo/internal/metrics"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/scanner"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

// Data — всё, что нужно интерфейсу для одного кадра.
type Data struct {
	Learning *model.LearningReport
	Changes  *model.ChangesReport
	Auth     *model.AuthReport
	Timeline []model.TimelineEvent
	Status   view.Status
	Procs    []view.Summary
	Sockets  []model.Socket
	Events   []model.Event // новые первыми
	System   []model.SystemFinding
	// Exposure — открытые порты; nil, если служба старой версии без
	// /api/exposure.
	Exposure *model.ExposureReport
	// Audit — настройки безопасности; nil, если служба старой версии без
	// /api/audit.
	Audit *view.AuditView
	// Fail2ban — состояние fail2ban; nil, если fail2ban не установлен или
	// служба старой версии без /api/fail2ban. Панель есть, только когда
	// Installed.
	Fail2ban *model.Fail2banReport
	UFW      *model.UFWReport
	// Metrics — метрики сервера за выбранное окно; nil — сбор выключен
	// или служба старой версии без /api/metrics.
	Metrics *metrics.View
	// Net — сетевая нагрузка; nil — наблюдение выключено или служба
	// старой версии без /api/netload.
	Net *view.NetLoadView
}

// Source — откуда интерфейс берёт данные: из запущенной службы (через
// Unix-сокет) или из собственного сканера (служба не запущена, демо).
type Source interface {
	Fetch() (*Data, error)
	Detail(key string) (*view.Detail, error)
	Rescan() error
	// RunAudit — «Проверить сейчас» для настроек безопасности.
	RunAudit() error
	// SetRange задаёт окно графиков метрик (metrics.Range*).
	SetRange(rng string)
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
	workers   sync.WaitGroup
	sc        *scanner.Scanner
	netOn     bool               // наблюдение за сетевой нагрузкой включено
	audit     *audit.Runner      // nil — аудит выключен
	met       *metrics.Collector // nil — метрики выключены
	rng       atomic.Value       // окно графиков (строка)
	auditDone chan struct{}
	cancel    context.CancelFunc
	version   string
	demo      bool
	note      i18n.Msg
}

// NewLocalSource запускает сканер в фоне и ждёт первого снимка. Аудит
// (ar может быть nil) выполняется сразу, затем по таймеру, запросу и обновлению инвентаря.
func NewLocalSource(sc *scanner.Scanner, ar *audit.Runner, mc *metrics.Collector, netOn bool, version string, demo bool, note i18n.Msg) (*LocalSource, error) {
	if _, err := sc.ScanOnce(); err != nil {
		return nil, err
	}
	if ar != nil {
		ar.RunOnce()
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &LocalSource{sc: sc, audit: ar, met: mc, netOn: netOn, cancel: cancel, version: version, demo: demo, note: note}
	if mc != nil {
		// Первый замер — сразу, чтобы в «Сводке» были значения; дальше
		// метрики снимает своя горутина: ряды нужны чаще, чем идёт
		// сканирование процессов.
		_, _ = mc.Collect(time.Now())
		l.workers.Add(1)
		go func() { defer l.workers.Done(); mc.Run(ctx) }()
	}
	l.workers.Add(1)
	go func() {
		defer l.workers.Done()
		// Первый снимок уже есть: ждём интервал, затем Run сканирует сразу
		// и дальше по таймеру.
		select {
		case <-ctx.Done():
			return
		case <-time.After(sc.Interval()):
		}
		sc.Run(ctx)
	}()
	if ar != nil {
		l.auditDone = make(chan struct{})
		go func() { defer close(l.auditDone); ar.Run(ctx) }()
	}
	l.rng.Store(metrics.RangeHour)
	return l, nil
}

// SetRange задаёт окно графиков метрик.
func (l *LocalSource) SetRange(rng string) { l.rng.Store(metrics.ValidRange(rng)) }

func (l *LocalSource) metricsView() *metrics.View {
	if l.met == nil {
		return nil
	}
	rng, _ := l.rng.Load().(string)
	v := l.met.View(rng)
	return &v
}

func (l *LocalSource) Fetch() (*Data, error) {
	snap := l.sc.Snapshot()
	if snap == nil {
		return nil, i18n.Errorf("err.first_scan_running")
	}
	st := view.BuildStatus(view.Status{Version: l.version, Demo: l.demo, Interval: l.sc.Interval().Seconds()}, snap)
	st.Stale = !l.sc.Healthy(time.Now())
	ev := l.sc.History().Events(2000)
	slices.Reverse(ev)
	av := view.BuildAudit(false, false, 0, nil)
	if l.audit != nil {
		av = view.BuildAudit(true, l.audit.Running(), l.audit.Interval(), l.audit.Report())
	}
	st.Audit = av.Brief()
	if l.met != nil {
		st.Metrics = l.met.Brief()
	}
	d := &Data{Learning: snap.Learning, Changes: l.sc.Changes(), Auth: snap.Auth, Status: st, Procs: view.SummarizeAll(snap), Sockets: snap.Sockets, Events: ev, System: view.SortedSystem(snap),
		UFW: snap.UFW, Exposure: view.Exposure(snap), Audit: &av, Metrics: l.metricsView()}
	if snap.Auth != nil || snap.Recent != nil {
		d.Timeline = investigate.Timeline(snap, ev, snap.Recent, time.Now().Add(-48*time.Hour))
	}
	if l.netOn {
		nv := view.NetLoad(snap.NetLoad, true)
		d.Net = &nv
	}
	if f := view.Fail2ban(snap); f.Installed {
		d.Fail2ban = f
	}
	return d, nil
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

func (l *LocalSource) Close() {
	l.cancel()
	l.workers.Wait()
	if l.auditDone != nil {
		<-l.auditDone
	}
}

// ---------------------------------------------------------------------
// Источник-служба: API запущенной службы через локальный Unix-сокет
// ---------------------------------------------------------------------

// RemoteSource читает данные у службы. Так интерфейс видит полную
// историю (с момента установки), а не только текущий сеанс.
type RemoteSource struct {
	path    string
	rng     atomic.Value // окно графиков метрик (строка)
	client  *http.Client
	system  cachedReport[systemReport]
	ufw     cachedReport[*model.UFWReport]
	changes cachedReport[*model.ChangesReport]
	audit   cachedReport[view.AuditView]
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
	r.rng.Store(metrics.RangeHour)
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
	resp, err := r.request(path, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (r *RemoteSource) request(path, etag string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, "http://serversecuritygo"+path, nil)
	if err != nil {
		return nil, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotModified {
		return resp, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && !strings.HasPrefix(path, "/api/process/") {
		return nil, errNotFound
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	if e.Error == "" {
		e.Error = resp.Status
	}
	return nil, errors.New(e.Error)
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
	for _, q := range []struct {
		path string
		v    any
	}{{"/api/processes", &procs}, {"/api/connections", &conns}, {"/api/events?limit=2000", &evs}} {
		if err := r.get(q.path, q.v); err != nil {
			return nil, fmt.Errorf("%s: %w", q.path, err)
		}
	}
	d.Procs, d.Sockets, d.Events = procs.Processes, conns.Sockets, evs.Events
	sys, err := fetchReport(r, "/api/system", &r.system)
	if err != nil {
		return nil, fmt.Errorf("/api/system: %w", err)
	}
	d.System = sys.Findings
	// Открытые порты появились в новой версии: служба, обновлённая
	// позже терминала, отвечает 404 — тогда панель просто пустая.
	var exp struct {
		Exposure *model.ExposureReport `json:"exposure"`
	}
	if err := r.get("/api/exposure", &exp); err != nil && !errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("/api/exposure: %w", err)
	}
	d.Exposure = exp.Exposure
	if d.UFW, err = fetchReport(r, "/api/ufw", &r.ufw); err != nil && !errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("/api/ufw: %w", err)
	}

	// fail2ban запрашивается, только если он установлен: так говорит сводка
	// в /api/status (старая служба сводки не присылает — раздела нет).
	if d.Status.Fail2ban != nil {
		var f model.Fail2banReport
		if err := r.get("/api/fail2ban", &f); err == nil && f.Installed {
			d.Fail2ban = &f
		} else if err != nil && !errors.Is(err, errNotFound) {
			return nil, fmt.Errorf("/api/fail2ban: %w", err)
		}
	}
	// Метрики запрашиваются, только если служба их собирает (сводка в
	// /api/status): иначе раздела нет.
	if d.Status.Metrics != nil {
		rng, _ := r.rng.Load().(string)
		var mv metrics.View
		if err := r.get("/api/metrics?range="+url.QueryEscape(rng), &mv); err == nil && mv.Enabled {
			d.Metrics = &mv
		} else if err != nil && !errors.Is(err, errNotFound) {
			return nil, fmt.Errorf("/api/metrics: %w", err)
		}
	}
	// Сетевая нагрузка запрашивается, только если служба наблюдает
	// (сводка в /api/status).
	if d.Status.Net != nil {
		var nv view.NetLoadView
		if err := r.get("/api/netload", &nv); err == nil && nv.Enabled {
			d.Net = &nv
		} else if err != nil && !errors.Is(err, errNotFound) {
			return nil, fmt.Errorf("/api/netload: %w", err)
		}
	}
	var auth struct {
		Report *model.AuthReport `json:"report"`
	}
	if err := r.get("/api/logins", &auth); err != nil && !errors.Is(err, errNotFound) {
		return nil, err
	}
	d.Auth = auth.Report
	var timeline struct {
		Events []model.TimelineEvent `json:"events"`
	}
	if err := r.get("/api/timeline", &timeline); err != nil && !errors.Is(err, errNotFound) {
		return nil, err
	}
	d.Timeline = timeline.Events
	if err := r.get("/api/learning", &d.Learning); err != nil && !errors.Is(err, errNotFound) {
		return nil, err
	}
	if d.Changes, err = fetchReport(r, "/api/changes", &r.changes); err != nil && !errors.Is(err, errNotFound) {
		return nil, err
	}
	av, err := fetchReport(r, "/api/audit", &r.audit)
	if err == nil {
		d.Audit = &av
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

// SetRange задаёт окно графиков метрик.
func (r *RemoteSource) SetRange(rng string) { r.rng.Store(metrics.ValidRange(rng)) }

func (r *RemoteSource) Describe() i18n.Msg { return i18n.T("tui.source_service", r.path) }

func (r *RemoteSource) Close() { r.client.CloseIdleConnections() }

package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

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
}

// Source — откуда интерфейс берёт данные: из запущенной службы (через
// Unix-сокет) или из собственного сканера (служба не запущена, демо).
type Source interface {
	Fetch() (*Data, error)
	Detail(key string) (*view.Detail, error)
	Rescan() error
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
	cancel  context.CancelFunc
	version string
	demo    bool
	note    i18n.Msg
}

// NewLocalSource запускает сканер в фоне и ждёт первого снимка.
func NewLocalSource(sc *scanner.Scanner, version string, demo bool, note i18n.Msg) (*LocalSource, error) {
	if _, err := sc.ScanOnce(); err != nil {
		return nil, err
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
	return &LocalSource{sc: sc, cancel: cancel, version: version, demo: demo, note: note}, nil
}

func (l *LocalSource) Fetch() (*Data, error) {
	snap := l.sc.Snapshot()
	if snap == nil {
		return nil, i18n.Errorf("err.first_scan_running")
	}
	st := view.BuildStatus(view.Status{Version: l.version, Demo: l.demo, Interval: l.sc.Interval().Seconds()}, snap)
	ev := l.sc.History().Events(2000)
	slices.Reverse(ev)
	return &Data{Status: st, Procs: view.SummarizeAll(snap), Sockets: snap.Sockets, Events: ev, System: view.SortedSystem(snap)}, nil
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

// get выполняет GET и декодирует JSON. Хост в URL условный: соединение
// всё равно идёт в Unix-сокет.
func (r *RemoteSource) get(path string, v any) error {
	resp, err := r.client.Get("http://serversecuritygo" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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

func (r *RemoteSource) Describe() i18n.Msg { return i18n.T("tui.source_service", r.path) }

func (r *RemoteSource) Close() { r.client.CloseIdleConnections() }

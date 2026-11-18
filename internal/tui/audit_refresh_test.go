package tui

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/audit"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

func TestLocalAuditRefreshAndSourceFreshness(t *testing.T) {
	sc := demoScanner(t)
	var inventory atomic.Pointer[model.FileInventory]
	updates := make(chan struct{}, 1)
	ar := audit.NewRunner(audit.RunnerOptions{HostRoot: t.TempDir(), Inventory: inventory.Load, InventoryUpdates: updates, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	src, err := NewLocalSource(sc, ar, nil, false, "test", false, i18n.L("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	a := New(Options{Source: src, Out: io.Discard, Lang: i18n.EN})
	a.w, a.h = 120, 40
	a.load()
	a.focusPanel(pAudit)
	if !strings.Contains(screen(a), "inventory not yet available") {
		t.Fatal("pending source hidden")
	}
	first := ar.Report()
	inventory.Store(&model.FileInventory{Time: time.Now(), Incomplete: true})
	updates <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for ar.Report() == first && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ar.Report() == first {
		t.Fatal("local audit never refreshed")
	}
	a.load()
	if !strings.Contains(screen(a), "is incomplete;") || !ar.Report().Time.Equal(first.Time) {
		t.Fatalf("source age/completeness missing: time=%v first=%v\n%s", ar.Report().Time, first.Time, screen(a))
	}
	src.Close()
	select {
	case <-src.auditDone:
	default:
		t.Fatal("audit worker survived close")
	}
}

func TestRemoteAuditCacheRefreshesWithoutFullAudit(t *testing.T) {
	var current atomic.Pointer[view.AuditView]
	var requests atomic.Int32
	full := time.Now().UTC()
	current.Store(&view.AuditView{Enabled: true, Ready: true, Time: full, UpdatedAt: full, InventorySource: &model.AuditInventorySource{Incomplete: true}})
	dir, err := makeShortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "audit.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rep := current.Load()
		switch r.URL.Path {
		case "/api/status":
			json.NewEncoder(w).Encode(map[string]any{"ready": true, "audit": rep.Brief()})
		case "/api/audit":
			body, _ := json.Marshal(rep)
			etag := fmt.Sprintf("\"%x\"", sha256.Sum256(body))
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			requests.Add(1)
			w.Write(body)
		default:
			io.WriteString(w, "{}")
		}
	})}
	go server.Serve(ln)
	defer server.Close()
	remote, err := DialSocket(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	first, err := remote.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remote.Fetch(); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("unchanged audit not cached")
	}
	next := *current.Load()
	next.UpdatedAt = full.Add(time.Second)
	next.InventorySource = &model.AuditInventorySource{Ready: true, Time: full, Incomplete: true}
	current.Store(&next)
	second, err := remote.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || second.Audit == first.Audit || !second.Audit.InventorySource.Ready || !second.Audit.Time.Equal(first.Audit.Time) {
		t.Fatal("partial update stayed cached")
	}
	// Отсутствие updatedAt не мешает условному запросу по содержимому.
	legacy := next
	legacy.UpdatedAt = time.Time{}
	legacy.InventorySource = nil
	current.Store(&legacy)
	if _, err = remote.Fetch(); err != nil {
		t.Fatal(err)
	}
	if _, err = remote.Fetch(); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 3 {
		t.Fatal("legacy cache broken")
	}
}

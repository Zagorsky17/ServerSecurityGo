package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
)

const maxReportCacheBytes = 8 << 20

type reportReply struct {
	value any
	body  []byte
	etag  string
}

// В каждом фиксированном разделе сохраняется лишь последний неизменяемый отчёт.
type reportCache struct {
	mu     sync.Mutex
	source any
	reply  reportReply
}

func (c *reportCache) get(source any, build func() any) (reportReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reply.body != nil && reflect.DeepEqual(c.source, source) {
		return c.reply, nil
	}
	value := build()
	body, err := json.Marshal(value)
	if err != nil {
		return reportReply{}, err
	}
	body = append(body, '\n')
	sum := sha256.Sum256(body)
	reply := reportReply{value: value, body: body, etag: `"` + hex.EncodeToString(sum[:]) + `"`}
	if len(body) <= maxReportCacheBytes {
		c.source, c.reply = source, reply
	} else {
		c.source, c.reply = nil, reportReply{}
	}
	return reply, nil
}

func (reply reportReply) write(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Кеш только в памяти клиента; чувствительные отчёты не сохраняются HTTP-кешами.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", reply.etag)
	for _, tag := range strings.Split(r.Header.Get("If-None-Match"), ",") {
		if tag = strings.TrimSpace(tag); tag == "*" || strings.TrimPrefix(tag, "W/") == reply.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(reply.body)
}

func (s *Server) reportJSON(w http.ResponseWriter, r *http.Request, c *reportCache, source any, build func() any) {
	reply, err := c.get(source, build)
	if err != nil {
		s.errJSON(w, r, http.StatusInternalServerError, "web.err.report")
		return
	}
	reply.write(w, r)
}

type systemReport struct {
	Groups   []view.SystemGroup    `json:"groups"`
	Findings []model.SystemFinding `json:"findings"`
	Host     model.HostInfo        `json:"host"`
	Warnings []i18n.Msg            `json:"warnings"`
}

type systemItem struct {
	ReviewFirst bool       `json:"reviewFirst,omitempty"`
	Index       int        `json:"index"`
	ID          string     `json:"id"`
	Title       i18n.Msg   `json:"title"`
	Path        string     `json:"path"`
	Risk        model.Risk `json:"risk"`
	ModTime     string     `json:"modTime,omitempty"`
	Suppressed  bool       `json:"suppressed,omitempty"`
}

func (s *Server) systemReport(w http.ResponseWriter, r *http.Request) (reportReply, bool) {
	snap := s.snapshot(w, r)
	if snap == nil {
		return reportReply{}, false
	}
	source := systemReport{Findings: snap.System, Host: snap.Host, Warnings: snap.Warnings}
	reply, err := s.systemCache.get(source, func() any {
		findings := view.SortedSystem(snap)
		return systemReport{Findings: findings, Groups: view.GroupSystem(findings), Host: snap.Host, Warnings: snap.Warnings}
	})
	if err != nil {
		s.errJSON(w, r, http.StatusInternalServerError, "web.err.report")
		return reportReply{}, false
	}
	return reply, true
}

func (s *Server) handleSystemDetail(w http.ResponseWriter, r *http.Request, _ session) {
	reply, ok := s.systemReport(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("revision") != reply.etag {
		s.errJSON(w, r, http.StatusConflict, "web.err.report_changed")
		return
	}
	index, err := strconv.Atoi(r.URL.Query().Get("index"))
	findings := reply.value.(systemReport).Findings
	if err != nil || index < 0 || index >= len(findings) {
		s.errJSON(w, r, http.StatusBadRequest, "web.err.bad_request")
		return
	}
	writeJSON(w, http.StatusOK, findings[index])
}

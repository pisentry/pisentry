// Package server is the panel's HTTP side: agent ingest, the API the web UI
// uses, and the UI itself. Nothing here opens a connection to an agent.
package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pisentry/pisentry/panel/internal/event"
	"github.com/pisentry/pisentry/panel/internal/store"
)

const (
	maxBody   = 4 << 20
	maxEvents = 1000
)

// Server holds what the handlers need.
type Server struct {
	Store      *store.Store
	QuietAfter time.Duration
	UI         http.Handler
	Log        *slog.Logger
	Now        func() time.Time
}

// Handler returns the panel's routes.
func (s *Server) Handler() http.Handler {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /ingest", s.ingest)
	mux.Handle("GET /api/hosts", s.admin(s.hosts))
	mux.Handle("GET /api/events", s.admin(s.events))
	mux.Handle("GET /api/events/{host}/{id}", s.admin(s.eventRaw))
	mux.Handle("GET /api/top10", s.admin(s.top10))
	if s.UI != nil {
		mux.Handle("GET /", s.UI)
	}
	return headers(mux)
}

func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		h.ServeHTTP(w, r)
	})
}

func bearer(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ingest takes a JSON array or newline-delimited JSON of Event Schema events.
// A batch is all or nothing: one bad event rejects it with 400 and its index,
// so the agent can drop that event instead of retrying it forever.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	h, err := s.Store.HostByToken(r.Context(), bearer(r))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.Log.Error("token lookup", "err", err)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="pisentry-panel"`)
		fail(w, http.StatusUnauthorized, "unknown or missing host token")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body over %d bytes", maxBody))
		return
	}
	raws, err := split(body)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(raws) > maxEvents {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("%d events, limit %d per request", len(raws), maxEvents))
		return
	}
	evs := make([]event.Event, 0, len(raws))
	for i, raw := range raws {
		e, err := event.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "index": i})
			return
		}
		evs = append(evs, e)
	}
	added, err := s.Store.Ingest(r.Context(), h, evs)
	if err != nil {
		s.Log.Error("ingest", "host", h.Name, "err", err)
		fail(w, http.StatusServiceUnavailable, "could not store events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"accepted": len(evs), "added": added})
}

func split(body []byte) ([]json.RawMessage, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, nil // a heartbeat with no events still marks the host seen
	}
	if body[0] == '[' {
		var raws []json.RawMessage
		if err := json.Unmarshal(body, &raws); err != nil {
			return nil, fmt.Errorf("body: %w", err)
		}
		return raws, nil
	}
	var raws []json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), event.MaxRaw+1)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		raws = append(raws, append(json.RawMessage(nil), line...))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}
	return raws, nil
}

func (s *Server) admin(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Store.CheckAdmin(r.Context(), bearer(r)) {
			fail(w, http.StatusUnauthorized, "admin token required")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fn(w, r)
	})
}

type hostView struct {
	store.Host
	Status    string `json:"status"` // ok, quiet or waiting (never seen)
	Events24h int    `json:"events_24h"`
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	hs, err := s.Store.Hosts(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	now := s.Now()
	counts, err := s.Store.CountsByHost(r.Context(), now.Add(-24*time.Hour))
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]hostView, 0, len(hs))
	for _, h := range hs {
		v := hostView{Host: h, Status: "ok", Events24h: counts[h.Name]}
		switch {
		case h.LastSeen.IsZero():
			v.Status = "waiting"
		case now.Sub(h.LastSeen) > s.QuietAfter:
			v.Status = "quiet"
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func since(r *http.Request, now time.Time) (time.Time, error) {
	v := r.URL.Query().Get("since")
	if v == "" {
		return now.Add(-24 * time.Hour), nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 || d > 400*24*time.Hour {
		return time.Time{}, fmt.Errorf("since %q: use a duration like 24h", v)
	}
	return now.Add(-d), nil
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	t, err := since(r, s.Now())
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	f := store.Filter{Host: q.Get("host"), Category: q.Get("category"), Since: t}
	if sev := q.Get("severity"); sev != "" {
		if f.MinRank = event.SeverityRank(sev); f.MinRank < 0 {
			fail(w, http.StatusBadRequest, "severity must be info, low, medium, high or critical")
			return
		}
	}
	if l := q.Get("limit"); l != "" {
		f.Limit, _ = strconv.Atoi(l)
	}
	rows, err := s.Store.Events(r.Context(), f)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) eventRaw(w http.ResponseWriter, r *http.Request) {
	raw, err := s.Store.EventRaw(r.Context(), r.PathValue("host"), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "no such event")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, raw)
}

func (s *Server) top10(w http.ResponseWriter, r *http.Request) {
	t, err := since(r, s.Now())
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, err := s.Store.Top10(r.Context(), t, r.URL.Query().Get("host"))
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.Log.Error("api", "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

// CheckListen refuses plain HTTP on anything but loopback: agent tokens and
// the admin token would cross the network in the clear.
func CheckListen(addr string, tls bool) error {
	if tls {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("listen %q without TLS: give -tls-cert and -tls-key, or listen on 127.0.0.1 behind a reverse proxy that terminates TLS", addr)
}

// Prune deletes old events every hour until ctx ends.
func (s *Server) Prune(ctx context.Context, keep time.Duration) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := s.Store.Prune(ctx, s.Now().Add(-keep)); err != nil {
			s.Log.Error("prune", "err", err)
		} else if n > 0 {
			s.Log.Info("pruned events", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/pisentry/pisentry/panel/internal/event"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func ev(t *testing.T, id, cat, sev string, at time.Time) event.Event {
	t.Helper()
	raw := fmt.Sprintf(`{"id":%q,"schema_version":1,"time":%q,"host":"pi-a","category":%q,"severity":%q,"summary":"s","rule":{"id":"R1"}}`,
		id, at.Format(time.RFC3339), cat, sev)
	e, err := event.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestHostsAndTokens(t *testing.T) {
	s, ctx := open(t), context.Background()
	tok, err := s.AddHost(ctx, "pi-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddHost(ctx, "pi-a"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate host: %v", err)
	}
	if _, err := s.AddHost(ctx, "bad name"); err == nil {
		t.Fatal("bad host name accepted")
	}
	h, err := s.HostByToken(ctx, tok)
	if err != nil || h.Name != "pi-a" {
		t.Fatalf("lookup: %v %+v", err, h)
	}
	for _, bad := range []string{"", "psp_nope", tok + "x", "nope"} {
		if _, err := s.HostByToken(ctx, bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("token %q: %v", bad, err)
		}
	}
	if err := s.DeleteHost(ctx, "pi-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostByToken(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatal("token still valid after delete")
	}
	if err := s.DeleteHost(ctx, "pi-a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("second delete should be not found")
	}
}

func TestIngestQueryPrune(t *testing.T) {
	s, ctx := open(t), context.Background()
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	tok, _ := s.AddHost(ctx, "pi-a")
	h, _ := s.HostByToken(ctx, tok)

	batch := []event.Event{
		ev(t, "1", "PS08", "critical", now.Add(-time.Hour)),
		ev(t, "2", "PS01", "medium", now.Add(-2*time.Hour)),
		ev(t, "3", "PS01", "low", now.Add(-40*24*time.Hour)),
	}
	n, err := s.Ingest(ctx, h, batch)
	if err != nil || n != 3 {
		t.Fatalf("ingest: %d %v", n, err)
	}
	if n, _ := s.Ingest(ctx, h, batch); n != 0 {
		t.Fatalf("retry stored %d duplicates", n)
	}
	hosts, _ := s.Hosts(ctx)
	if len(hosts) != 1 || !hosts[0].LastSeen.Equal(now) || hosts[0].ReportedAs != "pi-a" {
		t.Fatalf("hosts: %+v", hosts)
	}

	rows, err := s.Events(ctx, Filter{Since: now.Add(-24 * time.Hour)})
	if err != nil || len(rows) != 2 || rows[0].ID != "1" {
		t.Fatalf("events: %v %+v", err, rows)
	}
	rows, _ = s.Events(ctx, Filter{Since: now.Add(-24 * time.Hour), MinRank: event.SeverityRank("high")})
	if len(rows) != 1 || rows[0].Severity != "critical" {
		t.Fatalf("severity filter: %+v", rows)
	}
	rows, _ = s.Events(ctx, Filter{Category: "PS01"})
	if len(rows) != 2 {
		t.Fatalf("category filter: %+v", rows)
	}

	top, _ := s.Top10(ctx, now.Add(-24*time.Hour))
	if len(top) != 2 || top[0].Category != "PS01" || top[1].Worst != "critical" || top[1].Hosts != 1 {
		t.Fatalf("top10: %+v", top)
	}

	if raw, err := s.EventRaw(ctx, "pi-a", "1"); err != nil || raw == "" {
		t.Fatalf("raw: %v", err)
	}
	if n, _ := s.Prune(ctx, now.Add(-30*24*time.Hour)); n != 1 {
		t.Fatalf("pruned %d", n)
	}
}

func TestAdminToken(t *testing.T) {
	s, ctx := open(t), context.Background()
	a, err := s.AdminToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.AdminToken(ctx)
	if a != b {
		t.Fatal("admin token changed")
	}
	if !s.CheckAdmin(ctx, a) || s.CheckAdmin(ctx, "") || s.CheckAdmin(ctx, a+"x") {
		t.Fatal("CheckAdmin wrong")
	}
}

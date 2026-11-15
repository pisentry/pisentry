// Package store keeps the panel's hosts and events in SQLite.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pisentry/pisentry/panel/internal/event"

	_ "modernc.org/sqlite" // pure Go, no cgo
)

// TokenPrefix marks panel host tokens so they are easy to spot in a leak scan.
const TokenPrefix = "psp_"

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	hostNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
)

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	id          INTEGER PRIMARY KEY,
	name        TEXT NOT NULL UNIQUE,
	token_hash  BLOB NOT NULL UNIQUE,
	created_at  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL DEFAULT 0,
	reported_as TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
	host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	id       TEXT NOT NULL,
	time     INTEGER NOT NULL,
	category TEXT NOT NULL,
	severity TEXT NOT NULL,
	rule_id  TEXT NOT NULL DEFAULT '',
	summary  TEXT NOT NULL,
	raw      TEXT NOT NULL,
	PRIMARY KEY (host_id, id)
);
CREATE INDEX IF NOT EXISTS events_time ON events(time);
CREATE INDEX IF NOT EXISTS events_host_time ON events(host_id, time);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// Store is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open creates or opens the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init %s: %w", path, err)
	}
	return &Store{db: db, now: time.Now}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Host is a registered agent.
type Host struct {
	ID         int64     `json:"-"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeen   time.Time `json:"last_seen"`
	ReportedAs string    `json:"reported_as,omitempty"`
}

func newToken() (string, []byte) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on Linux
	}
	tok := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(tok))
	return tok, h[:]
}

// AddHost registers a host and returns its token. Only the token's hash is
// stored, so this is the one time it can be shown.
func (s *Store) AddHost(ctx context.Context, name string) (string, error) {
	if !hostNameRe.MatchString(name) {
		return "", fmt.Errorf("host name %q: use letters, digits, '.', '_' or '-', at most 63", name)
	}
	tok, h := newToken()
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts(name, token_hash, created_at) VALUES(?, ?, ?)`, name, h, s.now().Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", fmt.Errorf("host %q: %w", name, ErrExists)
		}
		return "", err
	}
	return tok, nil
}

// HostByToken finds the host a token belongs to.
func (s *Store) HostByToken(ctx context.Context, tok string) (Host, error) {
	if !strings.HasPrefix(tok, TokenPrefix) || len(tok) > 128 {
		return Host{}, ErrNotFound
	}
	h := sha256.Sum256([]byte(tok))
	var host Host
	var created, seen int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, created_at, last_seen, reported_as FROM hosts WHERE token_hash = ?`, h[:]).
		Scan(&host.ID, &host.Name, &created, &seen, &host.ReportedAs)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, err
	}
	host.CreatedAt, host.LastSeen = unix(created), unix(seen)
	return host, nil
}

// DeleteHost removes a host, its token and its events.
func (s *Store) DeleteHost(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("host %q: %w", name, ErrNotFound)
	}
	return nil
}

// Hosts lists every host by name.
func (s *Store) Hosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, last_seen, reported_as FROM hosts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		var created, seen int64
		if err := rows.Scan(&h.ID, &h.Name, &created, &seen, &h.ReportedAs); err != nil {
			return nil, err
		}
		h.CreatedAt, h.LastSeen = unix(created), unix(seen)
		out = append(out, h)
	}
	return out, rows.Err()
}

// Ingest stores events for a host and marks it seen. Events already stored
// (same id) are skipped, so an agent retrying a batch causes no duplicates.
func (s *Store) Ingest(ctx context.Context, h Host, evs []event.Event) (added int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO events(host_id, id, time, category, severity, rule_id, summary, raw) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	reported := h.ReportedAs
	for _, e := range evs {
		res, err := stmt.ExecContext(ctx, h.ID, e.ID, e.Time.Unix(), e.Category, e.Severity, e.RuleID, e.Summary, string(e.Raw))
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		added += int(n)
		if e.Host != "" {
			reported = e.Host
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET last_seen = ?, reported_as = ? WHERE id = ?`, s.now().Unix(), reported, h.ID); err != nil {
		return 0, err
	}
	return added, tx.Commit()
}

// Filter selects events. Zero values match everything.
type Filter struct {
	Host     string
	Category string
	MinRank  int // event.SeverityRank; 0 is info and up
	Since    time.Time
	Limit    int
}

// EventRow is an event as the API returns it.
type EventRow struct {
	Host     string    `json:"host"`
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Category string    `json:"category"`
	Severity string    `json:"severity"`
	RuleID   string    `json:"rule_id,omitempty"`
	Summary  string    `json:"summary"`
}

var severityAtLeast = []string{
	`'info','low','medium','high','critical'`,
	`'low','medium','high','critical'`,
	`'medium','high','critical'`,
	`'high','critical'`,
	`'critical'`,
}

// Events returns matching events, newest first.
func (s *Store) Events(ctx context.Context, f Filter) ([]EventRow, error) {
	q := `SELECT h.name, e.id, e.time, e.category, e.severity, e.rule_id, e.summary FROM events e JOIN hosts h ON h.id = e.host_id WHERE e.time >= ?`
	args := []any{f.Since.Unix()}
	if f.Host != "" {
		q += ` AND h.name = ?`
		args = append(args, f.Host)
	}
	if f.Category != "" {
		q += ` AND e.category = ?`
		args = append(args, f.Category)
	}
	if f.MinRank > 0 && f.MinRank < len(severityAtLeast) {
		q += ` AND e.severity IN (` + severityAtLeast[f.MinRank] + `)`
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	q += ` ORDER BY e.time DESC, e.id LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventRow{}
	for rows.Next() {
		var r EventRow
		var t int64
		if err := rows.Scan(&r.Host, &r.ID, &t, &r.Category, &r.Severity, &r.RuleID, &r.Summary); err != nil {
			return nil, err
		}
		r.Time = unix(t)
		out = append(out, r)
	}
	return out, rows.Err()
}

// EventRaw returns one event's original JSON.
func (s *Store) EventRaw(ctx context.Context, host, id string) (string, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT e.raw FROM events e JOIN hosts h ON h.id = e.host_id WHERE h.name = ? AND e.id = ?`, host, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return raw, err
}

// CategoryCount is one row of the fleet Top 10.
type CategoryCount struct {
	Category string `json:"category"`
	Events   int    `json:"events"`
	Hosts    int    `json:"hosts"`
	Worst    string `json:"worst"`
}

// Top10 counts events per category since t.
func (s *Store) Top10(ctx context.Context, since time.Time) ([]CategoryCount, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT category, COUNT(*), COUNT(DISTINCT host_id),
  MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
FROM events WHERE time >= ? GROUP BY category ORDER BY category`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := []string{"info", "low", "medium", "high", "critical"}
	out := []CategoryCount{}
	for rows.Next() {
		var c CategoryCount
		var worst int
		if err := rows.Scan(&c.Category, &c.Events, &c.Hosts, &worst); err != nil {
			return nil, err
		}
		c.Worst = names[worst]
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountsByHost counts events per host name since t.
func (s *Store) CountsByHost(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT h.name, COUNT(*) FROM events e JOIN hosts h ON h.id = e.host_id WHERE e.time >= ? GROUP BY h.name`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		out[name] = n
	}
	return out, rows.Err()
}

// Prune deletes events older than t and returns how many went.
func (s *Store) Prune(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE time < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// AdminToken returns the token the web UI and API ask for, creating it on
// first use. It stands in for accounts until they land (#77).
func (s *Store) AdminToken(ctx context.Context) (string, error) {
	var tok string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'admin_token'`).Scan(&tok)
	if err == nil {
		return tok, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok = "psa_" + base64.RawURLEncoding.EncodeToString(b)
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO settings(key, value) VALUES('admin_token', ?)`, tok); err != nil {
		return "", err
	}
	// Another process may have won the race; return what is stored.
	err = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'admin_token'`).Scan(&tok)
	return tok, err
}

// CheckAdmin compares a presented admin token in constant time.
func (s *Store) CheckAdmin(ctx context.Context, presented string) bool {
	tok, err := s.AdminToken(ctx)
	if err != nil || presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(presented)) == 1
}

func unix(t int64) time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(t, 0).UTC()
}

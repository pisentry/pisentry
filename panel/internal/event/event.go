// Package event validates pisentry Event Schema v1 events as the panel
// receives them. The panel keeps the original JSON and indexes a few fields;
// it does not need every field the agent sends, and ignores the ones it
// doesn't know, so agents can add fields within v1.
package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// SupportedVersions are the Event Schema major versions the panel accepts:
// the current one and, once v2 exists, the previous one (ADR 0002).
var SupportedVersions = map[int]bool{1: true}

// MaxRaw is the largest single event the panel stores.
const MaxRaw = 64 << 10

var (
	categoryRe = regexp.MustCompile(`^PS(0[0-9]|1[0-9])$`)
	severities = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
)

// Event holds the indexed fields of one event plus its original JSON.
type Event struct {
	ID       string
	Time     time.Time
	Host     string
	Category string
	Severity string
	RuleID   string
	Summary  string
	Raw      json.RawMessage
}

type wire struct {
	ID            string    `json:"id"`
	SchemaVersion int       `json:"schema_version"`
	Time          time.Time `json:"time"`
	Host          string    `json:"host"`
	Category      string    `json:"category"`
	Severity      string    `json:"severity"`
	Summary       string    `json:"summary"`
	Rule          *struct {
		ID string `json:"id"`
	} `json:"rule"`
}

// Parse validates one raw event.
func Parse(raw []byte) (Event, error) {
	if len(raw) > MaxRaw {
		return Event{}, fmt.Errorf("event is %d bytes, limit %d", len(raw), MaxRaw)
	}
	if !utf8.Valid(raw) {
		return Event{}, errors.New("event is not valid UTF-8")
	}
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return Event{}, fmt.Errorf("event: %w", err)
	}
	switch {
	case !SupportedVersions[w.SchemaVersion]:
		return Event{}, fmt.Errorf("schema_version %d not supported", w.SchemaVersion)
	case w.ID == "" || len(w.ID) > 128:
		return Event{}, errors.New("id must be 1 to 128 bytes")
	case w.Time.IsZero():
		return Event{}, errors.New("time is required")
	case !categoryRe.MatchString(w.Category):
		return Event{}, fmt.Errorf("category %q is not PS00 to PS19", w.Category)
	case w.Summary == "" || len(w.Summary) > 4096:
		return Event{}, errors.New("summary must be 1 to 4096 bytes")
	case len(w.Host) > 255:
		return Event{}, errors.New("host is longer than 255 bytes")
	}
	if _, ok := severities[w.Severity]; !ok {
		return Event{}, fmt.Errorf("severity %q is not one of info, low, medium, high, critical", w.Severity)
	}
	e := Event{ID: w.ID, Time: w.Time.UTC(), Host: w.Host, Category: w.Category,
		Severity: w.Severity, Summary: w.Summary, Raw: append(json.RawMessage(nil), raw...)}
	if w.Rule != nil && len(w.Rule.ID) <= 128 {
		e.RuleID = w.Rule.ID
	}
	return e, nil
}

// SeverityRank orders severities from info (0) to critical (4); unknown is -1.
func SeverityRank(s string) int {
	if r, ok := severities[s]; ok {
		return r
	}
	return -1
}

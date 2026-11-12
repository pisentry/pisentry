package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pisentry/pisentry/internal/event"
)

func TestCorruptStateRecovers(t *testing.T) {
	dir := t.TempDir()
	// Simulates a Pi losing power mid-write on an older build.
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"version":1,"totals":{"PS0`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("corrupt state must not be fatal: %v", err)
	}
	if st.Recovered == "" {
		t.Fatal("expected quarantined path")
	}
	st.Record(event.Event{Category: event.PortScan})
	if err := st.Save(false); err != nil {
		t.Fatal(err)
	}
	s, err := ReadFile(filepath.Join(dir, FileName))
	if err != nil || s.Totals[event.PortScan] != 1 {
		t.Fatalf("roundtrip: %v %+v", err, s.Totals)
	}
}

func TestResetBaselinesRestartsLearning(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.View(func(s *State) {
		if !s.Baselines.LearningSince.IsZero() {
			t.Fatalf("fresh state should learn from Created, got LearningSince %v", s.Baselines.LearningSince)
		}
	})
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.FixedZone("x", 3600))
	st.Update(func(s *State) { s.Baselines.Logins["pi"] = map[string]time.Time{"192.0.2.1": at} })
	st.ResetBaselines(at)
	if err := st.Save(false); err != nil {
		t.Fatal(err)
	}
	s, err := ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Baselines.LearningSince.Equal(at) || s.Baselines.LearningSince.Location() != time.UTC {
		t.Fatalf("LearningSince = %v, want %v in UTC", s.Baselines.LearningSince, at)
	}
	if len(s.Baselines.Logins) != 0 {
		t.Fatalf("logins not reset: %v", s.Baselines.Logins)
	}
}

package engine

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pisentry/pisentry/internal/config"
	"github.com/pisentry/pisentry/internal/event"
	"github.com/pisentry/pisentry/internal/metrics"
)

// Benchmarks for the per-event path: sanitize, enrich and JSON encode. The
// budget for each lives in bench/budget.json; see bench/README.md.

const benchCmdline = "/usr/bin/python3 /opt/app/server.py --port 8080 --workers 4 --log-level info"

// benchProcessEvent is a process rule hit as ProcWatch emits it.
func benchProcessEvent() event.Event {
	return event.Event{
		Category: event.ReverseShell, Severity: event.High, Detector: "proc",
		Key:     "BENCH-RULE|4242:1234567",
		Summary: "Interpreter with a network argument: python3 (pid 4242)",
		MITRE:   []string{"T1059.006"},
		Rule:    &event.RuleEntity{ID: "BENCH-RULE", Title: "Interpreter with a network argument"},
		Process: &event.ProcessEntity{
			PID: 4242, PPID: 1, StartTime: 1234567, UID: event.IntPtr(1000),
			Comm: "python3", Exe: "/usr/bin/python3.13", Cmdline: benchCmdline,
		},
		User: &event.UserEntity{UID: event.IntPtr(1000)},
		Fields: map[string]string{
			"pid": "4242", "comm": "python3", "exe": "/usr/bin/python3.13",
			"cmdline": benchCmdline, "uid": "1000", "rule": "BENCH-RULE",
		},
	}
}

// Attacker text from a forged sudo log line: terminal escapes, a bidi
// override and invalid UTF-8 in the user name and command line.
var (
	hostileUser = "pi\x1b[2J\x1b]0;owned\x07"
	hostileCmd  = "/bin/sh -c echo \u202etxt.exe\xff " + strings.Repeat("A", 600)
	hostileKey  = "sudo-risky|" + hostileUser + "|" + hostileCmd
)

// resetHostile puts the attacker strings back. SanitizeEvent works in place,
// so each iteration needs them again; plain assignments do not allocate.
func resetHostile(ev *event.Event) {
	ev.Summary = "Risky command via sudo by " + "pi" + " as root"
	ev.Key = hostileKey
	ev.User.Name = hostileUser
	ev.Process.Cmdline = hostileCmd
	ev.Fields["user"] = hostileUser
	ev.Fields["command"] = hostileCmd
}

func BenchmarkSanitizeEvent(b *testing.B) {
	b.Run("clean", func(b *testing.B) {
		ev := benchProcessEvent()
		b.ReportAllocs()
		for b.Loop() {
			SanitizeEvent(&ev)
		}
	})
	b.Run("hostile", func(b *testing.B) {
		ev := event.Event{
			Category: event.PrivEsc, Severity: event.High, Detector: "auth",
			User:    &event.UserEntity{},
			Process: &event.ProcessEntity{},
			Rule:    &event.RuleEntity{ID: "PS04-SUDO-PIPE-SHELL", Title: "Download piped to a shell via sudo"},
			Fields:  map[string]string{"user": "", "as_user": "root", "command": "", "pattern": "PS04-SUDO-PIPE-SHELL"},
		}
		b.ReportAllocs()
		for b.Loop() {
			resetHostile(&ev)
			SanitizeEvent(&ev)
		}
	})
}

func BenchmarkEncodeEvent(b *testing.B) {
	ev := benchProcessEvent()
	ev.ID = "6f1c2a9e-8d3b-4c7a-9e5f-0a1b2c3d4e5f"
	ev.SchemaVersion = event.SchemaVersion
	ev.Time = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	ev.Host = "kubepi"
	ev.CategoryName = event.Lookup(ev.Category).Name
	s := NewJSONSink(io.Discard)
	b.ReportAllocs()
	for b.Loop() {
		s.Handle(ev)
	}
}

// BenchmarkEmit is one event through Engine.Emit: ID, sanitize, enrich,
// cooldown bookkeeping, metrics and a JSON sink.
func BenchmarkEmit(b *testing.B) {
	cfg := config.Defaults()
	cfg.Cooldown = config.D(0) // never suppress, so every iteration takes the full path
	eng := New(&cfg, "kubepi", nil, metrics.NewSet())
	eng.AddSink(NewJSONSink(io.Discard))
	ev := benchProcessEvent()
	b.ReportAllocs()
	for b.Loop() {
		eng.Emit(ev)
	}
}

package logsrc

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pisentry/pisentry/internal/metrics"
)

func TestParseSyslog(t *testing.T) {
	cases := []struct{ in, ident, msg string }{
		{"Oct 15 10:01:02 kubepi sshd[1234]: Failed password for pi from 1.2.3.4 port 22 ssh2", "sshd", "Failed password for pi from 1.2.3.4 port 22 ssh2"},
		{"2026-10-15T10:01:02.123456-04:00 kubepi sshd-session[99]: Invalid user x from 1.2.3.4 port 5", "sshd-session", "Invalid user x from 1.2.3.4 port 5"},
		{"Oct  5 09:00:00 kubethink kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DPT=23", "kernel", "[UFW BLOCK] IN=eth0 SRC=1.2.3.4 DPT=23"},
		{"Oct 15 10:01:02 kubepi sudo:      jon : TTY=pts/0 ; COMMAND=/bin/ls", "sudo", "     jon : TTY=pts/0 ; COMMAND=/bin/ls"},
	}
	for _, c := range cases {
		l, ok := ParseSyslog(c.in)
		if !ok || l.Ident != c.ident || l.Msg != c.msg {
			t.Errorf("%q -> %+v ok=%v", c.in, l, ok)
		}
	}
	if l, _ := ParseSyslog(cases[2].in); !l.Kernel {
		t.Error("kernel flag")
	}
}

func TestFromJournal(t *testing.T) {
	var e journalEntry
	_ = json.Unmarshal([]byte(`{"MESSAGE":"Accepted publickey for jon from 10.0.0.5 port 2 ssh2","SYSLOG_IDENTIFIER":"sshd-session","__REALTIME_TIMESTAMP":"1760522400000000"}`), &e)
	l, ok := FromJournal(e)
	if !ok || l.Ident != "sshd-session" || l.Time.Unix() != 1760522400 {
		t.Errorf("%+v", l)
	}
	// Non-UTF-8 messages arrive as byte arrays.
	e = journalEntry{}
	_ = json.Unmarshal([]byte(`{"MESSAGE":[83,82,67,61,49],"_TRANSPORT":"kernel"}`), &e)
	l, ok = FromJournal(e)
	if !ok || l.Msg != "SRC=1" || !l.Kernel || l.Ident != "kernel" {
		t.Errorf("%+v", l)
	}
}

// logrotate `create` renames auth.log and creates a new one, and rsyslog keeps
// writing to the renamed file until it is told to reopen. Those lines are read
// before the tailer moves to the new file (#53).
func TestTailFileReadsRenamedFileBeforeReopen(t *testing.T) {
	old := tailInterval
	tailInterval = 200 * time.Millisecond
	t.Cleanup(func() { tailInterval = old })

	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendLine := func(p, msg string) {
		t.Helper()
		f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("Oct 15 10:01:02 pi sshd[1]: " + msg + "\n"); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	appendLine(path, "before start")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan Line, 64)
	done := make(chan struct{})
	go func() {
		tailFile(ctx, path, out, metrics.NewSet(), slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	defer func() { cancel(); <-done }()

	next := func() string {
		t.Helper()
		select {
		case l := <-out:
			return l.Msg
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a line")
			return ""
		}
	}

	// The tailer starts at the end of the file. Write until it sees a line,
	// so the rest of the test does not depend on when it opened the file.
	for i := 0; ; i++ {
		appendLine(path, "warmup")
		select {
		case l := <-out:
			if l.Msg != "warmup" {
				t.Fatalf("got %q before warmup", l.Msg)
			}
		case <-time.After(300 * time.Millisecond):
			if i > 20 {
				t.Fatal("tailer never picked up the file")
			}
			continue
		}
		break
	}
	for len(out) > 0 {
		<-out
	}

	appendLine(path, "line A")
	if got := next(); got != "line A" {
		t.Fatalf("got %q, want line A", got)
	}
	// All three steps land inside one poll interval, so the tailer sees the
	// new inode with line B still unread in the old file.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(path+".1", "line B")
	appendLine(path, "line C")

	for _, want := range []string{"line B", "line C"} {
		if got := next(); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

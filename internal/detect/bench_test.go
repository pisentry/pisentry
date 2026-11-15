package detect

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pisentry/pisentry/internal/config"
	"github.com/pisentry/pisentry/internal/event"
	"github.com/pisentry/pisentry/internal/metrics"
	"github.com/pisentry/pisentry/internal/rules"
)

// fixtureCopies scales testdata/proc (20 processes from a k3s node on a Pi,
// 4 of them kernel threads) to 180 processes, about what such a node runs.
const fixtureCopies = 9

// copyProcFixture builds a /proc tree under dir from testdata/proc. Copy k
// shifts every pid by k*100000; parents keep their original pids, which copy
// 0 holds. Symlinks come from testdata/proc/links because not every checkout
// can store them in git. It returns the number of user processes, the ones
// with an exe link; ProcWatch skips kernel threads.
func copyProcFixture(tb testing.TB, dir string) int {
	tb.Helper()
	src := filepath.Join("testdata", "proc")
	ents, err := os.ReadDir(src)
	if err != nil {
		tb.Fatal(err)
	}
	links, err := os.ReadFile(filepath.Join(src, "links"))
	if err != nil {
		tb.Fatal(err)
	}
	n := 0
	for k := range fixtureCopies {
		for _, e := range ents {
			pid, err := strconv.Atoi(e.Name())
			if err != nil || !e.IsDir() {
				continue
			}
			newPID := strconv.Itoa(pid + k*100000)
			files, err := os.ReadDir(filepath.Join(src, e.Name()))
			if err != nil {
				tb.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, newPID), 0o755); err != nil {
				tb.Fatal(err)
			}
			for _, f := range files {
				b, err := os.ReadFile(filepath.Join(src, e.Name(), f.Name()))
				if err != nil {
					tb.Fatal(err)
				}
				if f.Name() == "stat" {
					b = append([]byte(newPID), b[bytes.IndexByte(b, ' '):]...)
				}
				if err := os.WriteFile(filepath.Join(dir, newPID, f.Name()), b, 0o644); err != nil {
					tb.Fatal(err)
				}
			}
		}
		sc := bufio.NewScanner(bytes.NewReader(links))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			path, target, ok := strings.Cut(line, " ")
			if !ok {
				tb.Fatalf("bad links line %q", line)
			}
			pid, rest, _ := strings.Cut(path, "/")
			p, err := strconv.Atoi(pid)
			if err != nil {
				tb.Fatalf("bad links line %q", line)
			}
			dst := filepath.Join(dir, strconv.Itoa(p+k*100000), filepath.FromSlash(rest))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				tb.Fatal(err)
			}
			if err := os.Symlink(target, dst); err != nil {
				tb.Fatal(err)
			}
			if rest == "exe" {
				n++
			}
		}
	}
	return n
}

// Process rules for the scan benchmark, kept small and fixed so the numbers
// track the scan (reads, parsing, bookkeeping) and not the shipped rules.
const scanBenchRules = `{
  "schema_version": 1,
  "catalog": {"shell_names": ["sh", "bash", "dash", "zsh", "python", "perl"], "stratum_ports": [3333, 4444, 5555]},
  "rules": [
    {"id": "SCAN-MINER", "title": "Known miner", "category": "PS06", "level": "critical", "source": "process",
     "match": {"any": [{"field": "process.comm", "equals": ["xmrig", "kdevtmpfsi", "kinsing"]},
                       {"field": "process.cmdline", "regex": ["stratum\\+(tcp|ssl)://"]}]}},
    {"id": "SCAN-TMP-EXEC", "title": "Binary in a temp dir", "category": "PS06", "level": "high", "source": "process",
     "match": {"all": [{"field": "process.exe", "startswith": ["/tmp/", "/dev/shm/", "/var/tmp/"]}]}},
    {"id": "SCAN-NC-EXEC", "title": "netcat with exec", "category": "PS08", "level": "high", "source": "process",
     "match": {"all": [{"field": "process.comm", "equals": ["nc", "ncat"]},
                       {"field": "process.cmdline", "regex": ["\\s-(e|c)\\s"]}]}}%s
  ]
}`

// eagerRule matches on the parent comm, which makes ProcWatch read the uid
// and parent for every process instead of only after a hit.
const eagerRule = `,
    {"id": "SCAN-WEB-SHELL", "title": "Shell under a web server", "category": "PS08", "level": "high", "source": "process",
     "match": {"all": [{"field": "process.comm", "equals": ["sh", "bash"]},
                       {"field": "process.parent_comm", "equals": ["nginx", "apache2", "lighttpd"]}]}}`

// BenchmarkProcScan is one ProcWatch.Scan over the fixture tree. In lazy no
// rule reads the uid or parent, so they are only read after a hit; eager adds
// a rule on process.parent_comm, which reads both for every process.
func BenchmarkProcScan(b *testing.B) {
	for _, tc := range []struct {
		name, extra string
	}{
		{"lazy", ""},
		{"eager", eagerRule},
	} {
		b.Run(tc.name, func(b *testing.B) {
			procRoot := filepath.Join(b.TempDir(), "proc")
			nuser := copyProcFixture(b, procRoot)
			re, err := rules.NewEngineFromBytes("bench.json", []byte(strings.Replace(scanBenchRules, "%s", tc.extra, 1)))
			if err != nil {
				b.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.ProcRoot = procRoot
			emitted := 0
			pw := NewProcWatch(Deps{
				Cfg: &cfg, Rules: re, M: metrics.NewSet(),
				Emit: event.EmitFunc(func(event.Event) { emitted++ }),
				Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err := pw.Scan(); err != nil {
				b.Fatal(err)
			}
			if got := len(pw.prev); got != nuser {
				b.Fatalf("scan saw %d user processes, want %d", got, nuser)
			}
			if emitted != 0 {
				b.Fatalf("fixture is benign but the scan emitted %d events", emitted)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := pw.Scan(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

package main

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const headOut = `goos: linux
goarch: arm64
pkg: github.com/pisentry/pisentry/internal/engine
BenchmarkSanitizeEvent/clean-4         	  224851	      1071 ns/op	       0 B/op	       0 allocs/op
BenchmarkSanitizeEvent/clean-4         	  224851	      1200 ns/op	       0 B/op	       0 allocs/op
BenchmarkEmit-4                        	   52880	      4436 ns/op	    1773 B/op	      27 allocs/op
BenchmarkEmit-4                        	   52880	      4500 ns/op	    1773 B/op	      27 allocs/op
PASS
ok  	github.com/pisentry/pisentry/internal/engine	0.977s
pkg: github.com/pisentry/pisentry/internal/rules
BenchmarkRuleMatch/process/rules=75-4  	    5151	     42316 ns/op	     320 B/op	       4 allocs/op
BenchmarkNoBudget-4                    	    5151	       100 ns/op	       0 B/op	       0 allocs/op
`

// Trimmed from real benchstat -format csv output.
const statCSV = `goos: linux
goarch: arm64
pkg: github.com/pisentry/pisentry/internal/engine
,base,,head,,,
,sec/op,CI,sec/op,CI,vs base,P
SanitizeEvent/clean-4,1.018e-06,2%,1.021e-06,1%,~,p=0.841 n=10
Emit-4,4.395e-06,1%,5.6e-06,1%,+27.42%,p=0.000 n=10
geomean,3.487793810680469e-06,,3.5015168131409045e-06,,+0.39%,

,base,,head,,,
,B/op,CI,B/op,CI,vs base,P
Emit-4,1775,0%,1776,0%,~,p=1.000 n=10
geomean,,,,,+0.02%,

,base,,head,,,
,allocs/op,CI,allocs/op,CI,vs base,P
SanitizeEvent/clean-4,0,0%,0,0%,~,p=1.000 n=10
Emit-4,27,0%,27,0%,~,p=1.000 n=10

pkg: github.com/pisentry/pisentry/internal/rules
,base,,head,,,
,sec/op,CI,sec/op,CI,vs base,P
"RuleMatch/process/rules=75-4",4.0775e-05,1%,6.0e-05,1%,+47.15%,p=0.000 n=10
`

func TestParseBench(t *testing.T) {
	got, err := ParseBench(strings.NewReader(headOut))
	if err != nil {
		t.Fatal(err)
	}
	s := got["SanitizeEvent/clean"]
	if s == nil || len(s.Ns) != 2 || s.Ns[1] != 1200 || len(s.Allocs) != 2 {
		t.Fatalf("SanitizeEvent/clean = %+v", s)
	}
	if got["RuleMatch/process/rules=75"] == nil || got["Emit"].Allocs[0] != 27 {
		t.Fatalf("names or allocs not parsed: %v", got)
	}
}

func TestParseBenchstatCSV(t *testing.T) {
	ds, err := ParseBenchstatCSV(strings.NewReader(statCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 5 {
		t.Fatalf("want 5 sec/op and allocs/op rows, got %d: %+v", len(ds), ds)
	}
	if ds[0].Name != "SanitizeEvent/clean" || ds[0].Delta != "~" || !math.IsNaN(ds[0].Pct) {
		t.Fatalf("row 0 = %+v", ds[0])
	}
	if ds[1].Name != "Emit" || ds[1].Unit != "sec/op" || ds[1].Pct != 27.42 {
		t.Fatalf("row 1 = %+v", ds[1])
	}
	if ds[4].Name != "RuleMatch/process/rules=75" || ds[4].Pct != 47.15 {
		t.Fatalf("row 4 = %+v", ds[4])
	}
}

func testBudget() *Budget {
	return &Budget{MaxRegressionPct: 20, Benchmarks: []Entry{
		{Name: "SanitizeEvent/clean", Per: "event", Hot: true, NsPerOp: 4000, AllocsPerOp: 0},
		{Name: "Emit", Per: "event", Hot: true, NsPerOp: 15000, AllocsPerOp: 27},
		{Name: "RuleMatch/process/rules=75", Per: "event", Hot: false, NsPerOp: 150000, AllocsPerOp: 5},
	}}
}

func TestCheckRegression(t *testing.T) {
	head, _ := ParseBench(strings.NewReader(headOut))
	ds, _ := ParseBenchstatCSV(strings.NewReader(statCSV))
	var out bytes.Buffer
	fails := Check(&out, testBudget(), head, ds, true)
	// Emit is hot and 27% slower; RuleMatch is 47% slower but not gated here.
	if len(fails) != 1 || !strings.HasPrefix(fails[0], "Emit: sec/op +27.42%") {
		t.Fatalf("fails = %q\n%s", fails, out.String())
	}
	if !strings.Contains(out.String(), "NoBudget") {
		t.Errorf("report does not list the benchmark without a budget:\n%s", out.String())
	}
}

func TestCheckBudget(t *testing.T) {
	head, _ := ParseBench(strings.NewReader(headOut))
	b := testBudget()
	b.Benchmarks[0].NsPerOp = 1100 // slowest clean run is 1200 ns
	b.Benchmarks[1].AllocsPerOp = 26
	b.Benchmarks = append(b.Benchmarks, Entry{Name: "Gone", NsPerOp: 1, Per: "event"})
	var out bytes.Buffer
	fails := Check(&out, b, head, nil, false)
	if len(fails) != 3 {
		t.Fatalf("want time, allocs and missing failures, got %q", fails)
	}
	for i, want := range []string{"SanitizeEvent/clean: slowest run", "Emit: 27 allocs/op", "Gone: no result"} {
		if !strings.HasPrefix(fails[i], want) {
			t.Errorf("fails[%d] = %q, want prefix %q", i, fails[i], want)
		}
	}
}

// The budget file in the repo must parse and cover every benchmark it names
// at most once.
func TestRepoBudget(t *testing.T) {
	dir := t.TempDir()
	head := filepath.Join(dir, "head.txt")
	if err := os.WriteFile(head, []byte(headOut), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	// Fails on missing results, which is fine: this checks the file loads.
	err := run([]string{"-budget", "../budget.json", "-head", head}, &out)
	if err != nil && !strings.Contains(err.Error(), "check(s) failed") {
		t.Fatal(err)
	}
	b, err := loadBudget("../budget.json")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range b.Benchmarks {
		if seen[e.Name] {
			t.Errorf("duplicate budget entry %q", e.Name)
		}
		seen[e.Name] = true
		if e.NsPerOp <= 0 || e.Per == "" {
			t.Errorf("%s: ns_per_op and per are required", e.Name)
		}
	}
}

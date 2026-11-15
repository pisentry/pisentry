// Command benchgate checks benchmark results against bench/budget.json and,
// on pull requests, the benchstat comparison with the base branch. It writes
// a Markdown report and exits 1 when a benchmark breaks its budget or a hot
// path benchmark regresses by more than the allowed percentage.
//
// It runs in CI only and is not part of the agent. See bench/README.md.
package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Budget is bench/budget.json.
type Budget struct {
	MaxRegressionPct float64 `json:"max_regression_pct"`
	Benchmarks       []Entry `json:"benchmarks"`
}

// Entry is the budget for one benchmark. Name is as benchstat prints it:
// no "Benchmark" prefix and no -GOMAXPROCS suffix.
type Entry struct {
	Name        string  `json:"name"`
	Per         string  `json:"per"`
	Hot         bool    `json:"hot"`
	NsPerOp     float64 `json:"ns_per_op"`
	AllocsPerOp float64 `json:"allocs_per_op"`
}

// Samples holds every run of one benchmark.
type Samples struct {
	Ns     []float64
	Allocs []float64
}

// Delta is one benchstat row: a change benchstat found significant, or
// "~" when it found none.
type Delta struct {
	Name  string
	Unit  string // sec/op or allocs/op
	Delta string
	Pct   float64 // NaN unless Delta is a percentage
}

var procsSuffix = regexp.MustCompile(`-\d+$`)

// normName strips the Benchmark prefix and the -GOMAXPROCS suffix.
func normName(s string) string {
	return procsSuffix.ReplaceAllString(strings.TrimPrefix(s, "Benchmark"), "")
}

// ParseBench reads `go test -bench -benchmem` output.
func ParseBench(r io.Reader) (map[string]*Samples, error) {
	out := map[string]*Samples{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || !strings.HasPrefix(f[0], "Benchmark") {
			continue
		}
		if _, err := strconv.Atoi(f[1]); err != nil {
			continue // not a result line
		}
		s := out[normName(f[0])]
		if s == nil {
			s = &Samples{}
			out[normName(f[0])] = s
		}
		for i := 2; i+1 < len(f); i += 2 {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return nil, fmt.Errorf("bad value %q in %q", f[i], sc.Text())
			}
			switch f[i+1] {
			case "ns/op":
				s.Ns = append(s.Ns, v)
			case "allocs/op":
				s.Allocs = append(s.Allocs, v)
			}
		}
	}
	return out, sc.Err()
}

// ParseBenchstatCSV reads `benchstat -format csv base=... head=...` and
// returns the sec/op and allocs/op rows.
func ParseBenchstatCSV(r io.Reader) ([]Delta, error) {
	var out []Delta
	unit := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || !strings.Contains(line, ",") {
			continue // blank lines and goos:, pkg: headers
		}
		rec, err := csv.NewReader(strings.NewReader(line)).Read()
		if err != nil {
			return nil, fmt.Errorf("benchstat csv %q: %w", line, err)
		}
		if rec[0] == "" {
			if len(rec) > 1 && strings.Contains(rec[1], "/op") {
				unit = rec[1]
			}
			continue
		}
		if rec[0] == "geomean" || (unit != "sec/op" && unit != "allocs/op") || len(rec) < 7 {
			continue
		}
		d := Delta{Name: normName(rec[0]), Unit: unit, Delta: rec[5], Pct: math.NaN()}
		if p, ok := strings.CutSuffix(rec[5], "%"); ok {
			if v, err := strconv.ParseFloat(p, 64); err == nil {
				d.Pct = v
			}
		}
		out = append(out, d)
	}
	return out, sc.Err()
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func fmtNs(ns float64) string {
	switch {
	case math.IsNaN(ns):
		return "-"
	case ns >= 1e6:
		return fmt.Sprintf("%.2f ms", ns/1e6)
	case ns >= 1e3:
		return fmt.Sprintf("%.2f µs", ns/1e3)
	}
	return fmt.Sprintf("%.0f ns", ns)
}

func fmtCount(v float64) string {
	if math.IsNaN(v) {
		return "-"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// Check compares head results and the optional deltas with b and writes a
// Markdown report to w. It returns the failures.
func Check(w io.Writer, b *Budget, head map[string]*Samples, deltas []Delta, compared bool) []string {
	var fails []string
	byName := map[string]Entry{}
	fmt.Fprintf(w, "## Benchmarks\n\n")
	fmt.Fprintf(w, "Time is the slowest of the runs, a stand-in for p99. Allocations are per op.\n\n")
	fmt.Fprintf(w, "| Benchmark | per op | median | slowest | budget | allocs | budget | |\n")
	fmt.Fprintf(w, "|---|---|---:|---:|---:|---:|---:|---|\n")
	for _, e := range b.Benchmarks {
		byName[e.Name] = e
		s := head[e.Name]
		if s == nil || len(s.Ns) == 0 {
			fails = append(fails, fmt.Sprintf("%s: no result; rename the budget entry if the benchmark was renamed", e.Name))
			fmt.Fprintf(w, "| %s | %s | - | - | %s | - | %s | ❌ missing |\n", e.Name, e.Per, fmtNs(e.NsPerOp), fmtCount(e.AllocsPerOp))
			continue
		}
		worst := slices.Max(s.Ns)
		allocs := math.NaN()
		if len(s.Allocs) > 0 {
			allocs = slices.Max(s.Allocs)
		}
		var over []string
		if worst > e.NsPerOp {
			over = append(over, "time")
			fails = append(fails, fmt.Sprintf("%s: slowest run %s is over the %s budget", e.Name, fmtNs(worst), fmtNs(e.NsPerOp)))
		}
		if math.IsNaN(allocs) || allocs > e.AllocsPerOp {
			over = append(over, "allocs")
			fails = append(fails, fmt.Sprintf("%s: %s allocs/op, budget %s (run with -benchmem)", e.Name, fmtCount(allocs), fmtCount(e.AllocsPerOp)))
		}
		status := "✅"
		if len(over) > 0 {
			status = "❌ " + strings.Join(over, ", ")
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", e.Name, e.Per,
			fmtNs(median(s.Ns)), fmtNs(worst), fmtNs(e.NsPerOp), fmtCount(allocs), fmtCount(e.AllocsPerOp), status)
	}
	var extra []string
	for name := range head {
		if _, ok := byName[name]; !ok {
			extra = append(extra, name)
		}
	}
	slices.Sort(extra)
	if len(extra) > 0 {
		fmt.Fprintf(w, "\nNo budget yet (add them to bench/budget.json): %s\n", strings.Join(extra, ", "))
	}

	fmt.Fprintf(w, "\n## Compared with the base branch\n\n")
	if !compared {
		fmt.Fprintf(w, "No comparison: no base results (a push to main, or the base branch has no benchmarks).\n")
	} else {
		fmt.Fprintf(w, "A hot path benchmark fails on a significant change over +%g%% in time or allocations.\n\n", b.MaxRegressionPct)
		fmt.Fprintf(w, "| Benchmark | unit | change | |\n|---|---|---:|---|\n")
		for _, d := range deltas {
			e, ok := byName[d.Name]
			status := ""
			switch {
			case !ok || !e.Hot:
				status = "not gated"
			case !math.IsNaN(d.Pct) && d.Pct > b.MaxRegressionPct:
				status = "❌"
				fails = append(fails, fmt.Sprintf("%s: %s %s against the base branch (limit +%g%%)", d.Name, d.Unit, d.Delta, b.MaxRegressionPct))
			default:
				status = "✅"
			}
			change := d.Delta
			if change == "" {
				change = "new"
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", d.Name, d.Unit, change, status)
		}
	}

	if len(fails) > 0 {
		fmt.Fprintf(w, "\n## Failures\n\n")
		for _, f := range fails {
			fmt.Fprintf(w, "- %s\n", f)
		}
	}
	return fails
}

// loadBudget reads and checks a budget file. Unknown keys are errors so a
// typo cannot drop a limit.
func loadBudget(path string) (*Budget, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Budget
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if b.MaxRegressionPct <= 0 {
		return nil, fmt.Errorf("%s: max_regression_pct must be positive", path)
	}
	return &b, nil
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("benchgate", flag.ContinueOnError)
	budgetPath := fs.String("budget", "bench/budget.json", "budget file")
	headPath := fs.String("head", "", "go test -bench output of the change (required)")
	csvPath := fs.String("compare", "", "benchstat -format csv output, base against head (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *headPath == "" {
		return errors.New("-head is required")
	}
	b, err := loadBudget(*budgetPath)
	if err != nil {
		return err
	}
	hf, err := os.Open(*headPath)
	if err != nil {
		return err
	}
	head, err := ParseBench(hf)
	hf.Close()
	if err != nil {
		return err
	}
	var deltas []Delta
	compared := false
	if *csvPath != "" {
		cf, err := os.Open(*csvPath)
		if err != nil {
			return err
		}
		deltas, err = ParseBenchstatCSV(cf)
		cf.Close()
		if err != nil {
			return err
		}
		compared = true
	}
	if fails := Check(stdout, b, head, deltas, compared); len(fails) > 0 {
		return fmt.Errorf("%d benchmark check(s) failed", len(fails))
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "benchgate:", err)
		os.Exit(1)
	}
}

# Benchmarks and the performance budget

pisentry runs on a 2 GB Pi next to the workloads it watches, so the event path has a budget. `go test -bench` covers it:

| Benchmark | Package | One op |
|---|---|---|
| `SanitizeEvent/clean`, `SanitizeEvent/hostile` | `internal/engine` | sanitize one event: plain strings, or a forged sudo line with escapes, a bidi override, invalid UTF-8 and a 600-byte command |
| `EncodeEvent` | `internal/engine` | JSON-encode one enriched event to the JSON sink |
| `Emit` | `internal/engine` | one event through `Engine.Emit`: ID, sanitize, enrich, cooldown, metrics, JSON sink |
| `RuleMatch/{process,sudo}/rules={75,500,1000}` | `internal/rules` | evaluate one event against that many rules of its source |
| `ProcScan/{lazy,eager}` | `internal/detect` | one `ProcWatch.Scan` over 180 processes |

`RuleMatch` generates its rules (literal and regex conditions on `process.cmdline`, `process.comm` and the sudo `log.msg`, some case-insensitive, some with exceptions), so it does not move when the shipped rules or packs change. `ProcScan` reads a fixture `/proc` from `internal/detect/testdata/proc`, 20 processes from a k3s node copied nine times. Symlinks (`exe`, `fd/*`) are listed in `testdata/proc/links` and created when the benchmark copies the tree, because not every checkout can store them. `eager` adds a rule on `process.parent_comm`, which makes the scan read the uid and parent of every process.

## Running them

```bash
make bench
```

runs every benchmark 10 times and checks the results against [budget.json](budget.json). To compare two commits yourself:

```bash
go test -run '^$' -bench . -benchmem -count 10 ./internal/engine ./internal/rules ./internal/detect > new.txt
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e old.txt new.txt
```

benchstat is a CI tool. It is fetched with `go run` and never enters `go.mod`.

## In CI

[`.github/workflows/bench.yml`](../.github/workflows/bench.yml) runs on the native arm64 runner for every pull request that touches Go code, and on main. On a pull request it runs the base branch and the change in five alternating rounds on the same machine, compares them with benchstat, and runs [benchgate](benchgate/main.go), which fails the job when:

- a benchmark marked `hot` gets slower, or allocates more, by more than `max_regression_pct` (20%) and benchstat finds the change significant
- the slowest run of any benchmark is over its `ns_per_op`, or its allocations are over `allocs_per_op`
- a benchmark in the budget has no result, which usually means it was renamed

The report, with the full benchstat table, is the job summary. Raw results are kept as the `bench-results` artifact for 30 days.

The time limit is checked against the slowest of the 10 runs, a stand-in for p99: Go benchmarks report a mean per run, not a per-event distribution. Allocations per op do not depend on the machine, so their limits sit close to the measured values. Time limits leave room for runner noise; the 20% comparison with the base branch catches the smaller regressions.

## Updating the budget

Change [budget.json](budget.json) in the same pull request as the change that needs it, and say why in the description. Take the numbers from the job summary of that pull request (arm64), not from a laptop:

- `allocs_per_op`: the new value, plus about 10%
- `ns_per_op`: about twice the new slowest run
- a new benchmark gets an entry; benchgate lists any benchmark without one in the summary
- `hot: true` puts a benchmark under the 20% gate. It is for code that runs once per event. `ProcScan` is not hot: it runs once per poll and its file reads are noisy on shared runners, so only its absolute budget applies

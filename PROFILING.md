# Profiling and Optimization Workflow

This guide explains how to capture performance profiles, generate flame graphs,
and compare benchmark runs when tuning nitr0g3n.

## 1. Capture CPU and Memory Profiles

Use the new CLI flags to capture CPU and heap profiles while running scans:

```bash
# Profile a scan
nitro --domain example.com --cpuprofile=cpu.prof

# Capture a heap snapshot after the run
nitro --domain example.com --memprofile=mem.prof
```

The CPU profile starts when the scan begins and is flushed when the command
exits. Memory profiles are collected at shutdown after forcing a garbage
collection cycle to ensure a consistent heap snapshot.

Inspect profiles with `go tool pprof`:

```bash
# Explore the profile in an interactive web UI
go tool pprof -http=:8080 cpu.prof
```

## 2. Generate Flame Graphs

Convert pprof output into a flame graph for visual analysis with the provided
helper script. The script expects a CPU or heap profile and optionally the path
to the nitr0g3n binary (required if symbols are missing from the profile).

```bash
scripts/generate_flamegraph.sh cpu.prof cpu.svg ./bin/nitro
```

By default the script looks for `flamegraph.pl` in your `PATH`. Override the
location by setting `FLAMEGRAPH_PL=/path/to/flamegraph.pl`.

## 3. Benchmark Before and After Changes

Use the benchmark harness to gather repeatable measurements. Generate a
baseline, apply your changes, then compare the updated results against the
baseline JSON report.

```bash
# Run benchmarks and save the baseline results
python benchmark/run_benchmarks.py --output benchmark/results/baseline.json

# Make changes, rebuild, then run again against the baseline
python benchmark/run_benchmarks.py \
  --output benchmark/results/after.json \
  --baseline benchmark/results/baseline.json \
  --comparison-output benchmark/results/after_comparison.json
```

The comparison report summarises metric deltas (runtime, QPS, total results) and
highlights regressions directly in the terminal. The JSON file can be archived
for CI enforcement or further analysis.

## 4. Optimization Checklist

1. Capture CPU and memory profiles around the slow path.
2. Use flame graphs to visualise hotspots and prioritise fixes.
3. Record a benchmark baseline before making changes.
4. Apply optimisations and rerun benchmarks with the baseline for comparison.
5. Iterate until regressions are eliminated and improvements are confirmed.

Following this workflow keeps performance investigations data-driven and
repeatable.

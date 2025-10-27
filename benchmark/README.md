# nitr0g3n Benchmark Suite

This directory contains tooling for measuring nitr0g3n performance across a
set of repeatable scenarios. It captures key metrics, generates comparison
charts, and integrates with CI for regression detection.

## Requirements

* Go (for building the `nitro` binary)
* Python 3.10+
* Python dependencies listed in `requirements.txt`

Install Python requirements with:

```bash
pip install -r benchmark/requirements.txt
```

## Running Benchmarks

Benchmarks are defined in `scenarios.yaml`. To execute them against live
infrastructure:

```bash
./benchmark.sh --generate-graphs
```

The script will build the CLI (if needed), run each scenario, and store results
under `benchmark/results/`. Metrics captured include:

* Queries per second
* Total runtime
* Time to first result
* Total discoveries

Graphs are written as PNG files alongside the JSON summary.

### Comparing Runs

To validate performance changes, compare a new run against a saved baseline
report. The comparison output highlights metric deltas and flags regressions:

```bash
python benchmark/run_benchmarks.py \
  --output benchmark/results/latest.json \
  --baseline benchmark/results/baseline.json \
  --comparison-output benchmark/results/compare.json
```

If `--comparison-output` is omitted, the summary defaults to
`benchmark/results/comparison.json`.

### Offline Fixtures

Live benchmarking requires internet access. For CI or offline development you
can replay stored fixtures instead:

```bash
python benchmark/run_benchmarks.py --offline --generate-graphs
```

This produces deterministic results without external network calls and is used
by the CI regression workflow.

## Updating Scenarios

Add or modify benchmark scenarios by editing `scenarios.yaml`. Each scenario
supports the following fields:

* `name` – Human-friendly scenario name (defaults to the domain)
* `domain` – Domain to benchmark
* `mode` – nitr0g3n mode (`passive`, `active`, or `all`)
* `description` – Optional documentation
* `arguments` – Extra CLI flags (list of strings)

## Output Artifacts

Benchmark runs emit a JSON report (default `benchmark/results/latest.json`). The
GitHub Actions workflow uploads rendered graphs as build artifacts for easy
comparison across runs.

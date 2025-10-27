#!/usr/bin/env python3
"""Utility for running nitr0g3n benchmarks across predefined scenarios."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from generate_graphs import generate_graphs

ROOT = Path(__file__).resolve().parent
DEFAULT_SCENARIO_FILE = ROOT / "scenarios.yaml"
DEFAULT_RESULTS_DIR = ROOT / "results"
DEFAULT_RESULTS_FILE = DEFAULT_RESULTS_DIR / "latest.json"
DEFAULT_FIXTURE = ROOT / "fixtures" / "offline_results.json"
DEFAULT_COMPARISON_FILE = DEFAULT_RESULTS_DIR / "comparison.json"

SUMMARY_TOTAL_RE = re.compile(r"Scan complete for .*: (\\d+) subdomains discovered")


class BenchmarkError(RuntimeError):
    """Raised when a benchmark scenario fails."""


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _ensure_binary(binary: Path, rebuild: bool = False) -> Path:
    if binary.exists() and not rebuild:
        return binary

    cmd = ["go", "build", "-o", str(binary), "./cmd/nitro"]
    print(f"[build] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, cwd=ROOT.parent)
    except subprocess.CalledProcessError as exc:  # pragma: no cover - build failure is fatal
        raise BenchmarkError(f"failed to build nitr0g3n binary: {exc}") from exc
    return binary


def _round_value(value: Any, digits: int = 3) -> Any:
    if isinstance(value, float):
        return round(value, digits)
    return value


def _load_results_file(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise BenchmarkError(f"baseline results file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    results = payload.get("results")
    if not isinstance(results, list):
        raise BenchmarkError(f"baseline file {path} does not contain a 'results' array")
    return results


METRIC_DIRECTIONS = {
    "total_time_seconds": "lower",
    "time_to_first_result": "lower",
    "queries_per_second": "higher",
    "total_results": "higher",
}


def _compare_results(
    baseline: List[Dict[str, Any]], current: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    baseline_index = {entry.get("scenario", entry.get("domain")): entry for entry in baseline}
    comparisons: List[Dict[str, Any]] = []

    for entry in current:
        scenario = entry.get("scenario", entry.get("domain"))
        if not scenario:
            continue
        baseline_entry = baseline_index.get(scenario)
        if not baseline_entry:
            continue

        metrics: Dict[str, Dict[str, Any]] = {}
        for metric, direction in METRIC_DIRECTIONS.items():
            current_value = entry.get(metric)
            baseline_value = baseline_entry.get(metric)
            if current_value is None or baseline_value is None:
                continue
            try:
                delta = current_value - baseline_value
            except TypeError:
                continue

            percent_change: Optional[float] = None
            if baseline_value not in (0, 0.0):
                try:
                    percent_change = (delta / baseline_value) * 100
                except TypeError:
                    percent_change = None

            if isinstance(delta, float):
                delta_rounded: Any = round(delta, 3)
            else:
                delta_rounded = delta

            if percent_change is not None:
                percent_change = round(percent_change, 2)

            if direction == "lower":
                if delta_rounded < 0:
                    trend = "improved"
                elif delta_rounded > 0:
                    trend = "regressed"
                else:
                    trend = "unchanged"
            else:
                if delta_rounded > 0:
                    trend = "improved"
                elif delta_rounded < 0:
                    trend = "regressed"
                else:
                    trend = "unchanged"

            metrics[metric] = {
                "baseline": _round_value(baseline_value),
                "current": _round_value(current_value),
                "delta": delta_rounded,
                "percent_change": percent_change,
                "trend": trend,
            }

        if not metrics:
            continue

        if any(details["trend"] == "regressed" for details in metrics.values()):
            status = "regressed"
        elif any(details["trend"] == "improved" for details in metrics.values()):
            status = "improved"
        else:
            status = "unchanged"

        comparisons.append({"scenario": scenario, "metrics": metrics, "status": status})

    return comparisons


def _print_comparisons(comparisons: List[Dict[str, Any]]) -> None:
    if not comparisons:
        print("[benchmark] No overlapping scenarios found for baseline comparison")
        return

    header = f"{'Scenario':25} {'Metric':22} {'Baseline':>10} {'Current':>10} {'Delta':>10} {'Change':>9} {'Trend':>10}"
    print("[benchmark] Benchmark comparison against baseline:")
    print(header)
    print("-" * len(header))
    for entry in comparisons:
        scenario = entry["scenario"]
        status = entry.get("status", "")
        first_line = True
        for metric, details in entry["metrics"].items():
            percent = details.get("percent_change")
            change = f"{percent:.2f}%" if isinstance(percent, float) else "n/a"
            line = f"{metric:22} {_round_value(details['baseline']):>10} {_round_value(details['current']):>10} {details['delta']:>10} {change:>9} {details['trend']:>10}"
            if first_line:
                print(f"{scenario:25} {line} [{status}]")
                first_line = False
            else:
                print(f"{'':25} {line}")
    print()


def _load_scenarios(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise BenchmarkError(f"scenario file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    scenarios = data.get("scenarios", [])
    if not isinstance(scenarios, list) or not scenarios:
        raise BenchmarkError("no scenarios defined in scenarios.yaml")
    normalised = []
    for entry in scenarios:
        if not isinstance(entry, dict):
            continue
        domain = entry.get("domain")
        if not domain:
            raise BenchmarkError("scenario is missing required 'domain' field")
        normalised.append(
            {
                "name": entry.get("name", domain),
                "domain": domain,
                "mode": entry.get("mode", "passive"),
                "description": entry.get("description", ""),
                "arguments": entry.get("arguments", []),
            }
        )
    return normalised


def _read_stream(stream, callback):
    for line in iter(stream.readline, ""):
        callback(line.rstrip("\n"))
    stream.close()


def _run_single(binary: Path, scenario: Dict[str, Any], timeout: Optional[int]) -> Dict[str, Any]:
    domain = scenario["domain"]
    mode = scenario.get("mode", "passive")

    cmd = [
        str(binary),
        "--domain",
        domain,
        "--mode",
        mode,
        "--format",
        "txt",
        "--log-level",
        "info",
    ]
    for arg in scenario.get("arguments", []):
        if not isinstance(arg, str):
            continue
        cmd.append(arg)

    print(f"[benchmark] Running {' '.join(cmd)}")
    start = time.perf_counter()
    stdout_records: List[str] = []
    stderr_lines: List[str] = []
    first_result: Optional[float] = None
    summary_total: Optional[int] = None

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        cwd=ROOT.parent,
    )

    stdout_lock = threading.Lock()

    def handle_stdout(line: str) -> None:
        nonlocal first_result
        if not line:
            return
        with stdout_lock:
            stdout_records.append(line)
        if line.startswith("Subdomain:") and first_result is None:
            first_result = time.perf_counter() - start

    def handle_stderr(line: str) -> None:
        nonlocal summary_total
        if not line:
            return
        stderr_lines.append(line)
        match = SUMMARY_TOTAL_RE.search(line)
        if match:
            summary_total = int(match.group(1))

    stdout_thread = threading.Thread(target=_read_stream, args=(process.stdout, handle_stdout))
    stderr_thread = threading.Thread(target=_read_stream, args=(process.stderr, handle_stderr))
    stdout_thread.start()
    stderr_thread.start()

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout_thread.join()
        stderr_thread.join()
        raise BenchmarkError(f"benchmark timed out for domain {domain}")

    stdout_thread.join()
    stderr_thread.join()
    end = time.perf_counter()
    duration = end - start

    exit_code = process.returncode
    if exit_code != 0:
        error_tail = "\n".join(stderr_lines[-10:])
        raise BenchmarkError(
            f"nitr0g3n exited with code {exit_code} for domain {domain}.\n{error_tail}"
        )

    total_results = sum(1 for line in stdout_records if line.startswith("Subdomain:"))
    if summary_total is not None and summary_total != total_results:
        print(
            f"[benchmark] Warning: summary reported {summary_total} results but parsed {total_results}",
            file=sys.stderr,
        )
        total_results = summary_total

    queries_per_second = 0.0
    if duration > 0 and total_results:
        queries_per_second = total_results / duration

    return {
        "scenario": scenario.get("name", domain),
        "domain": domain,
        "mode": mode,
        "description": scenario.get("description", ""),
        "timestamp": _utc_timestamp(),
        "total_time_seconds": round(duration, 3),
        "queries_per_second": round(queries_per_second, 3),
        "time_to_first_result": round(first_result, 3) if first_result is not None else None,
        "total_results": total_results,
        "command": cmd,
        "stderr": stderr_lines,
    }


def _load_offline_results(scenarios: Iterable[Dict[str, Any]], fixture_path: Path) -> List[Dict[str, Any]]:
    if not fixture_path.exists():
        raise BenchmarkError(f"offline fixture not found: {fixture_path}")
    with fixture_path.open("r", encoding="utf-8") as handle:
        fixture_data = json.load(handle)

    lookup = {entry["domain"]: entry for entry in fixture_data}
    results: List[Dict[str, Any]] = []
    for scenario in scenarios:
        domain = scenario["domain"]
        template = lookup.get(domain)
        if not template:
            raise BenchmarkError(f"no offline fixture available for domain {domain}")
        entry = {
            "scenario": scenario.get("name", domain),
            "domain": domain,
            "mode": scenario.get("mode", "passive"),
            "description": scenario.get("description", ""),
            "timestamp": _utc_timestamp(),
            "total_time_seconds": template.get("total_time_seconds", 0.0),
            "queries_per_second": template.get("queries_per_second", 0.0),
            "time_to_first_result": template.get("time_to_first_result"),
            "total_results": template.get("total_results", 0),
            "command": template.get("command", []),
            "stderr": template.get("stderr", []),
            "offline": True,
        }
        results.append(entry)
    return results


def run_benchmarks(
    scenario_file: Path,
    output_file: Path,
    binary_path: Optional[Path],
    rebuild: bool,
    timeout: Optional[int],
    offline: bool,
    fixture_path: Path,
    generate_graphs_flag: bool,
    baseline_file: Optional[Path],
    comparison_output: Optional[Path],
) -> List[Dict[str, Any]]:
    scenarios = _load_scenarios(scenario_file)

    if offline:
        results = _load_offline_results(scenarios, fixture_path)
    else:
        binary = _ensure_binary(binary_path or (ROOT.parent / "bin" / "nitro"), rebuild=rebuild)
        results = []
        for scenario in scenarios:
            try:
                result = _run_single(binary, scenario, timeout)
            except BenchmarkError as exc:
                print(f"[benchmark] {exc}", file=sys.stderr)
                result = {
                    "scenario": scenario.get("name", scenario["domain"]),
                    "domain": scenario["domain"],
                    "mode": scenario.get("mode", "passive"),
                    "description": scenario.get("description", ""),
                    "timestamp": _utc_timestamp(),
                    "error": str(exc),
                }
            results.append(result)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, Any] = {"generated_at": _utc_timestamp(), "results": results}

    comparisons: Optional[List[Dict[str, Any]]] = None
    if baseline_file is not None:
        baseline_results = _load_results_file(baseline_file)
        comparisons = _compare_results(baseline_results, results)
        payload["baseline"] = {
            "path": str(baseline_file),
            "generated_at": _utc_timestamp(),
        }

    with output_file.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    if generate_graphs_flag:
        try:
            generate_graphs(results, DEFAULT_RESULTS_DIR)
        except Exception as exc:  # pragma: no cover - graph generation failure shouldn't fail run
            print(f"[benchmark] Failed to generate graphs: {exc}", file=sys.stderr)

    if comparisons is not None:
        comparison_path = comparison_output or DEFAULT_COMPARISON_FILE
        comparison_path.parent.mkdir(parents=True, exist_ok=True)
        with comparison_path.open("w", encoding="utf-8") as handle:
            json.dump({"generated_at": _utc_timestamp(), "comparisons": comparisons}, handle, indent=2)
        _print_comparisons(comparisons)
        print(f"[benchmark] Comparison report written to {comparison_path}")

    return results


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run nitr0g3n benchmark scenarios")
    parser.add_argument(
        "--scenario-file",
        type=Path,
        default=DEFAULT_SCENARIO_FILE,
        help="Path to the benchmark scenario definition file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_RESULTS_FILE,
        help="Path to write JSON benchmark results",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=None,
        help="Path to the nitr0g3n binary (defaults to ./bin/nitro)",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Force rebuilding the nitr0g3n binary before running benchmarks",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Optional timeout in seconds for each scenario",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use offline fixtures instead of executing real benchmarks",
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        default=DEFAULT_FIXTURE,
        help="Path to the offline fixture JSON file",
    )
    parser.add_argument(
        "--generate-graphs",
        action="store_true",
        help="Generate comparison graphs after benchmarks complete",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Path to a previous benchmark JSON file for comparison",
    )
    parser.add_argument(
        "--comparison-output",
        type=Path,
        default=None,
        help="Path to write the comparison JSON report (defaults to benchmark/results/comparison.json)",
    )

    args = parser.parse_args(argv)

    try:
        run_benchmarks(
            scenario_file=args.scenario_file,
            output_file=args.output,
            binary_path=args.binary,
            rebuild=args.rebuild,
            timeout=args.timeout,
            offline=args.offline,
            fixture_path=args.fixture,
            generate_graphs_flag=args.generate_graphs,
            baseline_file=args.baseline,
            comparison_output=args.comparison_output,
        )
    except BenchmarkError as exc:
        print(f"[benchmark] {exc}", file=sys.stderr)
        return os.EX_DATAERR
    return os.EX_OK


if __name__ == "__main__":
    sys.exit(main())

"""Generate benchmark comparison graphs."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable, List, Mapping

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEFAULT_WIDTH = 10
DEFAULT_HEIGHT = 6


def _normalise_results(results: Iterable[Mapping[str, object]]) -> List[Mapping[str, object]]:
    return [result for result in results if isinstance(result, Mapping) and not result.get("error")]


def _plot_metric(results: List[Mapping[str, object]], metric: str, title: str, ylabel: str, output_path: Path) -> None:
    if not results:
        return

    labels = [str(entry.get("scenario", entry.get("domain", "unknown"))) for entry in results]
    values = [entry.get(metric, 0) or 0 for entry in results]

    plt.figure(figsize=(DEFAULT_WIDTH, DEFAULT_HEIGHT))
    bars = plt.bar(labels, values, color="#4285F4")
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=15, ha="right")
    plt.grid(axis="y", linestyle="--", alpha=0.4)

    for bar, value in zip(bars, values):
        height = bar.get_height()
        if math.isnan(height):
            continue
        plt.text(bar.get_x() + bar.get_width() / 2, height, f"{value}", ha="center", va="bottom")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def generate_graphs(results: Iterable[Mapping[str, object]], output_dir: Path) -> None:
    """Create comparison graphs for benchmark results."""
    filtered = _normalise_results(results)
    if not filtered:
        return

    metrics = [
        ("total_time_seconds", "Total Benchmark Duration", "Seconds", "total_time.png"),
        ("queries_per_second", "Queries Per Second", "queries/sec", "queries_per_second.png"),
        ("time_to_first_result", "Time To First Result", "Seconds", "time_to_first_result.png"),
    ]

    for metric, title, ylabel, filename in metrics:
        _plot_metric(filtered, metric, title, ylabel, output_dir / filename)

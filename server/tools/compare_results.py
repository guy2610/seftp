#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Any


def load_report(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def stages_by_load(report: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {
        int(stage["load"]): stage
        for stage in report.get("stages", [])
    }


def pct_change(old: float, new: float) -> str:
    if old == 0:
        if new == 0:
            return "0.0%"
        return "n/a"
    change = ((new - old) / old) * 100
    return f"{change:+.1f}%"


def metric(stage: dict[str, Any], path: list[str], default: float = 0.0) -> float:
    cur: Any = stage
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    try:
        return float(cur)
    except (TypeError, ValueError):
        return default


def print_metric(label: str, old: float, new: float, unit: str = "") -> None:
    print(f"  {label:<18} {old:>10.2f}{unit} -> {new:>10.2f}{unit} ({pct_change(old, new)})")


def print_count(label: str, old: int, new: int) -> None:
    delta = new - old
    print(f"  {label:<18} {old:>10} -> {new:>10} ({delta:+d})")


def compare_stage(load: int, baseline_stage: dict[str, Any], candidate_stage: dict[str, Any]) -> None:
    print(f"\nload {load}:")

    print_metric(
        "avg_ms",
        metric(baseline_stage, ["summary", "latency_ms", "avg"]),
        metric(candidate_stage, ["summary", "latency_ms", "avg"]),
        "ms",
    )
    print_metric(
        "p95_ms",
        metric(baseline_stage, ["summary", "latency_ms", "p95"]),
        metric(candidate_stage, ["summary", "latency_ms", "p95"]),
        "ms",
    )
    print_metric(
        "p99_ms",
        metric(baseline_stage, ["summary", "latency_ms", "p99"]),
        metric(candidate_stage, ["summary", "latency_ms", "p99"]),
        "ms",
    )
    print_metric(
        "throughput",
        metric(baseline_stage, ["throughput_ops_per_s"]),
        metric(candidate_stage, ["throughput_ops_per_s"]),
        " ops/s",
    )

    print_count(
        "ok",
        int(metric(baseline_stage, ["summary", "ok"])),
        int(metric(candidate_stage, ["summary", "ok"])),
    )
    print_count(
        "rejected",
        int(metric(baseline_stage, ["summary", "rejected"])),
        int(metric(candidate_stage, ["summary", "rejected"])),
    )
    print_count(
        "failed",
        int(metric(baseline_stage, ["summary", "failed"])),
        int(metric(candidate_stage, ["summary", "failed"])),
    )

    baseline_timings = baseline_stage.get("summary", {}).get("timings_ms", {})
    candidate_timings = candidate_stage.get("summary", {}).get("timings_ms", {})

    common_timings = sorted(set(baseline_timings) & set(candidate_timings))
    if common_timings:
        print("  timings avg:")
        for name in common_timings:
            old = metric(baseline_stage, ["summary", "timings_ms", name, "avg"])
            new = metric(candidate_stage, ["summary", "timings_ms", name, "avg"])
            if abs(old) < 0.01 and abs(new) < 0.01:
                continue
            print(f"    {name:<26} {old:>10.2f}ms -> {new:>10.2f}ms ({pct_change(old, new)})")


def compare_reports(baseline_path: Path, candidate_path: Path) -> int:
    baseline = load_report(baseline_path)
    candidate = load_report(candidate_path)

    baseline_stages = stages_by_load(baseline)
    candidate_stages = stages_by_load(candidate)

    common_loads = sorted(set(baseline_stages) & set(candidate_stages))
    if not common_loads:
        print("No matching load stages found between reports.")
        return 1

    print("Comparing benchmark reports")
    print(f"baseline : {baseline_path}")
    print(f"candidate: {candidate_path}")
    print()
    print(f"baseline run_id : {baseline.get('run_id', '-')}")
    print(f"candidate run_id: {candidate.get('run_id', '-')}")
    print(f"mode            : {baseline.get('scenario', {}).get('mode', '-')} -> {candidate.get('scenario', {}).get('mode', '-')}")
    print(f"file_size       : {baseline.get('scenario_params', {}).get('file_size_bytes', '-')} -> {candidate.get('scenario_params', {}).get('file_size_bytes', '-')}")
    print(f"chunk_size      : {baseline.get('scenario_params', {}).get('chunk_size_bytes', '-')} -> {candidate.get('scenario_params', {}).get('chunk_size_bytes', '-')}")
    print(f"rsa_key_pool    : {baseline.get('scenario_params', {}).get('rsa_key_pool_size', '-')} -> {candidate.get('scenario_params', {}).get('rsa_key_pool_size', '-')}")

    for load in common_loads:
        compare_stage(load, baseline_stages[load], candidate_stages[load])

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare two SEFTP load-test JSON reports."
    )
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return compare_reports(args.baseline, args.candidate)


if __name__ == "__main__":
    raise SystemExit(main())
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR / "results"
OUTPUT_DIR = SCRIPT_DIR / "plots"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_run(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_series(run: dict[str, Any]) -> dict[str, list[float]]:
    loads: list[float] = []
    latency_avg: list[float] = []
    latency_p95: list[float] = []
    throughput: list[float] = []
    success_rate: list[float] = []
    rejected_rate: list[float] = []
    failure_rate: list[float] = []
    cpu_peak: list[float] = []
    rss_peak: list[float] = []

    for stage in run["stages"]:
        loads.append(stage["load"])
        latency_avg.append(stage["summary"]["latency_ms"]["avg"])
        latency_p95.append(stage["summary"]["latency_ms"]["p95"])
        throughput.append(stage["throughput_ops_per_s"])
        success_rate.append(stage["summary"]["success_rate"] * 100.0)
        rejected_rate.append(stage["summary"]["rejected_rate"] * 100.0)
        failure_rate.append(stage["summary"]["failure_rate"] * 100.0)
        cpu_peak.append(stage["server_metrics"]["peak"]["cpu_percent"])
        rss_peak.append(stage["server_metrics"]["peak"]["rss_mb"])

    return {
        "loads": loads,
        "latency_avg": latency_avg,
        "latency_p95": latency_p95,
        "throughput": throughput,
        "success_rate": success_rate,
        "rejected_rate": rejected_rate,
        "failure_rate": failure_rate,
        "cpu_peak": cpu_peak,
        "rss_peak": rss_peak,
    }


def scenario_title(run: dict[str, Any]) -> str:
    mode = run["scenario"]["mode"]
    ramp = run["scenario"]["ramp"]
    return f"{mode} | ramp={ramp}"


def plot_latency(run: dict[str, Any], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    s = extract_series(run)
    plt.figure(figsize=(8, 5))
    plt.plot(s["loads"], s["latency_avg"], marker="o", label="avg")
    plt.plot(s["loads"], s["latency_p95"], marker="o", label="p95")
    plt.xlabel("Load")
    plt.ylabel("Latency (ms)")
    plt.title(f"{scenario_title(run)} | Latency")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_throughput(run: dict[str, Any], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    s = extract_series(run)
    plt.figure(figsize=(8, 5))
    plt.plot(s["loads"], s["throughput"], marker="o")
    plt.xlabel("Load")
    plt.ylabel("Throughput (ops/s)")
    plt.title(f"{scenario_title(run)} | Throughput")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_outcomes(run: dict[str, Any], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    s = extract_series(run)
    plt.figure(figsize=(8, 5))
    plt.plot(s["loads"], s["success_rate"], marker="o", label="success %")
    plt.plot(s["loads"], s["rejected_rate"], marker="o", label="rejected %")
    plt.plot(s["loads"], s["failure_rate"], marker="o", label="failed %")
    plt.xlabel("Load")
    plt.ylabel("Rate (%)")
    plt.title(f"{scenario_title(run)} | Outcomes")
    plt.ylim(0, 100)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_cpu(run: dict[str, Any], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    s = extract_series(run)
    plt.figure(figsize=(8, 5))
    plt.plot(s["loads"], s["cpu_peak"], marker="o")
    plt.xlabel("Load")
    plt.ylabel("CPU peak (%)")
    plt.title(f"{scenario_title(run)} | CPU Peak")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_rss(run: dict[str, Any], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    s = extract_series(run)
    plt.figure(figsize=(8, 5))
    plt.plot(s["loads"], s["rss_peak"], marker="o")
    plt.xlabel("Load")
    plt.ylabel("RSS peak (MB)")
    plt.title(f"{scenario_title(run)} | RSS Peak")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def slug_for_run(run: dict[str, Any]) -> str:
    return run["scenario"]["mode"]


def generate_all(run_path: Path) -> None:
    run = load_run(run_path)
    slug = slug_for_run(run)

    plot_latency(run, OUTPUT_DIR / f"{slug}_latency.png")
    plot_throughput(run, OUTPUT_DIR / f"{slug}_throughput.png")
    plot_outcomes(run, OUTPUT_DIR / f"{slug}_outcomes.png")
    plot_cpu(run, OUTPUT_DIR / f"{slug}_cpu.png")
    plot_rss(run, OUTPUT_DIR / f"{slug}_rss.png")

    print(f"Generated plots for {run_path.name}")

def extract_latency_series(run: dict[str, Any], latency_key: str = "p95") -> tuple[list[float], list[float]]:
    loads: list[float] = []
    values: list[float] = []

    for stage in run["stages"]:
        loads.append(stage["load"])
        values.append(stage["summary"]["latency_ms"][latency_key])

    return loads, values


def plot_latency_comparison(
    register_run: dict[str, Any],
    relogin_run: dict[str, Any],
    upload_run: dict[str, Any],
    out_path: Path,
    latency_key: str = "p95",
) -> None:
    import matplotlib.pyplot as plt

    reg_loads, reg_vals = extract_latency_series(register_run, latency_key)
    rel_loads, rel_vals = extract_latency_series(relogin_run, latency_key)
    up_loads, up_vals = extract_latency_series(upload_run, latency_key)

    plt.figure(figsize=(9, 6))
    plt.plot(reg_loads, reg_vals, marker="o", label=f"register {latency_key}")
    plt.plot(rel_loads, rel_vals, marker="o", label=f"relogin {latency_key}")
    plt.plot(up_loads, up_vals, marker="o", label=f"upload {latency_key}")

    plt.yscale("log")

    plt.xlabel("Load")
    plt.ylabel("Latency (ms)")
    plt.title(f"Latency Comparison Across Scenarios ({latency_key})")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def extract_upload_size_series(run: dict[str, Any]) -> tuple[int, dict[str, list[float]]]:
    size_bytes = run["scenario_params"]["file_size_bytes"]
    s = extract_series(run)
    return size_bytes, s
def extract_mixed_operation_series(run: dict[str, Any], operation: str) -> dict[str, list[float]]:
    loads: list[float] = []
    latency_avg: list[float] = []
    latency_p95: list[float] = []
    success_rate: list[float] = []
    rejected_rate: list[float] = []
    failure_rate: list[float] = []

    for stage in run["stages"]:
        ops = stage.get("per_operation_summaries")
        if not ops or operation not in ops:
            continue

        op = ops[operation]
        loads.append(stage["load"])
        latency_avg.append(op["latency_ms"]["avg"])
        latency_p95.append(op["latency_ms"]["p95"])
        success_rate.append(op["success_rate"] * 100.0)
        rejected_rate.append(op["rejected_rate"] * 100.0)
        failure_rate.append(op["failure_rate"] * 100.0)

    return {
        "loads": loads,
        "latency_avg": latency_avg,
        "latency_p95": latency_p95,
        "success_rate": success_rate,
        "rejected_rate": rejected_rate,
        "failure_rate": failure_rate,
    }
def human_file_size(size_bytes: int) -> str:
    if size_bytes >= 1_000_000:
        return f"{size_bytes / 1_000_000:.0f}MB"
    if size_bytes >= 1_000:
        return f"{size_bytes / 1_000:.0f}KB"
    return f"{size_bytes}B"

def plot_upload_size_latency_comparison(runs: list[dict[str, Any]], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    max_y = 0.0
    for run in runs:
        size_bytes, s = extract_upload_size_series(run)
        label = human_file_size(size_bytes)
        plt.plot(s["loads"], s["latency_p95"], marker="o", markersize=8, label=label)
        max_y = max(max_y, max(s["latency_p95"]))

    plt.axvline(x=25, linestyle="--", alpha=0.6)
    plt.text(25.5, max_y * 0.8, "capacity boundary", rotation=90)

    plt.yscale("log")
    plt.xlabel("Load")
    plt.ylabel("p95 Latency (ms) [log scale]")
    plt.title("Upload p95 Latency by File Size")
    plt.legend(title="File size")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def plot_upload_size_throughput_comparison(runs: list[dict[str, Any]], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    for run in runs:
        size_bytes, s = extract_upload_size_series(run)
        label = human_file_size(size_bytes)
        plt.plot(s["loads"], s["throughput"], marker="o", markersize=8, label=label)

        peak_idx = max(range(len(s["throughput"])), key=lambda i: s["throughput"][i])
        peak_load = s["loads"][peak_idx]
        peak_val = s["throughput"][peak_idx]
        plt.annotate("peak", (peak_load, peak_val), textcoords="offset points", xytext=(5, 5))

    plt.xlabel("Load")
    plt.ylabel("Throughput (ops/s)")
    plt.title("Upload Throughput by File Size")
    plt.legend(title="File size")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def plot_upload_size_rejected_comparison(runs: list[dict[str, Any]], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    for run in runs:
        size_bytes, s = extract_upload_size_series(run)
        label = human_file_size(size_bytes)
        plt.plot(s["loads"], s["rejected_rate"], marker="o", label=label)

    plt.xlabel("Load")
    plt.ylabel("Rejected Rate (%)")
    plt.title("Upload Rejected Rate by File Size")
    plt.ylim(0, 100)
    plt.legend(title="File size")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_upload_size_overload_comparison(runs: list[dict[str, Any]], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=True)

    for run in runs:
        size_bytes, s = extract_upload_size_series(run)
        label = human_file_size(size_bytes)

        axes[0].plot(s["loads"], s["rejected_rate"], marker="o", markersize=8, label=label)
        axes[1].plot(s["loads"], s["failure_rate"], marker="o", markersize=8, label=label)

    axes[0].set_xlabel("Load")
    axes[0].set_ylabel("Rate (%)")
    axes[0].set_title("Rejected Rate by File Size")
    axes[0].set_ylim(0, 100)
    axes[0].grid(True, alpha=0.3)

    axes[1].set_xlabel("Load")
    axes[1].set_title("Failure Rate by File Size")
    axes[1].set_ylim(0, 100)
    axes[1].grid(True, alpha=0.3)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, title="File size", loc="upper right")
    fig.suptitle("Upload Overload Behavior by File Size")
    fig.tight_layout()
    plt.savefig(out_path)
    plt.close()
def plot_upload_size_rss_comparison(runs: list[dict[str, Any]], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    max_rss = 0.0
    for run in runs:
        size_bytes, s = extract_upload_size_series(run)
        label = human_file_size(size_bytes)
        plt.plot(s["loads"], s["rss_peak"], marker="o", markersize=8, label=label)
        max_rss = max(max_rss, max(s["rss_peak"]))

    plt.ylim(0, max_rss * 1.2)
    plt.xlabel("Load")
    plt.ylabel("RSS Peak (MB)")
    plt.title("Upload RSS Peak by File Size")
    plt.legend(title="File size")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def plot_mixed_operation_latency(run: dict[str, Any], out_path: Path, latency_key: str = "p95") -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    for operation in ("register", "relogin", "upload"):
        s = extract_mixed_operation_series(run, operation)
        if not s["loads"]:
            continue

        values = s["latency_p95"] if latency_key == "p95" else s["latency_avg"]
        plt.plot(s["loads"], values, marker="o", label=operation)

    plt.xlabel("Load")
    plt.ylabel("Latency (ms)")
    plt.title(f"{scenario_title(run)} | Mixed Per-Operation Latency ({latency_key})")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_mixed_operation_outcomes(run: dict[str, Any], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    for operation in ("register", "relogin", "upload"):
        s = extract_mixed_operation_series(run, operation)
        if not s["loads"]:
            continue

        plt.plot(s["loads"], s["rejected_rate"], marker="o", label=f"{operation} rejected %")

    plt.xlabel("Load")
    plt.ylabel("Rejected Rate (%)")
    plt.title(f"{scenario_title(run)} | Mixed Per-Operation Rejected Rate")
    plt.ylim(0, 100)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def plot_mixed_operation_success(run: dict[str, Any], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    for operation in ("register", "relogin", "upload"):
        s = extract_mixed_operation_series(run, operation)
        if not s["loads"]:
            continue

        plt.plot(s["loads"], s["success_rate"], marker="o", label=f"{operation} success %")

    plt.xlabel("Load")
    plt.ylabel("Success Rate (%)")
    plt.title(f"{scenario_title(run)} | Mixed Per-Operation Success Rate")
    plt.ylim(0, 100)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def plot_mixed_upload_latency_by_size(runs: list[dict[str, Any]], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    for run in runs:
        size_bytes = run["scenario_params"]["file_size_bytes"]
        label = human_file_size(size_bytes)

        s = extract_mixed_operation_series(run, "upload")
        if not s["loads"]:
            continue

        plt.plot(s["loads"], s["latency_p95"], marker="o", markersize=8, label=label)

    plt.xlabel("Load")
    plt.ylabel("Upload p95 Latency (ms)")
    plt.title("Mixed Upload p95 Latency by File Size")
    plt.legend(title="File size")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_mixed_upload_rejected_by_size(runs: list[dict[str, Any]], out_path: Path) -> None:
    import matplotlib.pyplot as plt

    plt.figure(figsize=(9, 6))

    for run in runs:
        size_bytes = run["scenario_params"]["file_size_bytes"]
        label = human_file_size(size_bytes)

        s = extract_mixed_operation_series(run, "upload")
        if not s["loads"]:
            continue

        plt.plot(s["loads"], s["rejected_rate"], marker="o", markersize=8, label=label)

    plt.xlabel("Load")
    plt.ylabel("Upload Rejected Rate (%)")
    plt.title("Mixed Upload Rejected Rate by File Size")
    plt.ylim(0, 100)
    plt.legend(title="File size")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def stages_by_load(run: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {
        int(stage["load"]): stage
        for stage in run.get("stages", [])
    }


def common_loads(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[int]:
    baseline_loads = set(stages_by_load(baseline))
    candidate_loads = set(stages_by_load(candidate))
    return sorted(baseline_loads & candidate_loads)


def latency_values_by_load(
    run: dict[str, Any],
    loads: list[int],
    latency_key: str,
) -> list[float]:
    by_load = stages_by_load(run)
    return [
        by_load[load]["summary"]["latency_ms"][latency_key]
        for load in loads
    ]


def timing_avg_values_by_load(
    run: dict[str, Any],
    loads: list[int],
    timing_key: str,
) -> list[float]:
    by_load = stages_by_load(run)
    values: list[float] = []

    for load in loads:
        timing = (
            by_load[load]
            .get("summary", {})
            .get("timings_ms", {})
            .get(timing_key)
        )
        values.append(0.0 if timing is None else float(timing.get("avg", 0.0)))

    return values


def outcome_values_by_load(
    run: dict[str, Any],
    loads: list[int],
    key: str,
) -> list[float]:
    by_load = stages_by_load(run)
    return [
        float(by_load[load]["summary"][key])
        for load in loads
    ]


def describe_report(run: dict[str, Any]) -> str:
    scenario = run.get("scenario", {})
    params = run.get("scenario_params", {})

    mode = scenario.get("mode", "unknown")
    file_size = params.get("file_size_bytes")
    chunk_size = params.get("chunk_size_bytes")
    rsa_pool = params.get("rsa_key_pool_size")

    parts = [str(mode)]

    if file_size is not None:
        parts.append(f"file={human_file_size(int(file_size))}")

    if chunk_size is not None:
        parts.append(f"chunk={chunk_size}")

    if rsa_pool is not None:
        parts.append(f"rsa_pool={rsa_pool}")

    return " | ".join(parts)


def plot_stage8_latency_comparison(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    loads = common_loads(baseline, candidate)
    if not loads:
        raise ValueError("No common load stages found")

    plt.figure(figsize=(9, 6))

    plt.plot(
        loads,
        latency_values_by_load(baseline, loads, "avg"),
        marker="o",
        label="baseline avg",
    )
    plt.plot(
        loads,
        latency_values_by_load(candidate, loads, "avg"),
        marker="o",
        label="candidate avg",
    )
    plt.plot(
        loads,
        latency_values_by_load(baseline, loads, "p95"),
        marker="o",
        linestyle="--",
        label="baseline p95",
    )
    plt.plot(
        loads,
        latency_values_by_load(candidate, loads, "p95"),
        marker="o",
        linestyle="--",
        label="candidate p95",
    )

    plt.xlabel("Load")
    plt.ylabel("Latency (ms)")
    plt.title("Stage 8 Benchmark Latency Comparison")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_stage8_timing_comparison(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    out_path: Path,
    timing_key: str,
) -> None:
    import matplotlib.pyplot as plt

    loads = common_loads(baseline, candidate)
    if not loads:
        raise ValueError("No common load stages found")

    plt.figure(figsize=(9, 6))

    plt.plot(
        loads,
        timing_avg_values_by_load(baseline, loads, timing_key),
        marker="o",
        label=f"baseline {timing_key}",
    )
    plt.plot(
        loads,
        timing_avg_values_by_load(candidate, loads, timing_key),
        marker="o",
        label=f"candidate {timing_key}",
    )

    plt.xlabel("Load")
    plt.ylabel("Timing avg (ms)")
    plt.title(f"Stage 8 Timing Comparison: {timing_key}")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_stage8_outcome_comparison(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    loads = common_loads(baseline, candidate)
    if not loads:
        raise ValueError("No common load stages found")

    plt.figure(figsize=(9, 6))

    plt.plot(
        loads,
        outcome_values_by_load(baseline, loads, "rejected"),
        marker="o",
        label="baseline rejected",
    )
    plt.plot(
        loads,
        outcome_values_by_load(candidate, loads, "rejected"),
        marker="o",
        label="candidate rejected",
    )
    plt.plot(
        loads,
        outcome_values_by_load(baseline, loads, "failed"),
        marker="o",
        linestyle="--",
        label="baseline failed",
    )
    plt.plot(
        loads,
        outcome_values_by_load(candidate, loads, "failed"),
        marker="o",
        linestyle="--",
        label="candidate failed",
    )

    plt.xlabel("Load")
    plt.ylabel("Count")
    plt.title("Stage 8 Rejections and Failures Comparison")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def generate_stage8_compare_plots(
    baseline_path: Path,
    candidate_path: Path,
    out_dir: Path,
) -> None:
    baseline = load_run(baseline_path)
    candidate = load_run(candidate_path)

    out_dir.mkdir(parents=True, exist_ok=True)

    plot_stage8_latency_comparison(
        baseline,
        candidate,
        out_dir / "latency_avg_p95_comparison.png",
    )

    plot_stage8_outcome_comparison(
        baseline,
        candidate,
        out_dir / "outcomes_comparison.png",
    )

    timing_keys = sorted(
        set(
            baseline.get("stages", [{}])[0]
            .get("summary", {})
            .get("timings_ms", {})
            .keys()
        )
        & set(
            candidate.get("stages", [{}])[0]
            .get("summary", {})
            .get("timings_ms", {})
            .keys()
        )
    )

    for timing_key in timing_keys:
        plot_stage8_timing_comparison(
            baseline,
            candidate,
            out_dir / f"timing_{timing_key}.png",
            timing_key,
        )

    print("Generated Stage 8 comparison plots")
    print(f"baseline : {baseline_path}")
    print(f"candidate: {candidate_path}")
    print(f"out_dir  : {out_dir}")
    print(f"baseline : {describe_report(baseline)}")
    print(f"candidate: {describe_report(candidate)}")

def generate_legacy_stage6_plots() -> None:
    register_run = load_run(RESULTS_DIR / "2026-03-29T14-53-45Z_register_ramp.json")
    relogin_run = load_run(RESULTS_DIR / "2026-03-30T09-45-42Z_relogin_ramp.json")
    upload_run = load_run(RESULTS_DIR / "2026-03-30T09-47-58Z_upload_ramp.json")

    upload_100kb = load_run(RESULTS_DIR / "2026-03-30T10-59-28Z_upload_ramp.json")
    upload_1mb = load_run(RESULTS_DIR / "2026-03-30T11-01-19Z_upload_ramp.json")
    upload_5mb = load_run(RESULTS_DIR / "2026-03-30T11-03-05Z_upload_ramp.json")

    mixed_100kb = load_run(RESULTS_DIR / "2026-04-16T13-43-51Z_mixed_ramp.json")
    mixed_1mb = load_run(RESULTS_DIR / "2026-04-16T13-46-20Z_mixed_ramp.json")
    mixed_5mb = load_run(RESULTS_DIR / "2026-04-16T13-48-36Z_mixed_ramp.json")

    generate_all(RESULTS_DIR / "2026-03-29T14-53-45Z_register_ramp.json")
    generate_all(RESULTS_DIR / "2026-03-30T09-45-42Z_relogin_ramp.json")
    generate_all(RESULTS_DIR / "2026-03-30T09-47-58Z_upload_ramp.json")

    plot_latency_comparison(
        register_run,
        relogin_run,
        upload_run,
        OUTPUT_DIR / "comparison_latency_p95.png",
        latency_key="p95",
    )

    upload_size_runs = [upload_100kb, upload_1mb, upload_5mb]

    plot_upload_size_latency_comparison(
        upload_size_runs,
        OUTPUT_DIR / "upload_size_latency_p95.png",
    )
    plot_upload_size_throughput_comparison(
        upload_size_runs,
        OUTPUT_DIR / "upload_size_throughput.png",
    )
    plot_upload_size_rejected_comparison(
        upload_size_runs,
        OUTPUT_DIR / "upload_size_rejected.png",
    )
    plot_upload_size_overload_comparison(
        upload_size_runs,
        OUTPUT_DIR / "upload_size_overload.png",
    )
    plot_upload_size_rss_comparison(
        upload_size_runs,
        OUTPUT_DIR / "upload_size_rss.png",
    )

    plot_mixed_operation_latency(
        mixed_100kb,
        OUTPUT_DIR / "mixed_100kb_operation_latency_p95.png",
        latency_key="p95",
    )
    print("Generated mixed_100kb_operation_latency_p95.png")

    plot_mixed_operation_outcomes(
        mixed_100kb,
        OUTPUT_DIR / "mixed_100kb_operation_rejected.png",
    )
    print("Generated mixed_100kb_operation_rejected.png")

    plot_mixed_operation_success(
        mixed_100kb,
        OUTPUT_DIR / "mixed_100kb_operation_success.png",
    )
    print("Generated mixed_100kb_operation_success.png")

    mixed_size_runs = [mixed_100kb, mixed_1mb, mixed_5mb]

    plot_mixed_upload_latency_by_size(
        mixed_size_runs,
        OUTPUT_DIR / "mixed_upload_latency_p95_by_size.png",
    )
    print("Generated mixed_upload_latency_p95_by_size.png")

    plot_mixed_upload_rejected_by_size(
        mixed_size_runs,
        OUTPUT_DIR / "mixed_upload_rejected_by_size.png",
    )
    print("Generated mixed_upload_rejected_by_size.png")

def plot_stage6_vs_stage8_latency(
    stage6: dict[str, Any],
    stage8: dict[str, Any],
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    loads = common_loads(stage6, stage8)
    if not loads:
        raise ValueError("No common load stages found")

    plt.figure(figsize=(9, 6))
    plt.plot(
        loads,
        latency_values_by_load(stage6, loads, "p95"),
        marker="o",
        label="Stage 6 p95",
    )
    plt.plot(
        loads,
        latency_values_by_load(stage8, loads, "p95"),
        marker="o",
        label="Stage 8 p95",
    )

    plt.xlabel("Load")
    plt.ylabel("p95 latency (ms)")
    plt.title("Upload p95 latency: Stage 6 baseline vs Stage 8 post-streaming")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_stage6_vs_stage8_outcomes(
    stage6: dict[str, Any],
    stage8: dict[str, Any],
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    loads = common_loads(stage6, stage8)
    if not loads:
        raise ValueError("No common load stages found")

    plt.figure(figsize=(9, 6))

    plt.plot(
        loads,
        outcome_values_by_load(stage6, loads, "rejected"),
        marker="o",
        label="Stage 6 rejected",
    )
    plt.plot(
        loads,
        outcome_values_by_load(stage8, loads, "rejected"),
        marker="o",
        label="Stage 8 rejected",
    )
    plt.plot(
        loads,
        outcome_values_by_load(stage6, loads, "failed"),
        marker="o",
        linestyle="--",
        label="Stage 6 failed",
    )
    plt.plot(
        loads,
        outcome_values_by_load(stage8, loads, "failed"),
        marker="o",
        linestyle="--",
        label="Stage 8 failed",
    )

    plt.xlabel("Load")
    plt.ylabel("Count")
    plt.title("Upload overload outcomes: Stage 6 vs Stage 8")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def throughput_values_by_load(
    run: dict[str, Any],
    loads: list[int],
) -> list[float]:
    by_load = stages_by_load(run)
    return [
        float(by_load[load].get("throughput_ops_per_s", 0.0))
        for load in loads
    ]


def plot_stage6_vs_stage8_throughput(
    stage6: dict[str, Any],
    stage8: dict[str, Any],
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    loads = common_loads(stage6, stage8)
    if not loads:
        raise ValueError("No common load stages found")

    plt.figure(figsize=(9, 6))

    plt.plot(
        loads,
        throughput_values_by_load(stage6, loads),
        marker="o",
        label="Stage 6 throughput",
    )
    plt.plot(
        loads,
        throughput_values_by_load(stage8, loads),
        marker="o",
        label="Stage 8 throughput",
    )

    plt.xlabel("Load")
    plt.ylabel("Throughput (ops/s)")
    plt.title("Upload throughput: Stage 6 vs Stage 8")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def plot_stage6_vs_stage8_cpu(
    stage6: dict[str, Any],
    stage8: dict[str, Any],
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    loads = common_loads(stage6, stage8)
    if not loads:
        raise ValueError("No common load stages found")

    plt.figure(figsize=(9, 6))

    plt.plot(
        loads,
        resource_peak_values_by_load(stage6, loads, "cpu_percent"),
        marker="o",
        label="Stage 6 CPU peak %",
    )
    plt.plot(
        loads,
        resource_peak_values_by_load(stage8, loads, "cpu_percent"),
        marker="o",
        label="Stage 8 CPU peak %",
    )

    plt.xlabel("Load")
    plt.ylabel("CPU peak (%)")
    plt.title("Upload CPU peak: Stage 6 vs Stage 8")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def resource_peak_values_by_load(
    run: dict[str, Any],
    loads: list[int],
    resource_key: str,
) -> list[float]:
    by_load = stages_by_load(run)
    values: list[float] = []

    for load in loads:
        peak = by_load[load].get("server_metrics", {}).get("peak")
        if not peak:
            values.append(0.0)
            continue
        values.append(float(peak.get(resource_key, 0.0)))

    return values


def plot_stage6_vs_stage8_resources(
    stage6: dict[str, Any],
    stage8: dict[str, Any],
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    loads = common_loads(stage6, stage8)
    if not loads:
        raise ValueError("No common load stages found")

    plt.figure(figsize=(9, 6))

    plt.plot(
        loads,
        resource_peak_values_by_load(stage6, loads, "rss_mb"),
        marker="o",
        label="Stage 6 RSS peak MB",
    )
    plt.plot(
        loads,
        resource_peak_values_by_load(stage8, loads, "rss_mb"),
        marker="o",
        label="Stage 8 RSS peak MB",
    )

    plt.xlabel("Load")
    plt.ylabel("RSS peak (MB)")
    plt.title("Upload RSS peak: Stage 6 vs Stage 8")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def generate_stage6_vs_stage8_plots(
    stage6_path: Path,
    stage8_path: Path,
    out_dir: Path,
) -> None:
    stage6 = load_run(stage6_path)
    stage8 = load_run(stage8_path)

    out_dir.mkdir(parents=True, exist_ok=True)

    plot_stage6_vs_stage8_latency(
        stage6,
        stage8,
        out_dir / "latency_p95_comparison.png",
    )
    plot_stage6_vs_stage8_outcomes(
        stage6,
        stage8,
        out_dir / "outcomes_comparison.png",
    )
    plot_stage6_vs_stage8_resources(
        stage6,
        stage8,
        out_dir / "rss_peak_comparison.png",
    )
    plot_stage6_vs_stage8_throughput(
        stage6,
        stage8,
        out_dir / "throughput_comparison.png",
    )

    plot_stage6_vs_stage8_cpu(
        stage6,
        stage8,
        out_dir / "cpu_peak_comparison.png",
    )

    print("Generated Stage 6 vs Stage 8 comparison plots")
    print(f"stage6 : {stage6_path}")
    print(f"stage8 : {stage8_path}")
    print(f"out_dir: {out_dir}")
    print("Note: this is a behavioral comparison across major protocol/upload changes, not a strict apples-to-apples microbenchmark.")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SEFTP benchmark plotting utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "legacy-stage6",
        help="Generate the original hardcoded Stage 6 plots",
    )

    stage8 = sub.add_parser(
        "stage8-compare",
        help="Generate Stage 8 comparison plots from two benchmark JSON reports",
    )
    stage8.add_argument("--baseline", required=True, type=Path)
    stage8.add_argument("--candidate", required=True, type=Path)
    stage8.add_argument("--out-dir", required=True, type=Path)

    stage6_vs_stage8 = sub.add_parser(
        "stage6-vs-stage8",
        help="Generate behavioral comparison plots between Stage 6 and Stage 8 benchmark reports",
    )
    stage6_vs_stage8.add_argument("--stage6", required=True, type=Path)
    stage6_vs_stage8.add_argument("--stage8", required=True, type=Path)
    stage6_vs_stage8.add_argument("--out-dir", required=True, type=Path)

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.command == "legacy-stage6":
        generate_legacy_stage6_plots()
        return 0

    if args.command == "stage8-compare":
        generate_stage8_compare_plots(
            baseline_path=args.baseline,
            candidate_path=args.candidate,
            out_dir=args.out_dir,
        )
        return 0

    if args.command == "stage6-vs-stage8":
        generate_stage6_vs_stage8_plots(
            stage6_path=args.stage6,
            stage8_path=args.stage8,
            out_dir=args.out_dir,
        )
        return 0

    raise RuntimeError(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

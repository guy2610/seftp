from __future__ import annotations

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
if __name__ == "__main__":
    register_run = load_run(RESULTS_DIR / "2026-03-29T14-53-45Z_register_ramp.json")
    relogin_run = load_run(RESULTS_DIR / "2026-03-30T09-45-42Z_relogin_ramp.json")
    upload_run = load_run(RESULTS_DIR / "2026-03-30T09-47-58Z_upload_ramp.json")

    upload_100kb = load_run(RESULTS_DIR / "2026-03-30T10-59-28Z_upload_ramp.json")
    upload_1mb = load_run(RESULTS_DIR / "2026-03-30T11-01-19Z_upload_ramp.json")
    upload_5mb = load_run(RESULTS_DIR / "2026-03-30T11-03-05Z_upload_ramp.json")

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
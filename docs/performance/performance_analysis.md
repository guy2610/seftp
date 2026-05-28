# Performance Analysis - Stage 6

## Scope
Stage 6 focused on measuring runtime behavior under load for the main server paths, collecting structured benchmark output, and identifying early bottlenecks before any optimization work.

The scenarios measured so far are:
- register
- relogin
- upload
- mixed (combined workload: register + relogin + upload)

The benchmark runner now produces structured JSON output per run, including stage-level summaries, latency percentiles, throughput, success and failure counts, and sampled server resource metrics.
Note: The mixed workload currently uses randomized operation selection, which may introduce variability between runs. Future iterations may use deterministic ratios for more stable comparisons.

## Test setup
The measurements were executed using the Stage 6 load runner with ramp-based scenarios and per-stage summaries.

Relevant observations from the setup:
- The server is an asyncio-based multi-client server.
- The register and relogin paths mostly execute on the event loop path.
- The upload path is heavier and includes bounded executor usage for upload finalization.
- Early register failures were initially caused by the configured connection limit, not by intrinsic performance collapse.
- Upload behavior is strongly affected by the configured max concurrent uploads limit.

## Key benchmark infrastructure outcomes
The following Stage 6 capabilities are now in place:
- ramp-based scenario execution
- structured JSON benchmark output
- per-stage summary tables
- latency metrics: avg, p50, p95, p99, max
- throughput calculation
- success, failure, and rejection counts
- server-side sampled metrics: RSS, CPU, thread count

This provides a usable baseline for comparing scenarios and documenting observed bottlenecks.

## Register findings
Initial register runs showed failures at relatively low concurrency, but those failures were traced to the configured connection cap rather than actual throughput limits.

After raising connection-related limits:
- the register path remained stable up to at least 100 concurrent clients
- success rate stayed at 100%
- no rejections were observed
- latency increased under load, but remained moderate
- CPU utilization reached saturation relatively early

Observed behavior:
- around 20 concurrent clients, CPU usage was already near full utilization
- despite that, the server continued to serve register requests successfully
- by 100 concurrent clients, the path was still stable, with higher but still controlled latency

Interpretation:
- the register path appears CPU-bound relatively early
- however, CPU saturation did not immediately translate into request failures
- this suggests the register path remains functionally stable, but has limited headroom before optimization would be needed

## Upload findings
The upload path is significantly heavier than the register path in both latency and operational cost.

With the original upload concurrency cap:
- the system accepted only up to the configured number of concurrent uploads
- additional uploads were rejected via backpressure

After raising the upload concurrency limit to 25:
- the system remained stable up to 25 concurrent uploads
- all 25 succeeded
- latency was high even below overload
- at 50 concurrent uploads, overload behavior became visible

Observed behavior at higher upload load:
- 25 uploads succeeded
- 18 uploads were rejected in a controlled way due to upload backpressure
- 7 uploads failed with timeout errors
- CPU usage was high, but the first clear operational bottleneck remained the configured upload concurrency cap
- memory usage increased more noticeably than in register/relogin scenarios

Interpretation:
- the first practical bottleneck in the upload path is the configured concurrent upload limit
- once load exceeds that capacity, the server begins to reject excess work
- beyond that point, overload is no longer expressed only as clean rejection, but also as timeout failures
- this makes upload the heaviest and least forgiving path measured so far

### Upload sensitivity to file size
An additional upload scaling experiment was executed with three file sizes:
- 100KB
- 1MB
- 5MB

Each size was tested with the same load ramp:
- 10
- 25
- 50 concurrent uploads

Observed behavior:
- all file sizes remained stable through load 25
- at load 50, all file sizes dropped to 50% success, but failure mode distribution changed with file size
- smaller files showed more rejection-dominated overload behavior
- larger files showed fewer rejections but more timeout failures
- larger files also produced significantly higher RSS peaks and higher CPU utilization

Interpretation:
- file size does not materially change the stable region up to the configured upload capacity
- however, once overload begins, larger files increase resource pressure more sharply
- in particular, memory usage grows significantly with larger uploads, and overload shifts from mostly controlled rejection toward a more failure-heavy pattern

Key insight:
- upload capacity is not only limited by concurrency, but also by per-upload resource cost
- larger files significantly increase memory pressure (RSS) and CPU utilization
- under overload, smaller files are mostly rejected, while larger files tend to result in more timeout failures

Implication:
- the system currently lacks size-aware backpressure
- treating all uploads equally leads to less efficient overload behavior for larger files

## Relogin findings
The relogin path was significantly lighter than upload and remained stable through moderate concurrency levels.

Measured results showed:
- low request latency at lower load
- stable success up to 40 concurrent relogin requests
- no controlled rejections
- failures appearing at 50 concurrent requests, mainly as timeout errors

Observed behavior:
- latency increased gradually as concurrency increased
- the path remained stable through 40 concurrent relogin requests
- at 50 concurrent relogins, timeout-based failures began to appear
- no backpressure or explicit rejection behavior was observed

Important caveat:
- the relogin worker currently performs setup work before the measured relogin request
- however, the measured latency itself reflects only the 827 relogin phase
- the overall stage elapsed time still includes the setup cost

Interpretation:
- the relogin path itself appears relatively lightweight and lookup-oriented
- unlike upload, degradation under higher load does not currently manifest as controlled rejection
- instead, the first visible failure mode is timeout-based degradation around the 40-50 concurrent range

## Mixed workload findings

A mixed workload scenario was introduced to simulate a more realistic production pattern, combining:
- register
- relogin
- upload

Each worker randomly selects an operation, resulting in a shared-concurrency environment.

## Churn findings

- under default connection caps, churn exposed abrupt connection termination behavior
- after raising connection limits, churn remained stable through the tested range
- no rejections or failures were observed up to load 50 with 10 short-lived connections per worker
- CPU utilization increased quickly under churn, but without operational collapse
- this suggests the main issue was configured connection admission limits rather than a fundamental cleanup or teardown bottleneck

## Idle + active upload findings

- idle connections remained stable across the tested range
- under combined idle + upload load, degradation appeared in the upload path only
- uploads were increasingly rejected via backpressure as idle connection count grew
- no timeout or crash-based failures were observed in this scenario
- this suggests that passive open connections reduce effective capacity for active work, while the server still preserves stable idle-session handling

### Observed behavior

- upload is the first operation to degrade under load
- register and relogin remain stable even when the system is under pressure
- rejections occur almost exclusively in the upload path due to upload backpressure
- under moderate load (e.g., 25 concurrent requests), upload begins to show rejection behavior while other operations maintain 100% success

At higher loads:
- upload latency increases significantly (p95 spikes)
- upload rejection rate grows
- register and relogin continue to succeed, with only moderate latency increase

### CPU and resource behavior

- mixed workload amplifies CPU utilization compared to single-scenario runs
- for larger file sizes (1MB, 5MB), CPU saturation occurs much earlier
- memory usage (RSS) also increases with file size, especially under concurrent upload pressure

### Sensitivity to file size

Under mixed workload:

- 100KB files:
  - system remains stable up to higher loads (up to ~50)
  - overload expressed primarily as upload rejections

- 1MB files:
  - CPU saturation occurs earlier (around load 25)
  - upload rejection appears sooner

- 5MB files:
  - CPU saturation occurs even at low load (~10)
  - memory usage increases significantly
  - system reaches overload state much earlier

### Interpretation

- upload remains the dominant cost driver even in mixed scenarios
- register and relogin are comparatively lightweight and resilient
- system behavior under realistic mixed load is primarily dictated by upload pressure
- file size significantly affects how early the system reaches CPU saturation and overload

### Key insight

In mixed workloads:
- upload dictates system capacity
- other operations are effectively "shielded" until upload saturates resources

This indicates that optimization efforts should primarily target:
- upload concurrency handling
- CPU efficiency of upload processing
- memory usage per upload

## Bottleneck summary

### Register
- primary observed bottleneck: early CPU saturation
- behavior under load: stable, no failures after lifting connection caps
- conclusion: CPU-bound but still operationally stable in tested range

### Upload
- primary observed bottleneck: concurrent upload limit and memory pressure under larger file sizes
- secondary overload symptoms: timeout failures and throughput collapse under heavier load
- overload behavior shifts with file size: smaller uploads are rejected more often, while larger uploads produce more timeout failures
- conclusion: upload capacity is constrained both by configured concurrency and by the per-upload resource cost of larger files
- under mixed workloads, upload is also the first path to degrade and reject requests

### Relogin
- primary observed bottleneck: timeout-based degradation under higher concurrency
- behavior under load: stable through 40 concurrent relogins, then begins failing around 50
- conclusion: relatively lightweight path, but currently degrades through timeouts rather than controlled rejection
- remains stable even under mixed load conditions

## Practical conclusions
At this stage, the server already shows meaningful differentiated behavior across paths:
- register is stable but CPU-heavy
- upload is the most expensive path and is constrained first by concurrent upload limits, then degrades further under overload
- relogin is lighter, but under higher concurrency currently degrades through timeout failures rather than controlled rejection
- upload overload behavior is also sensitive to file size: larger files increase memory pressure and shift overload behavior toward more timeout-driven failures
- under mixed workloads, system capacity is effectively determined by upload performance, while register and relogin remain stable

## Charts

### Register CPU saturation
![Register CPU](../../tools/plots/register_cpu.png)

### Upload throughput
![Upload Throughput](../../tools/plots/upload_throughput.png)

### Upload overload outcomes
![Upload Outcomes](../../tools/plots/upload_outcomes.png)

### Relogin overload outcomes
![Relogin Outcomes](../../tools/plots/relogin_outcomes.png)

### Cross-scenario latency comparison
![Latency Comparison](../../tools/plots/comparison_latency_p95.png)

### Upload p95 latency by file size
![Upload Size Latency](../../tools/plots/upload_size_latency_p95.png)

### Upload throughput by file size
![Upload Size Throughput](../../tools/plots/upload_size_throughput.png)

### Upload overload behavior by file size
![Upload Size Overload](../../tools/plots/upload_size_overload.png)

### Upload RSS peak by file size
![Upload Size RSS](../../tools/plots/upload_size_rss.png)

### Mixed workload per-operation latency
![Mixed Operation Latency](../../tools/plots/mixed_100kb_operation_latency_p95.png)

### Mixed workload rejected rate per operation
![Mixed Operation Rejected](../../tools/plots/mixed_100kb_operation_rejected.png)

### Mixed workload success rate per operation
![Mixed Operation Success](../../tools/plots/mixed_100kb_operation_success.png)

### Mixed upload p95 latency by file size
![Mixed Upload Size Latency](../../tools/plots/mixed_upload_latency_p95_by_size.png)

### Mixed upload rejected rate by file size
![Mixed Upload Size Rejected](../../tools/plots/mixed_upload_rejected_by_size.png)

## Next steps

- refine mixed workload generation using deterministic operation ratios for more stable comparisons
- translate measured upload bottlenecks into concrete optimization candidates for later stages
- evaluate size-aware upload backpressure for larger files
- defer deeper runtime observability improvements such as active upload visibility, queue depth, and internal timing breakdown to Stage 8


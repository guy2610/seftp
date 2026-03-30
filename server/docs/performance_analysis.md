# Performance Analysis - Stage 6

## Scope
Stage 6 focused on measuring runtime behavior under load for the main server paths, collecting structured benchmark output, and identifying early bottlenecks before any optimization work.

The scenarios measured so far are:
- register
- relogin
- upload

The benchmark runner now produces structured JSON output per run, including stage-level summaries, latency percentiles, throughput, success and failure counts, and sampled server resource metrics.

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

## Bottleneck summary

### Register
- primary observed bottleneck: early CPU saturation
- behavior under load: stable, no failures after lifting connection caps
- conclusion: CPU-bound but still operationally stable in tested range

### Upload
- primary observed bottleneck: concurrent upload limit and backpressure
- secondary overload symptom: timeout failures under heavier load
- conclusion: upload capacity is currently constrained by configured concurrency and becomes unstable when pushed beyond that limit

### Relogin
- primary observed bottleneck: timeout-based degradation under higher concurrency
- behavior under load: stable through 40 concurrent relogins, then begins failing around 50
- conclusion: relatively lightweight path, but currently degrades through timeouts rather than controlled rejection

## Practical conclusions
At this stage, the server already shows meaningful differentiated behavior across paths:
- register is stable but CPU-heavy
- upload is the most expensive path and is constrained first by concurrent upload limits, then degrades further under overload
- relogin is lighter, but under higher concurrency currently degrades through timeout failures rather than controlled rejection

This means the Stage 6 benchmark work is already valuable for guiding future changes:
- connection limits must be distinguished from real throughput bottlenecks
- upload capacity should be evaluated separately from register/relogin paths
- backpressure behavior should be treated as an intentional control mechanism, not automatically as failure
- optimization decisions should be based on measured path-specific bottlenecks rather than intuition

## Charts

### Register CPU saturation
![Register CPU](../tools/plots/register_cpu.png)

### Upload throughput
![Upload Throughput](../tools/plots/upload_throughput.png)

### Upload overload outcomes
![Upload Outcomes](../tools/plots/upload_outcomes.png)

### Relogin overload outcomes
![Relogin Outcomes](../tools/plots/relogin_outcomes.png)

### Cross-scenario latency comparison
![Latency Comparison](../tools/plots/comparison_latency_p95.png)

## Next steps
- add a mixed workload scenario
- add a connection churn scenario
- document benchmark configuration and scenario assumptions more explicitly
- refine relogin benchmarking to reduce setup-side distortion if cleaner isolation is needed
- use the current findings to define concrete follow-up optimization candidates in later stages



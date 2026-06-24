# Stage 8 Performance Observability

## Scope

Stage 8 focuses on improving the quality of runtime measurements, benchmark reliability, and production-behavior visibility after the Stage 7 security and streaming-upload changes.

Stage 6 established the original performance analysis framework and identified upload as the dominant cost driver. Stage 7 then changed the upload implementation substantially by moving from full-file buffering to an end-to-end streaming upload pipeline. Because of that, Stage 8 does not treat the old Stage 6 numbers as directly comparable raw performance numbers. Instead, Stage 8 uses them as behavioral context and establishes a new post-Stage-7 baseline.

The main goals are:

- update benchmarking tools to work with the Stage 7 protocol
- collect per-phase timing data instead of only end-to-end latency
- separate server-side bottlenecks from benchmark-runner overhead
- evaluate upload packet-size behavior
- document evidence-based optimization candidates for future work

## Background

Stage 6 showed that upload was the dominant cost path under load. Register and relogin behaved mostly as control-plane operations, while upload dictated system capacity in both upload-only and mixed workloads.

The main Stage 6 findings were:

- upload was the first operation to degrade under load
- larger files increased RSS and CPU pressure
- overload behavior became less clean as file size increased
- the system lacked size-aware upload admission control
- future work should include deeper internal timing and active upload visibility

Stage 7 changed the upload implementation significantly:

- the client now reads plaintext incrementally
- CRC32 is computed incrementally
- AES-CBC encryption is performed with continuous state
- ciphertext is sent as 828 packets without full-file buffering
- the server decrypts incrementally
- plaintext is written to a temporary upload file
- CRC32 is computed incrementally on the server
- final upload paths are atomically replaced on success

This means Stage 8 must re-establish the performance baseline after the Stage 7 upload pipeline.

## Benchmark tooling updates

The Stage 6 load runner originally issued application requests directly. After Stage 7, that was no longer valid because the server requires the Stage 7 handshake before application-level requests.

Stage 8 updated the load runner to perform the required Stage 7 protocol flow:

1. send `829 CLIENT_HELLO`
2. receive and parse `1608 SERVER_HELLO`
3. send `830 CLIENT_HANDSHAKE_ACK`
4. continue with `825`, `826`, `827`, or `828`

The load runner was also updated for the Stage 7 AES key response format. Responses `1602` and `1605` now include the encrypted AES key together with a server-side AES key binding signature. The benchmark runner parses this response format so that upload and relogin scenarios remain protocol-compatible with Stage 7.

The benchmark runner does not perform full production-grade trust validation. Its purpose is measurement, not replacing the C++ client security implementation.

## Per-phase timing breakdown

Stage 8 added per-phase timing data to the load test JSON output.

For upload scenarios, the benchmark runner now records timing for phases such as:

- connect and Stage 7 handshake
- registration
- RSA key selection or generation
- AES key exchange
- RSA decrypt
- client-side encryption preparation
- upload packet transmission
- CRC confirmation

This timing breakdown changed the interpretation of the upload benchmark.

Initial post-Stage-7 upload runs showed very high end-to-end latency. However, the breakdown revealed that a large portion of that latency came from client-side RSA key generation and setup work inside the load generator, not from the server upload packet path itself.

## RSA key pool

The original upload benchmark generated a fresh RSA-2048 keypair inside each upload worker. That made the benchmark CPU-heavy on the client side and polluted the measurement.

Stage 8 added RSA key pool support to the load runner.

When `--rsa-key-pool-size N` is provided, the load runner pre-generates RSA key material and each worker reuses a prepared key from the pool. This removes key generation from the measured worker path and produces a cleaner measurement of the server and protocol upload behavior.

Example:

```bash
python3 tools/load_test.py upload \
  --server-pid <PID> \
  --ramp 10,25,50 \
  --concurrency 50 \
  --file-size 1000000 \
  --chunk-size 65536 \
  --rsa-key-pool-size 50 \
  --stop-cpu-percent 200
```

This showed that the earlier upload benchmark was heavily affected by benchmark-runner overhead. After RSA key pooling, 1MB upload latency dropped from multi-second values to sub-second values under the tested load range.

## Stage 8 upload baseline with RSA key pool

With 1MB files, 64KB upload chunks, and RSA key pooling, the upload path showed the following behavior:

| Load | Success | Rejected | Failed | Avg latency | p95 latency |
|---:|---:|---:|---:|---:|---:|
| 10 | 10 | 0 | 0 | ~420ms | ~436ms |
| 25 | 25 | 0 | 0 | ~564ms | ~577ms |
| 50 | 25 | 25 | 0 | ~816ms | ~826ms |

The load 50 result is expected because the server is configured to allow a bounded number of concurrent uploads. The important result is that overload is expressed through controlled backpressure and not through timeout failures.

Observed behavior:

- load 10 and load 25 completed with 100% success
- load 50 produced controlled upload rejections
- no failed uploads were observed
- RSS remained bounded
- CPU increased under upload pressure but the process remained stable

This is a stronger overload profile than the earlier Stage 6 behavior, where upload overload could include timeout failures.

## Chunk size experiment

Stage 8 compared upload behavior with three chunk sizes for 1MB uploads:

- 16KB
- 60KB
- 64KB

The 16KB chunk size was significantly slower because it produced many more upload packets. The 60KB chunk size performed well, but 64KB was consistently slightly better.

Summary:

| Chunk size | Load 10 avg | Load 25 avg | Load 50 avg | Load 50 p95 |
|---:|---:|---:|---:|---:|
| 16KB | ~1412ms | ~1560ms | ~1810ms | ~1819ms |
| 60KB | ~445ms | ~599ms | ~842ms | ~850ms |
| 64KB | ~420ms | ~564ms | ~816ms | ~826ms |

Conclusion:

- packet count is a meaningful factor in the upload hot path
- 16KB creates too much per-packet overhead for this workload
- 64KB aligns with the server default maximum chunk size
- the load runner default should use 64KB instead of 60KB

Stage 8 therefore updated the load runner default upload chunk size to `64 * 1024`.

## Interpretation

After fixing the benchmark runner, the upload hot path is now clearer.

The dominant cost is no longer artificial RSA key generation in the load generator. With RSA key pooling enabled, the main measured costs are:

- upload packet transmission and server-side streaming processing
- AES key exchange
- connection and handshake overhead under concurrency

The upload packet phase remains the largest component in the clean upload benchmark, which confirms that upload is still the correct area to observe and optimize first.

However, the system currently behaves well under configured upload capacity:

- stable at load 10 and load 25
- controlled rejection at load 50
- no timeout failures in the tested RSA-pool upload runs

This suggests that immediate optimization should be evidence-driven rather than speculative.

## Cleanup of benchmark-generated uploads

The load runner currently sends real upload requests to the server. As a result, benchmark uploads are persisted under the server upload directory just like normal client uploads.

For local performance experiments, these benchmark-created files are usually not useful after the run report has been written. They can also pollute the upload directory and make it harder to distinguish real manual uploads from synthetic benchmark files.

Stage 8 should improve benchmark hygiene by cleaning up files created by the load runner after each run.

The cleanup should follow these rules:

- only delete files created by the current load test run
- do not delete unrelated user uploads
- do not require a special flag for normal benchmark behavior
- keep the structured JSON benchmark result
- keep SQLite metadata unless a later explicit metadata-cleanup mode is added
- prefer unique benchmark filenames or a run-specific upload namespace so cleanup is safe

A safe implementation approach is to make the load runner generate upload filenames with a unique run prefix, for example:

```text
loadtest_<run_id>_<worker_id>.bin
```

At the end of the run, the load runner can remove only files matching that run prefix from the upload directory.

This keeps server behavior realistic during the benchmark while avoiding long-term filesystem clutter from synthetic uploads.

## Optimization candidates

Stage 8 identifies the following future optimization candidates.

### 1. Size-aware upload backpressure

The current upload limiter is concurrency-based. It treats all active uploads as equivalent, regardless of file size.

Stage 6 showed that larger files create more RSS and CPU pressure and can shift overload behavior toward timeout failures. Stage 8 confirms that upload remains the main resource-sensitive path after streaming.

A future size-aware limiter could account for declared upload size when admitting new uploads.

Possible approaches:

- assign each upload a cost based on declared plaintext or ciphertext size
- maintain a total active upload byte budget
- reject large uploads earlier when the system is already under pressure
- allow more small uploads while limiting large concurrent uploads
- expose active upload count and active upload bytes in metrics

This should be implemented only after adding enough observability to compare behavior before and after the change.

### 2. Plot and CLI comparison tooling

The benchmark runner now produces richer JSON output, including timing breakdowns. The plotting tooling should be updated to compare Stage 8 runs more directly.

Useful additions:

- compare two run JSON files from the CLI
- plot end-to-end latency before and after RSA key pooling
- plot per-phase timing breakdown
- compare chunk-size experiments
- show rejected, failed, and successful outcomes per stage
- generate charts into a Stage 8-specific plots directory

This would make the Stage 8 results easier to communicate and would support a more polished portfolio presentation.

### 3. Internal server timing

The load runner now measures client-observed phases, but the server does not yet expose internal phase timing.

Potential future server-side timings:

- frame read and parse time
- router dispatch time
- handler execution time
- SQLite operation time
- upload slot wait or rejection point
- upload packet processing time
- temp-file write time
- final padding and atomic replace time
- CRC confirmation handling time

This would help separate network/client-observed latency from actual server-side processing cost.

### 4. Active upload visibility

Stage 8 should eventually expose runtime state such as:

- active connections
- active uploads
- rejected connections
- rejected uploads
- upload slots in use
- upload bytes currently in flight
- recent protocol error counts

This would make overload behavior easier to explain and debug.

## Current Stage 8 status

Completed so far:

- load runner updated for Stage 7 handshake
- load runner updated for Stage 7 AES key response format
- timing breakdown added to benchmark JSON
- register timing baseline saved
- relogin timing baseline saved
- upload timing baseline saved
- RSA key pool support added to the load runner
- upload benchmark repeated with RSA key pooling
- chunk-size experiment completed
- load runner default upload chunk size changed to 64KB

Remaining useful Stage 8 work:

- clean up benchmark-created uploaded files
- add Stage 8 plotting or CLI comparison for benchmark JSON files
- document benchmark methodology and caveats
- decide whether size-aware upload backpressure belongs in Stage 8 implementation or Stage 9 follow-up
- optionally add server-side internal timing and active upload metrics

## Summary

Stage 8 turned the performance work from raw load testing into more reliable observability.

The most important finding is that the original post-Stage-7 upload benchmark was polluted by client-side RSA key generation inside the load generator. After adding per-phase timing and RSA key pooling, the benchmark became much more representative of the actual upload path.

The cleaned-up results show that the Stage 7 streaming upload pipeline behaves well under configured capacity, rejects excess upload work cleanly, and avoids timeout-based failure in the tested overload case.

The chunk-size experiment also showed that packet count matters. A 64KB chunk size performs best among the tested values and now matches the load runner default.

The next optimization should be evidence-driven. The strongest candidates are size-aware upload backpressure, better plot/CLI comparison tooling, and deeper server-side runtime visibility.
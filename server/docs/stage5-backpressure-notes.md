# Stage 5 - Upload Backpressure Notes

## Goal

Validate current server scalability behavior under concurrent uploads and add controlled upload admission when the server is under pressure.

## Why this change was needed

Baseline load tests showed that the upload path was the main scalability bottleneck.

Observed before admission control:
- idle connections were stable at higher counts
- register flow remained fast and stable
- concurrent uploads, especially 5MB uploads, caused strong latency growth and high CPU pressure

This indicated that the main problem was not general connection handling, but unbounded concurrent uploads.

## Change implemented

Added upload admission control with a configurable limit:

- `max_concurrent_uploads`
- upload slot acquired when a real upload begins
- upload rejected with `1607` when the server is already at capacity
- upload slot released on:
  - successful completion
  - protocol error
  - disconnect / cleanup

Default configured limit:
- `max_concurrent_uploads = 10`

## Load test improvements

The load test script was updated to:
- support ramp-up runs
- distinguish between:
  - successful uploads
  - rejected uploads due to backpressure
  - real failures
- detect early server rejection during upload instead of treating it as a generic failure

## Commands used

Exact-cap validation:
```
py tools/load_test.py upload --ramp 10 --concurrency 10 --file-size 5000000 --server-pid <PID> --stop-failure-rate 1 --stop-p95-ms 60000 --stop-rss-mb 1200 --stop-cpu-percent 300
```

Over-cap validation:
```
py tools/load_test.py upload --ramp 12,15,20 --concurrency 20 --file-size 5000000 --server-pid <PID> --stop-failure-rate 1 --stop-p95-ms 60000 --stop-rss-mb 1200 --stop-cpu-percent 300

```

Recovery validation:
```
py tools/load_test.py upload --ramp 20 --concurrency 20 --file-size 5000000 --server-pid <PID> --stop-failure-rate 1 --stop-p95-ms 60000 --stop-rss-mb 1200 --stop-cpu-percent 300

```

followed by:
```
py tools/load_test.py upload --ramp 10 --concurrency 10 --file-size 5000000 --server-pid <PID> --stop-failure-rate 1 --stop-p95-ms 60000 --stop-rss-mb 1200 --stop-cpu-percent 300

```

## Results after admission control

Exact-cap behavior:
- load 10 -> 10 ok, 0 rejected, 0 failed

Over-cap behavior:
- load 12 -> 10 ok, 2 rejected, 0 failed
- load 15 -> 10 ok, 5 rejected, 0 failed
- load 20 -> 10 ok, 10 rejected, 0 failed

## Recovery behavior:

- after an overloaded run, a new exact-cap run still completed successfully
- no immediate sign of upload slot leakage

## Conclusion

Upload backpressure is now working as intended.

The server no longer silently saturates under excessive concurrent upload load.
Instead, it applies a controlled rejection policy once the upload concurrency cap is reached.

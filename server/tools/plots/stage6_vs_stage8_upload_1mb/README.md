# Stage 6 vs Stage 8 Upload Comparison

These plots compare the Stage 6 upload behavioral baseline with the Stage 8 post-Stage-7 upload baseline for 1MB uploads.

This is not a strict apples-to-apples microbenchmark. Between Stage 6 and Stage 8, the system changed substantially:

- Stage 7 added the mandatory server-identity handshake
- Stage 7 added bound AES key responses
- Stage 7 replaced full-file upload buffering with streaming upload processing
- Stage 8 updated the load runner for the Stage 7 protocol
- Stage 8 added RSA key pooling to remove load-generator RSA generation overhead from upload measurements
- Stage 8 changed the default upload chunk size to `64 * 1024`

The purpose of these plots is to show behavioral change after the Stage 7 upload pipeline evolution and Stage 8 benchmark cleanup.

Key observations:

- Stage 8 keeps upload p95 latency below 1 second in the tested 1MB upload scenario, while Stage 6 reached multi-second and timeout-heavy behavior.
- Stage 8 preserves clean overload behavior at load 50: excess uploads are rejected, but upload failures remain at zero.
- Stage 8 shows lower RSS growth under the tested upload ramp.
- Stage 8 shows lower CPU peak under the tested upload ramp.
- Stage 8 reaches much higher measured throughput in this benchmark setup.

Interpretation:

Stage 6 identified upload as the dominant bottleneck and showed that larger uploads increase CPU and memory pressure. Stage 7 changed the upload architecture to stream data incrementally instead of buffering full files. Stage 8 then re-baselined the system and cleaned up benchmark-runner overhead.

The comparison supports the conclusion that the Stage 7 streaming upload pipeline improved upload behavior and that Stage 8 provides better tooling for analyzing the remaining upload hot path.
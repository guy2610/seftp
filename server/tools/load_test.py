import argparse
import asyncio
import base64
import math
import os
import random
import secrets
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
import psutil
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import json
from datetime import datetime, timezone
from pathlib import Path


RESPONSE_HEADER_LEN = 7
VERSION = b"\x03"


def build_request_frame(client_id: bytes, code: int, payload: bytes, version: bytes = VERSION) -> bytes:
    if len(client_id) != 16:
        raise ValueError("client_id must be 16 bytes")
    return (
        client_id +
        version +
        code.to_bytes(2, "little") +
        len(payload).to_bytes(4, "little") +
        payload
    )


async def read_exact(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
    return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)


async def read_response_frame(reader: asyncio.StreamReader, timeout: float):
    header = await read_exact(reader, RESPONSE_HEADER_LEN, timeout)
    version = header[:1]
    code = int.from_bytes(header[1:3], "little")
    payload_size = int.from_bytes(header[3:7], "little")
    payload = await read_exact(reader, payload_size, timeout) if payload_size else b""
    return version, code, payload

async def try_read_response_frame(reader: asyncio.StreamReader, timeout: float):
    try:
        return await read_response_frame(reader, timeout)
    except asyncio.TimeoutError:
        return None

def decode_1607_message(payload: bytes) -> str:
    if len(payload) < 16:
        return "<short_1607_payload>"
    return payload[16:].decode("utf-8", errors="replace")

def random_username(prefix: str = "load") -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def build_825_payload(username: str) -> bytes:
    return username.encode("utf-8") + b"\x00"


def build_826_payload(username: str, public_der_b64_ascii: bytes) -> bytes:
    return username.encode("utf-8") + b"\x00" + public_der_b64_ascii


def chunk_bytes(data: bytes, chunk_size: int):
    for i in range(0, len(data), chunk_size):
        yield data[i:i + chunk_size]


def encrypt_file_for_828(plaintext: bytes, aes_key: bytes):
    iv = secrets.token_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ciphertext


def build_828_packet(
    content_size: int,
    orig_file_size: int,
    packet_num: int,
    total_packets: int,
    file_name: str,
    cipher_chunk: bytes,
) -> bytes:
    return (
        content_size.to_bytes(4, "little") +
        orig_file_size.to_bytes(4, "little") +
        packet_num.to_bytes(2, "little") +
        total_packets.to_bytes(2, "little") +
        file_name.encode("utf-8") + b"\x00" +
        cipher_chunk
    )


def percentile(values: list[float], p: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = math.ceil((p / 100) * len(ordered)) - 1
    idx = max(0, min(idx, len(ordered) - 1))
    return ordered[idx]


@dataclass
class Result:
    ok: bool
    duration_ms: float
    error: Optional[str] = None
    rejected: bool = False


@dataclass
class Summary:
    name: str
    total: int = 0
    ok: int = 0
    failed: int = 0
    durations_ms: list[float] = field(default_factory=list)
    errors: dict[str, int] = field(default_factory=dict)
    rejected: int = 0

    def add(self, r: Result):
        self.total += 1
        if r.ok:
            self.ok += 1
            self.durations_ms.append(r.duration_ms)
        elif r.rejected:
            self.rejected += 1
            key = r.error or "rejected"
            self.errors[key] = self.errors.get(key, 0) + 1
        else:
            self.failed += 1
            key = r.error or "unknown"
            self.errors[key] = self.errors.get(key, 0) + 1

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.ok / self.total

    @property
    def accepted_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.ok / self.total

    @property
    def failure_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.failed / self.total

    @property
    def rejected_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.rejected / self.total

    @property
    def avg_ms(self) -> float:
        return statistics.mean(self.durations_ms) if self.durations_ms else 0.0

    @property
    def p95_ms(self) -> float:
        return percentile(self.durations_ms, 95)

    @property
    def p99_ms(self) -> float:
        return percentile(self.durations_ms, 99)

    @property
    def p50_ms(self) -> float:
        return percentile(self.durations_ms, 50)

    @property
    def max_ms(self) -> float:
        return max(self.durations_ms) if self.durations_ms else 0.0

    def print_verbose(self):
        print(f"\n=== {self.name} ===")
        print(
            f"total={self.total} ok={self.ok} rejected={self.rejected} "
            f"failed={self.failed} success_rate={self.success_rate * 100:.1f}%"
        )
        if self.durations_ms:
            print(
                f"avg_ms={self.avg_ms:.2f} "
                f"p95_ms={self.p95_ms:.2f} "
                f"p99_ms={self.p99_ms:.2f} "
                f"max_ms={self.max_ms:.2f}"
            )
        if self.errors:
            print("errors:")
            for k, v in sorted(self.errors.items(), key=lambda x: (-x[1], x[0])):
                print(f"  {k}: {v}")

def summary_to_dict(summary: Summary) -> dict:
    result = {}
    result["total"] = summary.total
    result["ok"] = summary.ok
    result["failed"] = summary.failed
    result["rejected"] = summary.rejected
    result["success_rate"] = summary.success_rate
    result["failure_rate"] = summary.failure_rate
    result["rejected_rate"] = summary.rejected_rate
    result["latency_ms"] = { "avg": summary.avg_ms,
      "p50": summary.p50_ms,
      "p95": summary.p95_ms,
      "p99": summary.p99_ms,
      "max": summary.max_ms}
    result["errors"] = dict(summary.errors)
    return result

@dataclass
class MetricsSnapshot:
    rss_mb: float = 0.0
    cpu_percent: float = 0.0
    num_threads: int = 0

    def short_str(self) -> str:
        return f"rss_mb={self.rss_mb:.1f} cpu={self.cpu_percent:.1f}% threads={self.num_threads}"

def metrics_snapshot_to_dict(snapshot: MetricsSnapshot) -> dict:
    if not snapshot:
        return None
    result = {"rss_mb" : snapshot.rss_mb,
              "cpu_percent" : snapshot.cpu_percent,
              "num_threads" : snapshot.num_threads}
    return result


@dataclass
class StageReport:
    load: int
    summary: Summary
    metrics_before: Optional[MetricsSnapshot]
    metrics_after: Optional[MetricsSnapshot]
    metrics_peak: Optional[MetricsSnapshot]
    elapsed_s: float
    per_operation_summaries: Optional[dict[str, Summary]] = None
    stop_reason: Optional[str] = None


def stage_report_to_dict(report: StageReport, concurrency) -> dict:
    result = {}
    result["load"] = report.load
    result["concurrency"] = concurrency
    result["elapsed_s"] = report.elapsed_s
    result["stop_reason"] = report.stop_reason
    result["throughput_ops_per_s"] = report.summary.ok / report.elapsed_s
    result["summary"] = summary_to_dict(report.summary)
    result["server_metrics"] = {
        "before": metrics_snapshot_to_dict(report.metrics_before),
        "after": metrics_snapshot_to_dict(report.metrics_after),
        "peak": metrics_snapshot_to_dict(report.metrics_peak)
    }
    if report.per_operation_summaries is None:
        result["per_operation_summaries"] = None
    else:
        result["per_operation_summaries"] = {
            operation: summary_to_dict(operation_summary)
            for operation, operation_summary in report.per_operation_summaries.items()
        }
    return result

class ServerMonitor:
    def __init__(self, pid: Optional[int], sample_interval: float = 0.1):
        self.pid = pid
        self.sample_interval = sample_interval
        self.process: Optional[psutil.Process] = None
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self.peak_rss_mb = 0.0
        self.peak_cpu_percent = 0.0
        self.peak_threads = 0

        if pid is not None:
            self.process = psutil.Process(pid)

    def _prime_cpu_counter(self) -> None:
        if self.process is None:
            return
        try:
            self.process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _update_peak_from_snapshot(self, snap: Optional["MetricsSnapshot"]) -> None:
        if snap is None:
            return
        self.peak_rss_mb = max(self.peak_rss_mb, snap.rss_mb)
        self.peak_cpu_percent = max(self.peak_cpu_percent, snap.cpu_percent)
        self.peak_threads = max(self.peak_threads, snap.num_threads)

    def snapshot(self) -> Optional[MetricsSnapshot]:
        if self.process is None:
            return None
        try:
            rss_mb = self.process.memory_info().rss / (1024 * 1024)
            cpu_percent = self.process.cpu_percent(interval=None)
            num_threads = self.process.num_threads()
            snap = MetricsSnapshot(
                rss_mb=rss_mb,
                cpu_percent=cpu_percent,
                num_threads=num_threads,
            )
            self._update_peak_from_snapshot(snap)
            return snap
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    async def start(self):
        if self.process is None or self.running:
            return
        self._prime_cpu_counter()
        self.running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        if self.process is None:
            return

        final_snap = self.snapshot()
        self._update_peak_from_snapshot(final_snap)

        self.running = False
        if self._task:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        final_snap = self.snapshot()
        self._update_peak_from_snapshot(final_snap)

    async def _run(self):
        while self.running:
            await asyncio.sleep(self.sample_interval)
            snap = self.snapshot()
            self._update_peak_from_snapshot(snap)

    def peak_snapshot(self) -> Optional[MetricsSnapshot]:
        if self.process is None:
            return None
        return MetricsSnapshot(
            rss_mb=self.peak_rss_mb,
            cpu_percent=self.peak_cpu_percent,
            num_threads=self.peak_threads,
        )

async def idle_connection_client(host: str, port: int, hold_seconds: float, connect_timeout: float) -> Result:
    started = time.perf_counter()
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=connect_timeout)
        await asyncio.sleep(hold_seconds)
        writer.close()
        await writer.wait_closed()
        return Result(ok=True, duration_ms=(time.perf_counter() - started) * 1000)
    except Exception as e:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return Result(ok=False, duration_ms=(time.perf_counter() - started) * 1000, error=type(e).__name__)


async def register_client(host: str, port: int, io_timeout: float) -> Result:
    started = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.open_connection(host, port)
        username = random_username("reg")
        frame = build_request_frame(
            client_id=b"\x00" * 16,
            code=825,
            payload=build_825_payload(username),
        )
        writer.write(frame)
        await writer.drain()

        _, code, payload = await read_response_frame(reader, io_timeout)
        if code not in (1600, 1601):
            raise RuntimeError(f"unexpected_response_{code}")

        if code == 1600 and len(payload) != 16:
            raise RuntimeError("bad_1600_payload_len")

        writer.close()
        await writer.wait_closed()
        return Result(ok=True, duration_ms=(time.perf_counter() - started) * 1000)
    except Exception as e:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return Result(ok=False, duration_ms=(time.perf_counter() - started) * 1000, error=f"{type(e).__name__}: {e}")

async def churn_client(host: str, port: int, io_timeout: float,connections_per_worker:int) -> Result:
    started = time.perf_counter()
    writer = None
    try:
        for i in range(connections_per_worker):
            reader, writer = await asyncio.open_connection(host, port)
            username = random_username("reg")
            frame = build_request_frame(
                client_id=b"\x00" * 16,
                code=825,
                payload=build_825_payload(username),
            )
            writer.write(frame)
            await writer.drain()

            _, code, payload = await read_response_frame(reader, io_timeout)
            if code not in (1600, 1601):
                raise RuntimeError(f"unexpected_response_{code}")

            if code == 1600 and len(payload) != 16:
                raise RuntimeError("bad_1600_payload_len")

            writer.close()
            await writer.wait_closed()
        return Result(ok=True, duration_ms=(time.perf_counter() - started) * 1000)
    except Exception as e:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return Result(ok=False, duration_ms=(time.perf_counter() - started) * 1000, error=f"{type(e).__name__}: {e}")

async def relogin_client(host: str, port: int, io_timeout: float) -> Result:
    writer = None
    try:
        # setup phase: create a valid existing user with stored public key
        reader, writer = await asyncio.open_connection(host, port)

        username = random_username("relogin")
        zero_id = b"\x00" * 16

        # 825 register
        writer.write(build_request_frame(zero_id, 825, build_825_payload(username)))
        await writer.drain()

        _, code, payload = await read_response_frame(reader, io_timeout)
        if code != 1600 or len(payload) != 16:
            raise RuntimeError(f"relogin_setup_register_failed_{code}")

        client_id = payload

        # 826 store public key + get AES
        rsa_key = RSA.generate(2048)
        public_der = rsa_key.publickey().export_key(format="DER")
        public_b64 = base64.b64encode(public_der)

        writer.write(build_request_frame(client_id, 826, build_826_payload(username, public_b64)))
        await writer.drain()

        _, code, payload = await read_response_frame(reader, io_timeout)
        if code != 1602:
            raise RuntimeError(f"relogin_setup_key_exchange_failed_{code}")
        if len(payload) < 16:
            raise RuntimeError("relogin_setup_bad_1602_payload_len")

        returned_client_id = payload[-16:]
        if returned_client_id != client_id:
            raise RuntimeError("relogin_setup_client_id_mismatch_after_1602")

        writer.close()
        await writer.wait_closed()
        writer = None

        # measured phase: 827 relogin
        started = time.perf_counter()

        reader, writer = await asyncio.open_connection(host, port)
        writer.write(build_request_frame(client_id, 827, build_825_payload(username)))
        await writer.drain()

        _, code, payload = await read_response_frame(reader, io_timeout)
        if code != 1605:
            raise RuntimeError(f"relogin_failed_{code}")
        if len(payload) < 16:
            raise RuntimeError("bad_1605_payload_len")

        returned_client_id = payload[-16:]
        if returned_client_id != client_id:
            raise RuntimeError("client_id_mismatch_after_1605")

        writer.close()
        await writer.wait_closed()

        return Result(ok=True, duration_ms=(time.perf_counter() - started) * 1000)

    except Exception as e:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return Result(
            ok=False,
            duration_ms=0.0 if 'started' not in locals() else (time.perf_counter() - started) * 1000,
            error=f"{type(e).__name__}: {e}",
        )

async def upload_client(
    host: str,
    port: int,
    io_timeout: float,
    file_size: int,
    chunk_size: int,
) -> Result:
    started = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.open_connection(host, port)

        username = random_username("up")
        zero_id = b"\x00" * 16

        writer.write(build_request_frame(zero_id, 825, build_825_payload(username)))
        await writer.drain()
        _, code, payload = await read_response_frame(reader, io_timeout)
        if code != 1600 or len(payload) != 16:
            raise RuntimeError(f"register_failed_{code}")
        client_id = payload

        rsa_key = RSA.generate(2048)
        public_der = rsa_key.publickey().export_key(format="DER")
        public_b64 = base64.b64encode(public_der)

        writer.write(build_request_frame(client_id, 826, build_826_payload(username, public_b64)))
        await writer.drain()
        _, code, payload = await read_response_frame(reader, io_timeout)
        if code != 1602:
            raise RuntimeError(f"key_exchange_failed_{code}")
        if len(payload) < 16:
            raise RuntimeError("bad_1602_payload_len")

        encrypted_aes = payload[:-16]
        returned_client_id = payload[-16:]
        if returned_client_id != client_id:
            raise RuntimeError("client_id_mismatch_after_1602")

        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes)
        if len(aes_key) != 32:
            raise RuntimeError("bad_aes_len")

        plaintext = os.urandom(file_size)
        file_name = f"load_{secrets.token_hex(4)}.bin"
        iv, ciphertext = encrypt_file_for_828(plaintext, aes_key)
        total_packets = math.ceil(len(ciphertext) / chunk_size)

        packet0 = build_828_packet(
            content_size=len(ciphertext),
            orig_file_size=len(plaintext),
            packet_num=0,
            total_packets=total_packets,
            file_name=file_name,
            cipher_chunk=iv,
        )
        writer.write(build_request_frame(client_id, 828, packet0))
        await writer.drain()

        early_crc_received = False

        early = await try_read_response_frame(reader, 0.02)
        if early is not None:
            _, early_code, early_payload = early
            if early_code == 1607:
                text = decode_1607_message(early_payload)
                writer.close()
                await writer.wait_closed()
                return Result(
                    ok=False,
                    rejected=True,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=f"rejected_early_1607: {text}",
                )
            elif early_code == 1603:
                early_crc_received = True
            else:
                raise RuntimeError(f"unexpected_early_response_after_packet0_{early_code}")

        if not early_crc_received:
            for idx, ch in enumerate(chunk_bytes(ciphertext, chunk_size), start=1):
                packet = build_828_packet(
                    content_size=len(ciphertext),
                    orig_file_size=len(plaintext),
                    packet_num=idx,
                    total_packets=total_packets,
                    file_name=file_name,
                    cipher_chunk=ch,
                )
                writer.write(build_request_frame(client_id, 828, packet))
                await writer.drain()

                early = await try_read_response_frame(reader, 0.02)
                if early is None:
                    continue

                _, early_code, early_payload = early

                if early_code == 1607:
                    text = decode_1607_message(early_payload)
                    writer.close()
                    await writer.wait_closed()
                    return Result(
                        ok=False,
                        rejected=True,
                        duration_ms=(time.perf_counter() - started) * 1000,
                        error=f"rejected_by_backpressure: {text}",
                    )

                if early_code == 1603:
                    early_crc_received = True
                    break

                raise RuntimeError(f"unexpected_early_response_during_upload_{early_code}")

        if not early_crc_received:
            _, code, payload = await read_response_frame(reader, io_timeout)

            if code == 1603:
                pass
            elif code == 1607:
                text = decode_1607_message(payload)
                writer.close()
                await writer.wait_closed()
                return Result(
                    ok=False,
                    rejected=True,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=f"rejected_final_1607: {text}",
                )
            else:
                raise RuntimeError(f"upload_crc_response_failed_{code}")

        writer.write(build_request_frame(client_id, 900, file_name.encode("utf-8") + b"\x00"))
        await writer.drain()

        _, code, _ = await read_response_frame(reader, io_timeout)
        if code != 1604:
            raise RuntimeError(f"final_confirm_failed_{code}")

        writer.close()
        await writer.wait_closed()
        return Result(ok=True, duration_ms=(time.perf_counter() - started) * 1000)
    except Exception as e:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return Result(ok=False, duration_ms=(time.perf_counter() - started) * 1000, error=f"{type(e).__name__}: {e}")


async def run_batched(total_clients: int, concurrency: int, worker_coro_factory, summary_name: str) -> Summary:
    sem = asyncio.Semaphore(concurrency)
    summary = Summary(summary_name)

    async def runner(i: int):
        async with sem:
            result = await worker_coro_factory(i)
            summary.add(result)

    await asyncio.gather(*(runner(i) for i in range(total_clients)))
    return summary

async def run_mixed_batched(total_clients: int, concurrency: int, worker_coro_factory, summary_name: str):
    sem = asyncio.Semaphore(concurrency)
    summary_overall = Summary(summary_name)
    summaries = {
        "relogin": Summary("relogin"),
        "register": Summary("register"),
        "upload": Summary("upload")
    }
    async def runner_mixed(i: int):
        async with sem:
            result, operation = await worker_coro_factory(i)
            summary_overall.add(result)
            summaries[operation].add(result)

    await asyncio.gather(*(runner_mixed(i) for i in range(total_clients)))
    return summary_overall,summaries

async def run_single_stage(args, mode: str, load: int) -> StageReport:
    started = time.perf_counter()

    monitor = ServerMonitor(args.server_pid, sample_interval=args.sample_interval)
    before = monitor.snapshot()
    await monitor.start()

    try:
        per_operation_summaries = None
        if mode == "idle":
            summary = await run_batched(
                total_clients=load,
                concurrency=min(args.concurrency, load),
                summary_name=f"idle load={load} concurrency={min(args.concurrency, load)} hold={args.hold}",
                worker_coro_factory=lambda _: idle_connection_client(
                    args.host, args.port, args.hold, args.connect_timeout
                ),
            )
        elif mode == "register":
            summary = await run_batched(
                total_clients=load,
                concurrency=min(args.concurrency, load),
                summary_name=f"register load={load} concurrency={min(args.concurrency, load)}",
                worker_coro_factory=lambda _: register_client(args.host, args.port, args.io_timeout),
            )
        elif mode == "upload":
            summary = await run_batched(
                total_clients=load,
                concurrency=min(args.concurrency, load),
                summary_name=(
                    f"upload load={load} concurrency={min(args.concurrency, load)} "
                    f"file_size={args.file_size} chunk_size={args.chunk_size}"
                ),
                worker_coro_factory=lambda _: upload_client(
                    args.host,
                    args.port,
                    args.io_timeout,
                    args.file_size,
                    args.chunk_size,
                ),
            )
        elif mode == "relogin":
            summary = await run_batched(
                total_clients=load,
                concurrency=min(args.concurrency, load),
                summary_name=f"relogin load={load} concurrency={min(args.concurrency, load)}",
                worker_coro_factory=lambda _: relogin_client(
                    args.host,
                    args.port,
                    args.io_timeout,
                ),
            )
        elif mode == "churn":
            summary = await run_batched(
                total_clients=load,
                concurrency=min(args.concurrency, load),
                summary_name=f"churn (short-lived connections) load={load} concurrency={min(args.concurrency, load)} connection_per_worker={args.connections_per_worker}",
                worker_coro_factory=lambda _: churn_client(args.host, args.port, args.io_timeout, args.connections_per_worker),
            )
        elif mode == "mixed":
            async def mixed_worker(i: int):
                r = random.random()
                if r < 0.25:
                    return await relogin_client(args.host,args.port,args.io_timeout), "relogin"
                elif r < 0.5:
                    return await register_client(args.host,args.port,args.io_timeout), "register"
                else:
                    return await upload_client(args.host,args.port,args.io_timeout,args.file_size,args.chunk_size) , "upload"

            summary, per_operation_summaries = await run_mixed_batched(
                total_clients=load,
                concurrency=min(args.concurrency, load),
                summary_name=(
                    f"mixed load={load} concurrency={min(args.concurrency, load)} "
                    f"file_size={args.file_size} chunk_size={args.chunk_size}"
                ),
                worker_coro_factory=mixed_worker,
            )
        else:
            raise RuntimeError(f"unknown mode: {mode}")
    finally:
        await monitor.stop()

    after = monitor.snapshot()
    peak = monitor.peak_snapshot()
    elapsed = time.perf_counter() - started

    return StageReport(
        load=load,
        summary=summary,
        metrics_before=before,
        metrics_after=after,
        metrics_peak=peak,
        elapsed_s=elapsed,
        per_operation_summaries=per_operation_summaries
    )


def should_stop(args, report: StageReport) -> Optional[str]:
    s = report.summary

    if s.failure_rate > args.stop_failure_rate:
        return f"failure_rate {s.failure_rate * 100:.1f}% > threshold {args.stop_failure_rate * 100:.1f}%"

    if s.p95_ms > args.stop_p95_ms:
        return f"p95 {s.p95_ms:.2f}ms > threshold {args.stop_p95_ms:.2f}ms"

    if report.metrics_peak is not None:
        if report.metrics_peak.rss_mb > args.stop_rss_mb:
            return f"rss {report.metrics_peak.rss_mb:.1f}MB > threshold {args.stop_rss_mb:.1f}MB"
        if report.metrics_peak.cpu_percent > args.stop_cpu_percent:
            return f"cpu {report.metrics_peak.cpu_percent:.1f}% > threshold {args.stop_cpu_percent:.1f}%"

    return None


def print_stage_report(report: StageReport):
    report.summary.print_verbose()
    if report.per_operation_summaries:
        print("per_operation:")
        for operation, operation_summary in report.per_operation_summaries.items():
            print(
                f"  {operation}: "
                f"total={operation_summary.total} "
                f"ok={operation_summary.ok} "
                f"rejected={operation_summary.rejected} "
                f"failed={operation_summary.failed} "
                f"success_rate={operation_summary.success_rate * 100:.1f}%"
            )
            if operation_summary.durations_ms:
                print(
                    f"    avg_ms={operation_summary.avg_ms:.2f} "
                    f"p95_ms={operation_summary.p95_ms:.2f} "
                    f"p99_ms={operation_summary.p99_ms:.2f} "
                    f"max_ms={operation_summary.max_ms:.2f}"
                )
            if operation_summary.errors:
                print("    errors:")
                for k, v in sorted(operation_summary.errors.items(), key=lambda x: (-x[1], x[0])):
                    print(f"      {k}: {v}")

    print(f"elapsed_s={report.elapsed_s:.2f}")
    if report.metrics_before:
        print(f"server_before: {report.metrics_before.short_str()}")
    if report.metrics_after:
        print(f"server_after:  {report.metrics_after.short_str()}")
    if report.metrics_peak:
        print(f"server_peak:   {report.metrics_peak.short_str()}")
    if report.stop_reason:
        print(f"stop_reason: {report.stop_reason}")


def print_final_table(reports: list[StageReport]):
    print("\n===== RAMP-UP SUMMARY =====")
    header = (
        f"{'load':>6}  {'ok':>5}  {'rej':>5}  {'fail':>5}  {'succ%':>7}  "
        f"{'avg_ms':>10}  {'p95_ms':>10}  {'max_ms':>10}  "
        f"{'rss_peak_mb':>12}  {'cpu_peak%':>10}  {'threads':>8}"
    )
    print(header)
    print("-" * len(header))

    for r in reports:
        peak_rss = f"{r.metrics_peak.rss_mb:.1f}" if r.metrics_peak else "-"
        peak_cpu = f"{r.metrics_peak.cpu_percent:.1f}" if r.metrics_peak else "-"
        peak_threads = f"{r.metrics_peak.num_threads}" if r.metrics_peak else "-"
        print(
            f"{r.load:>6}  "
            f"{r.summary.ok:>5}  "
            f"{r.summary.rejected:>5}  "
            f"{r.summary.failed:>5}  "
            f"{r.summary.success_rate * 100:>6.1f}%  "
            f"{r.summary.avg_ms:>10.2f}  "
            f"{r.summary.p95_ms:>10.2f}  "
            f"{r.summary.max_ms:>10.2f}  "
            f"{peak_rss:>12}  "
            f"{peak_cpu:>10}  "
            f"{peak_threads:>8}"
        )

    last = reports[-1] if reports else None
    if last and last.stop_reason:
        print(f"\nStopped early: {last.stop_reason}")


def parse_ramp(ramp_str: str) -> list[int]:
    values = []
    for part in ramp_str.split(","):
        part = part.strip()
        if not part:
            continue
        values.append(int(part))
    if not values:
        raise ValueError("ramp must contain at least one integer")
    return values

def build_run_id(mode: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    return f"{ts}_{mode}_ramp"


def build_scenario_params(args, mode: str) -> dict:
    params = {
        "io_timeout_s": args.io_timeout,
    }

    if mode == "idle":
        params["hold_s"] = args.hold
        params["connect_timeout_s"] = args.connect_timeout
        params["file_size_bytes"] = None
        params["chunk_size_bytes"] = None
    elif mode in ("upload", "mixed"):
        params["hold_s"] = None
        params["connect_timeout_s"] = None
        params["file_size_bytes"] = args.file_size
        params["chunk_size_bytes"] = args.chunk_size
    else:
        params["hold_s"] = None
        params["connect_timeout_s"] = None
        params["file_size_bytes"] = None
        params["chunk_size_bytes"] = None

    return params


def build_final_status(reports: list[StageReport], exit_code: int) -> dict:
    stopped_early = bool(reports and reports[-1].stop_reason)
    completed_all_stages = not stopped_early

    return {
        "completed_all_stages": completed_all_stages,
        "stopped_early": stopped_early,
        "final_exit_code": exit_code,
    }


def run_report_to_dict(args, mode: str, reports: list[StageReport], exit_code: int) -> dict:
    return {
        "run_id": build_run_id(mode),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": "stage6-v1",
        "server": {
            "host": args.host,
            "port": args.port,
            "server_pid": args.server_pid,
        },
        "scenario": {
            "mode": mode,
            "ramp": parse_ramp(args.ramp),
            "concurrency_limit": args.concurrency,
            "pause_between_stages_s": args.pause_between_stages,
        },
        "thresholds": {
            "stop_failure_rate": args.stop_failure_rate,
            "stop_p95_ms": args.stop_p95_ms,
            "stop_rss_mb": args.stop_rss_mb,
            "stop_cpu_percent": args.stop_cpu_percent,
        },
        "scenario_params": build_scenario_params(args, mode),
        "stages": [
            stage_report_to_dict(
                report,
                concurrency=min(args.concurrency, report.load),
            )
            for report in reports
        ],
        "final_status": build_final_status(reports, exit_code),
    }


def save_run_report(run_report: dict, output_dir: str = "tools/results") -> Path:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    file_name = f"{run_report['run_id']}.json"
    out_path = out_dir / file_name

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(run_report, f, indent=2)

    return out_path


async def run_ramp(args, mode: str) -> int:
    loads = parse_ramp(args.ramp)
    reports: list[StageReport] = []

    for load in loads:
        report = await run_single_stage(args, mode, load)
        report.stop_reason = should_stop(args, report)
        reports.append(report)
        print_stage_report(report)

        if report.stop_reason:
            break

        if args.pause_between_stages > 0:
            await asyncio.sleep(args.pause_between_stages)

    print_final_table(reports)

    if reports and reports[-1].stop_reason:
        exit_code = 2
    elif all(r.summary.failed == 0 for r in reports):
        exit_code = 0
    else:
        exit_code = 1

    run_report = run_report_to_dict(args, mode, reports, exit_code)
    output_path = save_run_report(run_report)
    print(f"\nSaved run report to: {output_path}")

    return exit_code


def build_common_parser(parser: argparse.ArgumentParser):
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1234)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--io-timeout", type=float, default=30.0)

    parser.add_argument("--ramp", default="1,5,10,20,50,100")
    parser.add_argument("--pause-between-stages", type=float, default=1.0)

    parser.add_argument("--server-pid", type=int, default=None)
    parser.add_argument("--sample-interval", type=float, default=0.1)

    parser.add_argument("--stop-failure-rate", type=float, default=0.10)
    parser.add_argument("--stop-p95-ms", type=float, default=30000.0)
    parser.add_argument("--stop-rss-mb", type=float, default=2048.0)
    parser.add_argument("--stop-cpu-percent", type=float, default=95.0)


def parse_args():
    parser = argparse.ArgumentParser(description="SEFFP load and capacity test runner")
    sub = parser.add_subparsers(dest="mode", required=True)

    idle_parser = sub.add_parser("idle")
    build_common_parser(idle_parser)
    idle_parser.add_argument("--hold", type=float, default=20.0)
    idle_parser.add_argument("--connect-timeout", type=float, default=10.0)

    register_parser = sub.add_parser("register")
    build_common_parser(register_parser)

    relogin_parser = sub.add_parser("relogin")
    build_common_parser(relogin_parser)

    upload_parser = sub.add_parser("upload")
    build_common_parser(upload_parser)
    upload_parser.add_argument("--file-size", type=int, default=100_000)
    upload_parser.add_argument("--chunk-size", type=int, default=60_000)

    mixed_parser = sub.add_parser("mixed")
    build_common_parser(mixed_parser)
    mixed_parser.add_argument("--file-size", type=int, default=100_000)
    mixed_parser.add_argument("--chunk-size", type=int, default=60_000)

    churn_parser = sub.add_parser("churn")
    build_common_parser(churn_parser)
    churn_parser.add_argument("--connections-per-worker", type=int, default=5)


    return parser.parse_args()


async def main():
    args = parse_args()
    return await run_ramp(args, args.mode)


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        raise SystemExit(130)
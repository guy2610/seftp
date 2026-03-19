import asyncio
import threading
import time

import pytest

from src.bounded_executor import BoundedExecutor


def test_init_rejects_non_positive_limits():
    with pytest.raises(ValueError):
        BoundedExecutor(max_workers=0, max_in_flight=1)

    with pytest.raises(ValueError):
        BoundedExecutor(max_workers=1, max_in_flight=0)


def test_init_rejects_in_flight_smaller_than_workers():
    with pytest.raises(ValueError):
        BoundedExecutor(max_workers=3, max_in_flight=2)


@pytest.mark.asyncio
async def test_run_returns_function_result():
    executor = BoundedExecutor(max_workers=2, max_in_flight=2)
    try:
        result = await executor.run(lambda x, y: x + y, 2, 3)
        assert result == 5
    finally:
        executor.shutdown()


@pytest.mark.asyncio
async def test_run_propagates_exceptions():
    executor = BoundedExecutor(max_workers=2, max_in_flight=2)

    def boom():
        raise RuntimeError("boom")

    try:
        with pytest.raises(RuntimeError, match="boom"):
            await executor.run(boom)
    finally:
        executor.shutdown()


@pytest.mark.asyncio
async def test_run_executes_multiple_jobs():
    executor = BoundedExecutor(max_workers=2, max_in_flight=4)

    def work(x):
        time.sleep(0.05)
        return x * 2

    try:
        results = await asyncio.gather(
            executor.run(work, 1),
            executor.run(work, 2),
            executor.run(work, 3),
        )
        assert results == [2, 4, 6]
    finally:
        executor.shutdown()


@pytest.mark.asyncio
async def test_max_in_flight_limits_actual_parallel_work():
    executor = BoundedExecutor(max_workers=4, max_in_flight=2)

    active = 0
    max_active = 0
    lock = threading.Lock()

    def work():
        nonlocal active, max_active
        with lock:
            active += 1
            if active > max_active:
                max_active = active
        try:
            time.sleep(0.15)
            return 1
        finally:
            with lock:
                active -= 1

    try:
        results = await asyncio.gather(
            executor.run(work),
            executor.run(work),
            executor.run(work),
            executor.run(work),
        )
        assert results == [1, 1, 1, 1]
        assert max_active <= 2
    finally:
        executor.shutdown()
import pytest

from src.runtime_metrics import RuntimeMetrics


@pytest.mark.asyncio
async def test_runtime_metrics_initial_snapshot():
    metrics = RuntimeMetrics()

    snapshot = await metrics.snapshot()

    assert snapshot == {
        "active_connections": 0,
        "active_uploads": 0,
        "rejected_connections": 0,
        "rejected_uploads": 0,
        "responses_1607": 0,
        "rate_limited_requests": 0,
    }


@pytest.mark.asyncio
async def test_runtime_metrics_updates_and_counters():
    metrics = RuntimeMetrics()

    await metrics.set_active_connections(5)
    await metrics.set_active_uploads(2)
    await metrics.inc_rejected_connections()
    await metrics.inc_rejected_uploads()
    await metrics.inc_responses_1607()
    await metrics.inc_rate_limited_requests()

    snapshot = await metrics.snapshot()

    assert snapshot["active_connections"] == 5
    assert snapshot["active_uploads"] == 2
    assert snapshot["rejected_connections"] == 1
    assert snapshot["rejected_uploads"] == 1
    assert snapshot["responses_1607"] == 1
    assert snapshot["rate_limited_requests"] == 1


@pytest.mark.asyncio
async def test_runtime_metrics_counters_accumulate():
    metrics = RuntimeMetrics()

    await metrics.inc_rejected_uploads()
    await metrics.inc_rejected_uploads()
    await metrics.inc_responses_1607()
    await metrics.inc_responses_1607()
    await metrics.inc_responses_1607()

    snapshot = await metrics.snapshot()

    assert snapshot["rejected_uploads"] == 2
    assert snapshot["responses_1607"] == 3

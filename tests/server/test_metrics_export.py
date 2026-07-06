import json

import pytest

from src.metrics_export import runtime_metrics_json
from src.runtime_metrics import RuntimeMetrics


@pytest.mark.asyncio
async def test_runtime_metrics_json_exports_snapshot():
    metrics = RuntimeMetrics()

    await metrics.set_active_connections(2)
    await metrics.set_active_uploads(1)
    await metrics.inc_rejected_connections()
    await metrics.inc_rejected_uploads()
    await metrics.inc_responses_1607()
    await metrics.inc_rate_limited_requests()

    encoded = await runtime_metrics_json(metrics)
    decoded = json.loads(encoded)

    assert decoded == {
        "runtime_metrics": {
            "active_connections": 2,
            "active_uploads": 1,
            "rejected_connections": 1,
            "rejected_uploads": 1,
            "responses_1607": 1,
            "rate_limited_requests": 1,
        }
    }
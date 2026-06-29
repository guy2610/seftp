import json
from typing import Any

from .runtime_metrics import RuntimeMetrics


async def runtime_metrics_json(metrics: RuntimeMetrics) -> str:
    snapshot = await metrics.snapshot()
    payload: dict[str, Any] = {
        "runtime_metrics": snapshot,
    }
    return json.dumps(payload, sort_keys=True)
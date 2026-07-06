import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuntimeMetrics:
    active_connections: int = 0
    active_uploads: int = 0
    rejected_connections: int = 0
    rejected_uploads: int = 0
    responses_1607: int = 0
    rate_limited_requests: int = 0

    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def set_active_connections(self, value: int) -> None:
        async with self._lock:
            self.active_connections = int(value)

    async def set_active_uploads(self, value: int) -> None:
        async with self._lock:
            self.active_uploads = int(value)

    async def inc_rejected_connections(self) -> None:
        async with self._lock:
            self.rejected_connections += 1

    async def inc_rejected_uploads(self) -> None:
        async with self._lock:
            self.rejected_uploads += 1

    async def inc_responses_1607(self) -> None:
        async with self._lock:
            self.responses_1607 += 1

    async def inc_rate_limited_requests(self) -> None:
        async with self._lock:
            self.rate_limited_requests += 1

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "active_connections": self.active_connections,
                "active_uploads": self.active_uploads,
                "rejected_connections": self.rejected_connections,
                "rejected_uploads": self.rejected_uploads,
                "responses_1607": self.responses_1607,
                "rate_limited_requests": self.rate_limited_requests,
            }

import asyncio
from typing import Optional

class ConnectionLimiter():
    def __init__(self, max_connections: int, max_connections_per_ip: int):
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        if max_connections_per_ip <= 0:
            raise ValueError("max_connections_per_ip must be positive")
        if max_connections_per_ip > max_connections:
            raise ValueError("max_connections_per_ip must not exceed max_connections")
        self.max_connections_per_ip = max_connections_per_ip
        self.max_connections = max_connections
        self.active_total = 0
        self._lock = asyncio.Lock()
        self.active_by_ip: dict[str, int] = {}

    async def try_acquire(self, peer_ip: str) -> tuple[bool, Optional[str]]:
        async with self._lock:
            if self.active_total >= self.max_connections:
                return False, "server_full"

            if self.active_by_ip.get(peer_ip, 0) >= self.max_connections_per_ip:
                return False, "per_ip_limit"

            self.active_total += 1
            self.active_by_ip[peer_ip] = self.active_by_ip.get(peer_ip, 0) + 1
            return True, None

    async def release(self, peer_ip)-> None:
        async with self._lock:
            count = self.active_by_ip.get(peer_ip, 0)
            if count <= 0:
                return

            self.active_total -= 1
            if count == 1:
                self.active_by_ip.pop(peer_ip, None)
            else:
                self.active_by_ip[peer_ip] = count - 1

    async def current_active(self)->tuple[int, dict[str, int]]:
        async with self._lock:
            return self.active_total, dict(self.active_by_ip)
import asyncio


class UploadLimiter:
    def __init__(self, max_concurrent_uploads: int):
        if max_concurrent_uploads <= 0:
            raise ValueError("max_concurrent_uploads must be positive")
        self.max_concurrent_uploads = max_concurrent_uploads
        self.active_uploads = 0
        self._lock = asyncio.Lock()

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self.active_uploads >= self.max_concurrent_uploads:
                return False
            self.active_uploads += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self.active_uploads > 0:
                self.active_uploads -= 1

    async def current_active(self) -> int:
        async with self._lock:
            return self.active_uploads
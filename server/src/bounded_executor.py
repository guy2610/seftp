import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial

class BoundedExecutor:
    def __init__(self, max_workers: int, max_in_flight: int):
        if max_workers <= 0:
            raise ValueError("max_workers must be positive")
        if max_in_flight <= 0:
            raise ValueError("max_in_flight must be positive")
        if max_in_flight < max_workers:
            raise ValueError("max_in_flight must be >= max_workers")

        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._semaphore = asyncio.Semaphore(max_in_flight)

    async def run(self, func, *args, **kwargs):
        loop = asyncio.get_running_loop()
        async with self._semaphore:
            bound = partial(func, *args, **kwargs)
            return await loop.run_in_executor(self._executor, bound)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True)
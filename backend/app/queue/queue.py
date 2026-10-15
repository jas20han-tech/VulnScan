"""Job queue abstraction.

v1 uses an in-process asyncio worker pool. The interface is kept abstract so it
can be swapped for Celery/Redis later without touching module code.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


class JobQueue:
    """Minimal in-process async job queue.

    Executes submitted jobs on a bounded worker pool. Jobs are plain coroutine
    factories (callables returning an awaitable), which keeps the abstraction
    independent of any specific payload type.
    """

    def __init__(
        self,
        max_workers: int = 3,
        queue_size: int = 100,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._queue: asyncio.Queue[Callable[[], Awaitable[Any]]] = asyncio.Queue(
            maxsize=queue_size
        )
        self._max_workers = max_workers
        self._workers: list[asyncio.Task] = []
        self._loop = loop
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._loop = asyncio.get_running_loop()
        self._started = True
        for _ in range(self._max_workers):
            task = self._loop.create_task(self._worker())
            self._workers.append(task)

    async def _worker(self) -> None:
        while True:
            job = await self._queue.get()
            try:
                await job()
            except Exception:  # noqa: BLE001 - keep the worker alive
                # Errors are surfaced to the scan record by the job itself.
                pass
            finally:
                self._queue.task_done()

    def submit(self, job: Callable[[], Awaitable[Any]]) -> None:
        self._queue.put_nowait(job)

    async def close(self) -> None:
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        self._started = False


# Module-level singleton queue.
_queue: JobQueue | None = None


def get_queue(max_workers: int = 3) -> JobQueue:
    global _queue
    if _queue is None:
        _queue = JobQueue(max_workers=max_workers)
    return _queue

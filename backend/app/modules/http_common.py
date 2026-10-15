"""Shared HTTP helpers for detection modules.

Provides a polite, same-origin-only, rate-limited HTTP client that modules use
for their confirmation requests. Constructs clients only against a
ConfirmedTarget, preserving the consent guarantee.
"""
from __future__ import annotations

import asyncio
import httpx

from app.config import get_settings
from app.core.domain import ConfirmedTarget


class ScanHTTPClient:
    def __init__(self, target: ConfirmedTarget, base_url: str | None = None):
        settings = get_settings()
        self.target = target
        self.base_url = base_url or target.base_url
        self.delay = settings.SCAN_DEFAULT_DELAY_MS / 1000.0
        self.max_concurrent = settings.SCAN_MAX_CONCURRENT_REQUESTS
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._ua = f"VulnScan/1.0 (authorized-scan; contact={target.owner_note or 'default'})"

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            headers={"User-Agent": self._ua},
            timeout=httpx.Timeout(20.0),
            follow_redirects=True,
        )

    async def get(self, *args, **kwargs):
        async with self._semaphore:
            try:
                async with self.client() as c:
                    r = await c.get(*args, **kwargs)
                    await asyncio.sleep(self.delay)
                    return r
            except httpx.HTTPError:
                return None

    async def post(self, *args, **kwargs):
        async with self._semaphore:
            try:
                async with self.client() as c:
                    r = await c.post(*args, **kwargs)
                    await asyncio.sleep(self.delay)
                    return r
            except httpx.HTTPError:
                return None

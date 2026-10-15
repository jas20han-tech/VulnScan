"""DetectionModule protocol shared by all modules (07-11).

Detection must be deterministic and explainable. No module here calls an LLM.
"""
from __future__ import annotations

from typing import Protocol

from app.core.domain import ConfirmedTarget, CrawlSurface, Finding


class DetectionModule(Protocol):
    name: str

    async def run(
        self,
        target: ConfirmedTarget,
        surface: CrawlSurface,
        http_client=None,
        progress_callback=None,
    ) -> list[Finding]:
        ...

"""Scan worker - runs the pipeline crawl -> detect -> store -> fix -> report.

Progress mapping (from 13-reporting-dashboard-backend.md):
  crawl            0-30%
  sqli            30-45%
  xss             45-60%
  auth            60-70%
  secrets         70-80%
  headers         80-90%
  fix generation  90-95%
  report          95-100%
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from app.config import get_settings
from app.db.session import async_session
from app.db.models import CrawlResult, Finding as FindingRow, Scan
from app.crawler.crawler import Crawler
from app.consent.service import build_confirmed_target
from app.core.domain import ConfirmedTarget
from app.modules.sqli.module import SQLiModule
from app.modules.xss.module import XSSModule
from app.modules.auth.module import AuthModule
from app.modules.secrets.module import SecretsModule
from app.modules.headers.module import HeadersModule
from app.modules.http_common import ScanHTTPClient
from app.fixgen.fixgen import generate_and_store_fix

logger = logging.getLogger(__name__)

RANGE = {
    "crawl": (0, 30),
    "sqli": (30, 45),
    "xss": (45, 60),
    "auth": (60, 70),
    "secrets": (70, 80),
    "headers": (80, 90),
    "fix": (90, 95),
    "report": (95, 100),
}


def _scale(low: int, high: int, cur: int, total: int) -> int:
    if total <= 0:
        return high
    frac = cur / total
    return low + int(frac * (high - low))


async def _set_scan_status(scan_id: str, status: str, progress: int | None = None):
    async with async_session() as s:
        scan = await s.get(Scan, scan_id)
        if scan is None:
            return
        if status:
            scan.status = status
        if progress is not None:
            scan.progress_pct = progress
        if status == "report_ready":
            from app.db.models import utcnow

            scan.completed_at = utcnow()
        await s.commit()


async def run_scan(scan_id: str) -> None:
    """Entry point enqueued on the job queue. Never raises - failures are
    recorded on the scan row so partial results survive."""
    try:
        await _execute(scan_id)
    except Exception as e:  # noqa: BLE001
        logger.exception("Scan %s failed", scan_id)
        async with async_session() as s:
            scan = await s.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.error_message = str(e)
                await s.commit()


async def _execute(scan_id: str) -> None:
    async with async_session() as s:
        scan = await s.get(Scan, scan_id)
        if scan is None:
            return
        target_id = scan.target_id
        consent_snapshot = scan.consent_snapshot

    target = await build_confirmed_target_cached(target_id)
    client = ScanHTTPClient(target)

    # Crawl.
    await _set_scan_status(scan_id, "crawling", RANGE["crawl"][0])
    crawler = Crawler(target)

    async def crawl_progress(pct: int) -> None:
        await _set_scan_status(scan_id, None, int(pct))

    surface = await crawler.crawl(progress_callback=crawl_progress)
    await _persist_crawl(scan_id, surface, target)

    # Detection modules.
    modules = [
        ("sqli", SQLiModule(), RANGE["sqli"]),
        ("xss", XSSModule(), RANGE["xss"]),
        ("auth", AuthModule(), RANGE["auth"]),
        ("secrets", SecretsModule(), RANGE["secrets"]),
        ("headers", HeadersModule(), RANGE["headers"]),
    ]

    await _set_scan_status(scan_id, "scanning", RANGE["sqli"][0])
    all_findings = []
    for name, mod, (lo, hi) in modules:
        await _set_scan_status(scan_id, "scanning", lo)
        if name == "xss":
            # XSS module manages its own progress callback signature.
            findings = await mod.run(target, surface, http_client=client)
        else:
            findings = await mod.run(target, surface, http_client=client)
        for f in findings:
            await _persist_finding(scan_id, f)
            all_findings.append(f)

    # Fix generation.
    await _set_scan_status(scan_id, "generating_fixes", RANGE["fix"][0])
    async with async_session() as s:
        rows = (
            (await s.execute(
                select(FindingRow).where(
                    FindingRow.scan_id == scan_id
                )
            ))
            .scalars()
            .all()
        )
    for i, row in enumerate(rows):
        await generate_and_store_fix(s, row)
        await _set_scan_status(
            scan_id, None, _scale(RANGE["fix"][0], RANGE["fix"][1], i, len(rows))
        )

    # Report.
    await _set_scan_status(scan_id, "generating_fixes", RANGE["report"][0])
    from app.reporting.report import generate_report

    await generate_report(scan_id)
    await _set_scan_status(scan_id, "report_ready", 100)


async def build_confirmed_target_cached(target_id: str) -> ConfirmedTarget:
    async with async_session() as s:
        return await build_confirmed_target(s, target_id)


async def _persist_crawl(scan_id: str, surface, target: ConfirmedTarget) -> None:
    async with async_session() as s:
        for route in surface.routes:
            forms_for_route = [
                {
                    "action": form.action,
                    "method": form.method,
                    "fields": [{"name": f.name, "type": f.input_type} for f in form.fields],
                }
                for form in surface.forms
                if form.route_url == route.url or form.action == route.url
            ]
            js_for_route = [
                b for b in surface.js_bundles if b.startswith(route.url)
            ]
            if not js_for_route and surface.js_bundles:
                js_for_route = surface.js_bundles
            row = CrawlResult(
                scan_id=scan_id,
                route=route.url,
                method=route.method,
                forms=forms_for_route,
                js_bundles=js_for_route,
                baseline_headers=dict(route.baseline_headers),
            )
            s.add(row)
        await s.commit()


async def _persist_finding(scan_id: str, f) -> None:
    async with async_session() as s:
        row = FindingRow(
            scan_id=scan_id,
            module=f.module,
            subtype=f.subtype,
            severity=f.severity,
            route=f.route,
            parameter=f.parameter,
            evidence=f.evidence,
            reproducible=f.reproducible,
        )
        s.add(row)
        await s.commit()

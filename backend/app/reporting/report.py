"""Reporting & dashboard backend (Epic 9, backend half).

Generates an HTML report (always) and attempts PDF conversion via WeasyPrint.
If WeasyPrint is unavailable/fails on the platform, records the HTML path with
a note - report generation must never fail the scan.
"""
from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

from app.config import get_settings
from app.db.session import async_session
from app.db.models import (
    CrawlResult,
    Finding,
    FixSuggestion,
    Report,
    Scan,
    Target,
)
from app.db.models import utcnow

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


async def get_report_context(scan_id: str) -> dict | None:
    async with async_session() as s:
        scan = await s.get(Scan, scan_id)
        if scan is None:
            return None
        target = await s.get(Target, scan.target_id)
        findings = (
            (await s.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            ))
            .scalars()
            .all()
        )
        crawl = (
            (await s.execute(
                select(CrawlResult).where(CrawlResult.scan_id == scan_id)
            ))
            .scalars()
            .all()
        )
        # Query fixes by finding_id properly.
        fixes = {}
        for f in findings:
            res = await s.execute(
                select(FixSuggestion).where(FixSuggestion.finding_id == f.id)
            )
            fix = res.scalar_one_or_none()
            if fix is not None:
                fixes[f.id] = fix

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings_sorted = sorted(
            findings, key=lambda f: severity_order.get(f.severity, 9)
        )
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "target": target,
            "scan": scan,
            "findings": findings_sorted,
            "fixes": fixes,
            "crawl": crawl,
            "counts": counts,
            "coverage": {
                "routes": [c.route for c in crawl],
                "route_count": len(crawl),
                "limits": getattr(scan, "error_message", None),
            },
        }


async def generate_report(scan_id: str) -> str | None:
    ctx = await get_report_context(scan_id)
    if ctx is None:
        return None
    template = _env.get_template("report.html")
    html = template.render(**ctx)

    settings = get_settings()
    out_dir = Path(settings.REPORT_OUTPUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / f"report_{scan_id}.html"
    html_path.write_text(html, encoding="utf-8")

    file_path = str(html_path)

    # Attempt PDF conversion (best effort).
    try:
        from weasyprint import HTML

        pdf_path = out_dir / f"report_{scan_id}.pdf"
        HTML(string=html, base_url=str(html_path.parent)).write_pdf(str(pdf_path))
        file_path = str(pdf_path)
    except Exception as e:  # noqa: BLE001
        logger.warning("PDF rendering unavailable (%s); keeping HTML report.", e)

    async with async_session() as s:
        report = Report(scan_id=scan_id, file_path=file_path, generated_at=utcnow())
        s.add(report)
        await s.commit()
    return file_path

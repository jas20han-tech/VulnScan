"""Full end-to-end flow: consent gate -> scan -> findings -> fixes -> report.

Exercises the service layer, worker pipeline, fix generation, and report
rendering against the vulnerable testbed - without needing the HTTP server to
be running (worker talks directly to the DB/target over the network).
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.config import get_settings
from app.db.session import async_session, init_db
from app.db.models import FixSuggestion, Report, Scan, Target
from app.consent.service import expected_consent_phrase, register_target
from app.core.worker import run_scan
from app.reporting.report import generate_report

PORT = 8098
BASE_URL = f"http://127.0.0.1:{PORT}"


@pytest_asyncio.fixture(scope="module")
def testbed():
    import uvicorn

    from testbeds.vulnerable_app import testbed_app

    config = uvicorn.Config(
        testbed_app.app, host="127.0.0.1", port=PORT, log_level="error"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            httpx.get(BASE_URL + "/", timeout=1)
            return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("testbed failed to start")


@pytest.mark.asyncio
async def test_full_scan_flow(testbed):
    settings = get_settings()
    # Ensure tables exist, then clean them for a clean assertion.
    await init_db()
    async with async_session() as s:
        from app.db.models import Base
        from app.db.session import engine

        async with engine.begin() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                await conn.execute(table.delete())

    # 1. Register target
    async with async_session() as s:
        target = await register_target(
            s, "127.0.0.1", BASE_URL, "flow-test"
        )
        target_id = target.id
        phrase = expected_consent_phrase("127.0.0.1")

    # Consent NOT yet confirmed.
    async with async_session() as s:
        t = await s.get(Target, target_id)
        assert t.consent_confirmed_at is None

    # The consent confirmation is what the API does; replicate it here via
    # the service that the API calls (build a confirmed target).
    from app.consent.service import confirm_consent

    async with async_session() as s:
        await confirm_consent(s, target_id, phrase)

    async with async_session() as s:
        t = await s.get(Target, target_id)
        assert t.consent_confirmed_at is not None

    # 2. Create scan + run worker.
    from app.db.models import utcnow

    async with async_session() as s:
        scan = Scan(
            target_id=target_id,
            status="queued",
            consent_snapshot={
                "domain": "127.0.0.1",
                "consent_confirmed_at": str(t.consent_confirmed_at),
                "phrase_typed": phrase,
            },
            started_at=utcnow(),
            progress_pct=0,
        )
        s.add(scan)
        await s.commit()
        scan_id = scan.id

    # Run the pipeline synchronously (the job queue would do this in prod).
    await run_scan(scan_id)

    # 3. Assert scan state.
    async with async_session() as s:
        scan = await s.get(Scan, scan_id)
        assert scan.status == "report_ready", f"scan failed: {scan.error_message}"
        assert scan.progress_pct == 100

    # 4. Assert findings exist across expected modules.
    from sqlalchemy import select

    async with async_session() as s:
        rows = (
            (await s.execute(select(Scan)))
            .scalars()
            .all()
        )
        from app.db.models import Finding

        findings = (
            (await s.execute(select(Finding).where(Finding.scan_id == scan_id)))
            .scalars()
            .all()
        )
        assert findings, "expected findings from the full scan"
        modules = {f.module for f in findings}
        assert "sqli" in modules
        assert "xss" in modules
        assert "secrets" in modules
        assert "headers" in modules

        # Fix suggestions present for findings (template fallback, no LLM).
        fixes = (
            (await s.execute(select(FixSuggestion).where(
                FixSuggestion.finding_id.in_([f.id for f in findings])
            )))
            .scalars()
            .all()
        )
        assert fixes, "expected fix suggestions to be generated"

        # Report generated.
        report = (
            (await s.execute(select(Report).where(Report.scan_id == scan_id)))
            .scalar_one_or_none()
        )
        assert report is not None
        report_path = Path(report.file_path)
        assert report_path.exists(), f"report file missing: {report_path}"

    # 5. Verify secrets redaction: the raw AWS secret must NOT appear in DB.
    async with async_session() as s:
        from app.db.models import Finding as F

        secrets_finding = (
            (await s.execute(select(F).where(
                F.scan_id == scan_id, F.module == "secrets"
            )))
            .scalars()
            .all()
        )
        for sf in secrets_finding:
            redacted = sf.evidence.get("matched_value_redacted", "")
            assert "AKIAIOSFODNN7ABCDEFG" not in redacted, "secret leaked in full!"
            assert redacted.startswith("AKIA"), "redaction should keep first 4 chars"

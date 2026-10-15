"""Live HTTP API contract test (04-api-contract.md).

Starts the REAL VulnScan backend (uvicorn) + the testbed target, then drives the
full REST surface over HTTP: register -> consent -> scan -> poll -> findings ->
fix -> report. Verifies error codes, the consent gate, and the worker pipeline.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

API_PORT = 8010
TARGET_PORT = 8011
TARGET_URL = f"http://127.0.0.1:{TARGET_PORT}"
API_URL = f"http://127.0.0.1:{API_PORT}"


@pytest.fixture(scope="module", autouse=True)
def servers():
    # Testbed target.
    from testbeds.vulnerable_app import testbed_app

    tconf = uvicorn.Config(
        testbed_app.app, host="127.0.0.1", port=TARGET_PORT, log_level="error"
    )
    tserver = uvicorn.Server(tconf)
    tt = threading.Thread(target=tserver.run, daemon=True)
    tt.start()

    # VulnScan backend.
    from app.main import app as vulnscan_app

    vconf = uvicorn.Config(
        vulnscan_app, host="127.0.0.1", port=API_PORT, log_level="error"
    )
    vserver = uvicorn.Server(vconf)
    vt = threading.Thread(target=vserver.run, daemon=True)
    vt.start()

    for _ in range(80):
        try:
            httpx.get(API_URL + "/", timeout=1)
            httpx.get(TARGET_URL + "/", timeout=1)
            break
        except Exception:
            time.sleep(0.25)
    time.sleep(0.5)

    # Ensure fresh tables.
    import asyncio

    async def reset():
        from app.db.session import engine, init_db
        from app.db.models import Base

        await init_db()
        async with engine.begin() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                await conn.execute(table.delete())

    asyncio.run(reset())

    yield
    vserver.should_exit = True
    tserver.should_exit = True


def test_full_api_contract(servers):
    c = httpx.Client(base_url=API_URL, timeout=30)

    # 1. Register target.
    r = c.post(
        "/targets",
        json={
            "domain": "127.0.0.1",
            "base_url": TARGET_URL,
            "owner_note": "api-test",
        },
    )
    assert r.status_code == 201, r.text
    target_id = r.json()["id"]
    assert r.json()["consent_confirmed_at"] is None

    # 2. Starting a scan before consent -> 400.
    r = c.post(f"/targets/{target_id}/scans")
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "consent_not_confirmed"

    # 3. Consent with a WRONG phrase -> 422, no state change.
    r = c.post(f"/targets/{target_id}/consent", json={"typed_phrase": "nope"})
    assert r.status_code == 422, r.text
    r = c.get(f"/targets/{target_id}")
    assert r.json()["consent_confirmed_at"] is None

    # 4. Get the correct phrase and confirm.
    phrase = c.get(f"/targets/{target_id}/consent/phrase").json()["phrase"]
    assert "127.0.0.1" in phrase
    r = c.post(f"/targets/{target_id}/consent", json={"typed_phrase": phrase})
    assert r.status_code == 200, r.text
    assert r.json()["consent_confirmed_at"] is not None

    # 5. Start scan.
    r = c.post(f"/targets/{target_id}/scans")
    assert r.status_code == 202, r.text
    scan_id = r.json()["scan_id"]

    # 6. Poll until report_ready (or failed).
    status = None
    for _ in range(240):
        r = c.get(f"/scans/{scan_id}")
        assert r.status_code == 200
        status = r.json()["status"]
        if status in ("report_ready", "failed"):
            break
        time.sleep(2)
    assert status == "report_ready", f"scan ended in {status}"

    # 7. Findings list.
    r = c.get(f"/scans/{scan_id}/findings")
    assert r.status_code == 200
    findings = r.json()
    assert findings, "expected findings"
    modules = {f["module"] for f in findings}
    assert modules >= {"sqli", "xss", "secrets", "headers"}

    # 8. Full finding + fix.
    fid = findings[0]["id"]
    r = c.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert r.json()["evidence"]

    r = c.get(f"/findings/{fid}/fix")
    assert r.status_code == 200, r.text

    # 9. Report file downloads.
    r = c.get(f"/scans/{scan_id}/report")
    assert r.status_code == 200
    assert r.headers["content-type"] in (
        "application/pdf",
        "text/html; charset=utf-8",
        "text/html",
    )

    c.close()

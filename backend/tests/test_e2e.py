"""End-to-end integration test for the full detection pipeline.

Starts the intentional-vulnerable testbed app on a real local port (as a
background uvicorn server), crawls it, and runs all detection modules,
asserting that each finds its expected vulnerability type.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import sys

import httpx
import pytest_asyncio

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.core.domain import ConfirmedTarget
from app.crawler.crawler import Crawler
from app.modules.auth.module import AuthModule
from app.modules.headers.module import HeadersModule
from app.modules.secrets.module import SecretsModule
from app.modules.sqli.module import SQLiModule
from app.modules.xss.module import XSSModule
from app.modules.http_common import ScanHTTPClient


PORT = 8099
BASE_URL = f"http://127.0.0.1:{PORT}"


def _target() -> ConfirmedTarget:
    return ConfirmedTarget(
        id="t-integration",
        domain="127.0.0.1",
        base_url=BASE_URL,
        owner_note="integration-test",
        consent_confirmed_at=datetime.now(timezone.utc),
    )


def _start_server():
    import uvicorn

    from testbeds.vulnerable_app import testbed_app

    config = uvicorn.Config(
        testbed_app.app, host="127.0.0.1", port=PORT, log_level="error"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    return server


def _wait_ready():
    for _ in range(50):
        try:
            httpx.get(BASE_URL + "/", timeout=1)
            return True
        except Exception:
            time.sleep(0.2)
    return False


@pytest_asyncio.fixture(scope="module")
def live_server():
    server = _start_server()
    assert _wait_ready(), "testbed server failed to start"
    yield server


@pytest_asyncio.fixture(scope="module")
def surface(live_server):
    import asyncio

    target = _target()
    crawler = Crawler(target)
    return asyncio.run(crawler.crawl())


def test_crawl_discovers_routes(surface):
    urls = [r.url for r in surface.routes]
    assert any("/search" in u for u in urls)
    assert any("/login" in u for u in urls)
    assert any(u.endswith("/js/app.js") for u in surface.js_bundles), surface.js_bundles


def test_sqli_detected(surface):
    import asyncio

    target = _target()
    findings = asyncio.run(SQLiModule().run(target, surface))
    sqli = [f for f in findings if f.module == "sqli"]
    assert sqli, f"expected SQLi findings, got {findings}"
    # Boolean SQLi against /api/products should be found.
    boolean = [f for f in sqli if f.subtype == "sqli_boolean"]
    assert boolean, f"expected a boolean SQLi subtype, got {[f.subtype for f in sqli]}"
    assert any("/api/products" in f.route for f in sqli)


def test_xss_detected(surface):
    import asyncio

    target = _target()
    findings = asyncio.run(XSSModule().run(target, surface))
    xss = [f for f in findings if f.module == "xss"]
    assert xss, "expected XSS findings (reflect on /search)"
    assert all(f.evidence.get("execution_confirmed") for f in xss)


def test_auth_cookie_flags_detected(surface):
    import asyncio

    target = _target()
    findings = asyncio.run(AuthModule().run(target, surface))
    auth = [f for f in findings if f.module == "auth"]
    cookie = [f for f in auth if f.subtype == "auth_cookie_flags"]
    assert cookie, "expected weak cookie flags finding"
    missing = {c for f in cookie for c in f.evidence.get("missing_flags", [])}
    assert "HttpOnly" in missing


def test_secrets_detected(surface):
    import asyncio

    target = _target()
    findings = asyncio.run(SecretsModule().run(target, surface))
    secrets = [f for f in findings if f.module == "secrets"]
    assert secrets, "expected secrets finding from JS bundle"
    assert any(f.subtype == "secrets_aws_access_key" for f in secrets)


def test_headers_detected(surface):
    import asyncio

    target = _target()
    findings = asyncio.run(HeadersModule().run(target, surface))
    headers = [f for f in findings if f.module == "headers"]
    names = {f.subtype for f in headers}
    # Testbed sets no security headers, so CSP/HSTS must be flagged.
    assert "headers_content-security-policy" in names


def test_template_fix_generation():
    from app.core.domain import Finding
    from app.fixgen.fixgen import build_template_fix

    f = Finding(
        module="sqli",
        subtype="sqli_boolean",
        severity="high",
        route="/api/search",
        parameter="q",
        evidence={"technique": "boolean"},
        reproducible=True,
    )
    diff, expl, model = build_template_fix(f)
    assert "parameterized" in diff.lower() or "text(" in diff
    assert model == "template"

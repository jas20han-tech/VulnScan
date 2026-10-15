"""XSS detection module (Epic 4).

Confirmation uses the "canary callback" pattern via Playwright: a unique token
is embedded in the payload, and execution is confirmed only when the token
actually fires in a real browser DOM - not by string-presence matching.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import uuid

from app.config import get_settings
from app.core.domain import ConfirmedTarget, CrawlSurface, Finding
from app.modules.http_common import ScanHTTPClient

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

# Payload contexts, each with canary pattern to confirm execution.
# {TOKEN} is replaced with the per-attempt token.
CANARY_JS = "window.__vulnscan_hit&&window.__vulnscan_hit('{TOKEN}')"

PAYLOAD_CONTEXTS = {
    "html_raw": "<script>{JS}</script>",
    "html_img_onerror": "<img src=x onerror=\"{JS}\">",
    "html_svg_onload": "<svg onload=\"{JS}\"></svg>",
    "attr_breakout": "\"><script>{JS}</script>",
    "js_string_breakout": "';{JS};//",
}


class XSSModule:
    name = "xss"

    def __init__(self, require_playwright: bool = True):
        self.require_playwright = require_playwright

    async def run(
        self,
        target: ConfirmedTarget,
        surface: CrawlSurface,
        http_client: ScanHTTPClient | None = None,
        progress_callback=None,
    ) -> list[Finding]:
        if not _PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not installed; XSS module skipped.")
            return []
        client = http_client or ScanHTTPClient(target)
        findings: list[Finding] = []

        # Collect candidate fields: prioritize search boxes, comments, profile.
        candidates = self._collect_candidates(surface)
        settings = get_settings()
        max_attempts = settings.XSS_MAX_PLAYWRIGHT_ATTEMPTS
        attempts = 0

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                for cand in candidates:
                    if attempts >= max_attempts:
                        break
                    for context_name in ["html_img_onerror", "attr_breakout", "js_string_breakout"]:
                        if attempts >= max_attempts:
                            break
                        token = f"vs_{secrets.token_hex(3)}"
                        finding = await self._try_payload(
                            target, browser, client, cand, context_name, token
                        )
                        attempts += 1
                        if finding is not None:
                            findings.append(finding)
                            break
                    if progress_callback:
                        await progress_callback(attempts, max_attempts)
            finally:
                await browser.close()

        return findings

    def _collect_candidates(self, surface):
        candidates = []
        seen = set()
        priority = {"text", "search", "comment", "textarea", "email"}
        # Query params from routes (reflected).
        from urllib.parse import urlparse, parse_qsl

        for route in surface.routes:
            parsed = urlparse(route.url)
            for k, v in parse_qsl(parsed.query):
                key = (route.url, k)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        {"route": route.url, "param": k, "method": "GET", "priority": 0}
                    )
        # Form text fields.
        for form in surface.forms:
            for field in form.fields:
                if field.input_type in ("submit", "button", "hidden"):
                    continue
                key = (form.action or form.route_url, field.name)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        {
                            "route": form.action or form.route_url,
                            "param": field.name,
                            "method": form.method,
                            "priority": 1 if field.input_type in priority else 2,
                            "form_fields": [f.name for f in form.fields if f.name != field.name],
                        }
                    )
        candidates.sort(key=lambda c: c["priority"])
        return candidates

    async def _try_payload(self, target, browser, client, cand, context, token):
        js = CANARY_JS.format(TOKEN=token)
        payload = PAYLOAD_CONTEXTS[context].format(JS=js)

        page = await browser.new_page()
        try:
            # Inject the canary collector before any page load.
            await page.add_init_script(
                "window.__vulnscan_results=[];"
                "window.__vulnscan_hit=function(t){window.__vulnscan_results.push(t)};"
            )

            route = cand["route"]
            param = cand["param"]

            if cand["method"] == "GET":
                from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

                parsed = urlparse(route)
                params = dict(parse_qsl(parsed.query))
                params[param] = payload
                url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, "", urlencode(params), "")
                )
                await page.goto(url, wait_until="load", timeout=15000)
            else:
                # POST via the crawler's original action URL + form fields.
                form_fields = {param: payload}
                for fn in cand.get("form_fields", []):
                    form_fields[fn] = "x"
                # Use Playwright to fill and submit the form.
                await page.goto(cand["route"].split("?")[0], wait_until="load", timeout=15000)
                # Find the input by name and fill.
                await page.fill(f'[name="{param}"]', payload)
                await page.click("button[type=submit], input[type=submit]")
                await page.wait_for_load_state("load", timeout=15000)

            await page.wait_for_timeout(1500)
            hits = await page.evaluate("window.__vulnscan_results")
            if hits and token in hits:
                screenshot = await page.screenshot()
                import base64

                dom_excerpt = await page.content()
                return Finding(
                    module="xss",
                    subtype="xss_reflected" if cand.get("method") == "GET" else "xss_stored",
                    severity="medium"
                    if cand.get("method") == "GET"
                    else "critical",
                    route=cand["route"],
                    parameter=param,
                    reproducible=True,
                    evidence={
                        "type": "reflected" if cand.get("method") == "GET" else "stored",
                        "parameter": param,
                        "payload_context": context,
                        "payload": payload,
                        "token": token,
                        "execution_confirmed": True,
                        "screenshot_base64": base64.b64encode(screenshot).decode(),
                        "dom_snapshot_excerpt": dom_excerpt[:2000],
                    },
                )
            return None
        except Exception as e:  # noqa: BLE001
            logger.debug("XSS attempt failed: %s", e)
            return None
        finally:
            await page.close()

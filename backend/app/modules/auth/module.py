"""Auth & session checks module (Epic 5).

v1 = unauthenticated-surface checks only: cookie flags, login rate limiting,
and session-ID entropy heuristic.
"""
from __future__ import annotations

import logging
import re
import time

from app.config import get_settings
from app.core.domain import ConfirmedTarget, CrawlSurface, Finding
from app.modules.http_common import ScanHTTPClient

logger = logging.getLogger(__name__)


def _parse_set_cookie_flags(header: str):
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
    flags = {p.split("=")[0].strip().lower(): p for p in parts[1:] if p}
    return name, flags


class AuthModule:
    name = "auth"

    async def run(
        self,
        target: ConfirmedTarget,
        surface: CrawlSurface,
        http_client: ScanHTTPClient | None = None,
        progress_callback=None,
    ) -> list[Finding]:
        client = http_client or ScanHTTPClient(target)
        findings: list[Finding] = []

        # Check 1: cookie flags.
        findings.extend(self._check_cookie_flags(target, surface))

        # Check 2: login rate limiting.
        login = self._find_login_endpoint(surface)
        if login is not None:
            rl = await self._check_rate_limiting(client, login)
            if rl is not None:
                findings.append(rl)

        # Check 3: session ID entropy heuristic.
        sid = await self._check_session_ids(client, surface)
        if sid is not None:
            findings.append(sid)

        if progress_callback:
            await progress_callback(1, 1)
        return findings

    def _check_cookie_flags(self, target, surface):
        findings = []
        seen = set()
        for route, cookies in surface.set_cookie_headers.items():
            for cookie in cookies:
                name, flags = _parse_set_cookie_flags(cookie)
                missing = []
                if "httponly" not in flags:
                    missing.append("HttpOnly")
                if "secure" not in flags:
                    missing.append("Secure")
                samesite = flags.get("samesite")
                if samesite is None or (
                    "same" in samesite and "none" in samesite.lower() and "secure" not in flags
                ):
                    if "SameSite" not in missing:
                        missing.append("SameSite")
                key = (name, tuple(missing))
                if key in seen:
                    continue
                seen.add(key)
                highest = "high" if "HttpOnly" in missing else "medium"
                findings.append(
                    Finding(
                        module="auth",
                        subtype="auth_cookie_flags",
                        severity=highest,
                        route=route,
                        parameter=name,
                        reproducible=True,
                        evidence={
                            "check": "cookie_flags",
                            "route": route,
                            "cookie_name": name,
                            "raw_set_cookie": cookie,
                            "missing_flags": missing,
                        },
                    )
                )
        return findings

    @staticmethod
    def _find_login_endpoint(surface):
        # A form with a password field.
        for form in surface.forms:
            for field in form.fields:
                if field.input_type == "password":
                    return form
        # Route path heuristics.
        for route in surface.routes:
            low = route.url.lower()
            if any(k in low for k in ["login", "signin", "auth"]):
                return type("F", (), {"action": route.url, "method": "GET", "fields": []})
        return None

    async def _check_rate_limiting(self, client, login):
        settings = get_settings()
        n = settings.AUTH_LOGIN_ATTEMPT_COUNT
        # Find a password field name.
        pw_field = "password"
        user_field = "username"
        for f in getattr(login, "fields", []):
            if f.input_type == "password":
                pw_field = f.name
            if f.input_type in ("text", "email"):
                user_field = f.name
        throttled = False
        timings = []
        for i in range(n):
            data = {user_field: f"vulnscan_test_{i}", pw_field: "wrong-password-placeholder-123"}
            start = time.monotonic()
            if login.method == "POST":
                resp = await client.post(login.action, data=data)
            else:
                resp = await client.get(login.action)
            elapsed = time.monotonic() - start
            timings.append(round(elapsed, 2))
            if resp is not None and resp.status_code == 429:
                throttled = True
                break
            if resp is not None and any(
                k in resp.text.lower() for k in ["locked", "rate limit", "too many attempts", "captcha"]
            ):
                throttled = True
                break
        if not throttled:
            return Finding(
                module="auth",
                subtype="auth_no_rate_limiting",
                severity="high",
                route=login.action,
                parameter=None,
                reproducible=True,
                evidence={
                    "check": "rate_limiting",
                    "route": login.action,
                    "attempts": n,
                    "response_times": timings,
                    "throttle_detected": False,
                },
            )
        return None

    async def _check_session_ids(self, client, surface):
        # Sample fresh session ids by hitting the base page a few times and
        # collecting Set-Cookie session values.
        ids = []
        for _ in range(5):
            resp = await client.get(surface.routes[0].url if surface.routes else client.base_url)
            if resp is not None:
                for cookie in resp.headers.get_list("set-cookie"):
                    name, flags = _parse_set_cookie_flags(cookie)
                    val = cookie.split("=", 1)[1].split(";", 1)[0] if "=" in cookie else ""
                    if val:
                        ids.append((name, val))
        if not ids:
            return None
        # Heuristic: low entropy => short or repeated/sequential pattern.
        samples = [v[1] for v in ids]
        min_len = min(len(s) for s in samples)
        unique = set(samples)
        patterned = min_len < 20 or len(unique) < len(samples)
        if patterned:
            return Finding(
                module="auth",
                subtype="auth_session_id_entropy",
                severity="medium",
                route=surface.routes[0].url if surface.routes else client.base_url,
                parameter=None,
                reproducible=True,
                evidence={
                    "check": "session_id",
                    "sampled_ids": samples,
                    "heuristic": "session ID appears low-entropy / patterned",
                    "note": "Heuristic signal; investigate further.",
                },
            )
        return None

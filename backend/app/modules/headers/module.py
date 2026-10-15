"""Security headers module (Epic 7).

Operates purely on crawler baseline headers - no new network requests.
One finding per missing/misconfigured header, collapsed site-wide with an
affected-route list.
"""
from __future__ import annotations

import logging

from app.core.domain import ConfirmedTarget, CrawlSurface, Finding

logger = logging.getLogger(__name__)

# Header -> (check function, severity-if-missing, recommendation)
HEADER_BASELINE = {
    "Content-Security-Policy": {
        "severity": "high",
        "recommendation": "Add a Content-Security-Policy restricting script-src to 'self' "
        "and required CDNs; avoid 'unsafe-inline'/'unsafe-eval'.",
        "validate": None,
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "(max-age >= 6 months).",
        "validate": None,
    },
    "X-Frame-Options": {
        "severity": "medium",
        "recommendation": "Add 'X-Frame-Options: DENY' (or SAMEORIGIN, or CSP frame-ancestors).",
        "validate": None,
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'.",
        "validate": None,
    },
    "Referrer-Policy": {
        "severity": "low",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' "
        "(avoid 'unsafe-url').",
        "validate": None,
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": "Add a Permissions-Policy limiting browser feature access.",
        "validate": None,
    },
}


def _validate_quality(header: str, value: str) -> bool:
    """Return True if the header value is meaningfully weak despite presence."""
    v = value.lower()
    if header == "Content-Security-Policy":
        return "script-src" in v and ("unsafe-inline" in v or "unsafe-eval" in v)
    if header == "Strict-Transport-Security":
        m = None
        import re

        m = re.search(r"max-age=(\d+)", value)
        if m and int(m.group(1)) < 15768000:
            return True
        return False
    if header == "X-Frame-Options":
        return value.upper() not in ("DENY", "SAMEORIGIN")
    if header == "X-Content-Type-Options":
        return value.strip().lower() != "nosniff"
    if header == "Referrer-Policy":
        return "unsafe-url" in v
    return False


class HeadersModule:
    name = "headers"

    async def run(
        self,
        target: ConfirmedTarget,
        surface: CrawlSurface,
        http_client=None,
        progress_callback=None,
    ) -> list[Finding]:
        findings = []
        # Group routes by header status.
        by_header: dict[str, dict] = {}

        for route in surface.routes:
            headers = {k.lower(): v for k, v in route.baseline_headers.items()}
            for hdr, meta in HEADER_BASELINE.items():
                low = hdr.lower()
                value = headers.get(low)
                status = "ok"
                if value is None:
                    status = "missing"
                elif _validate_quality(hdr, value):
                    status = "misconfigured"
                if status != "ok":
                    rec = by_header.setdefault(
                        hdr,
                        {
                            "status": status,
                            "severity": meta["severity"],
                            "recommendation": meta["recommendation"],
                            "affected_routes": [],
                        },
                    )
                    if route.url not in rec["affected_routes"]:
                        rec["affected_routes"].append(route.url)

        for hdr, rec in by_header.items():
            findings.append(
                Finding(
                    module="headers",
                    subtype=f"headers_{hdr.lower()}",
                    severity=rec["severity"],
                    route=rec["affected_routes"][0],
                    parameter=None,
                    reproducible=True,
                    evidence={
                        "header": hdr,
                        "status": rec["status"],
                        "affected_routes": rec["affected_routes"],
                        "affected_route_count": len(rec["affected_routes"]),
                        "recommendation": rec["recommendation"],
                    },
                )
            )

        if progress_callback:
            await progress_callback(1, 1)
        return findings

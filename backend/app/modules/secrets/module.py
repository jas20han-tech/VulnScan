"""Secrets exposure module (Epic 6).

Scans JS bundles for accidentally shipped secrets using a config-driven pattern
library. Matched values are always stored redacted.
"""
from __future__ import annotations

import logging
import re

from app.core.domain import ConfirmedTarget, CrawlSurface, Finding
from app.modules.http_common import ScanHTTPClient

logger = logging.getLogger(__name__)

# Pattern library (config-driven, easy to extend). Each entry: type, severity,
# regex, and whether to require proximity to a keyword.
PATTERN_LIBRARY = [
    {
        "type": "aws_access_key",
        "severity": "high",
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    },
    {
        "type": "private_key",
        "severity": "critical",
        "regex": re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    },
    {
        "type": "jwt",
        "severity": "medium",
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    },
    {
        "type": "connection_string",
        "severity": "critical",
        "regex": re.compile(r"(postgres|mongodb|redis|mysql)://[^\s\"'<>]+"),
    },
    {
        "type": "generic_api_key",
        "severity": "high",
        # keyword followed by = or : then a 20+ char alnum value.
        "regex": re.compile(
            r"(?P<kw>api[_-]?key|apikey|secret|token|password)\s*[:=]\s*[\"']?"
            r"(?P<val>[A-Za-z0-9_\-\+]{20,})",
            re.I,
        ),
        "proximity": True,
    },
]

# Placeholder/example strings to filter out (false-positive reduction).
PLACEHOLDER_DENYLIST = [
    "your-api-key-here",
    "your_secret_key_here",
    "xxxxxxxxxxxxxxxxxxxx",
    "example",
    "changeme",
    "placeholder",
    "your-token-here",
    "xxx",
]


def _redact(value: str, keep_first: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep_first + 4:
        return "*" * 6
    return value[:keep_first] + "*" * 16


def _line_number(text: str, match_start: int) -> int:
    return text.count("\n", 0, match_start) + 1


class SecretsModule:
    name = "secrets"

    async def run(
        self,
        target: ConfirmedTarget,
        surface: CrawlSurface,
        http_client: ScanHTTPClient | None = None,
        progress_callback=None,
    ) -> list[Finding]:
        if not surface.js_bundles:
            return []
        client = http_client or ScanHTTPClient(target)
        findings: list[Finding] = []
        # De-dup across files: module_key -> collected locations.
        by_value: dict[str, dict] = {}

        total = len(surface.js_bundles)
        for idx, bundle in enumerate(surface.js_bundles):
            if progress_callback:
                await progress_callback(idx, total)
            resp = await client.get(bundle)
            if resp is None:
                continue
            text = resp.text
            for entry in PATTERN_LIBRARY:
                for m in entry["regex"].finditer(text):
                    matched = m.group(0)
                    if entry.get("proximity"):
                        # Keyword-proximity patterns already validated by regex group.
                        matched = m.group("val")
                    else:
                        matched = m.group(0)
                    if self._is_placeholder(matched):
                        continue
                    line = _line_number(text, m.start())
                    key = (entry["type"], matched)
                    loc = {"file": bundle, "line": line}
                    if key not in by_value:
                        by_value[key] = {
                            "type": entry["type"],
                            "severity": entry["severity"],
                            "redacted": _redact(matched),
                            "locations": [],
                        }
                    by_value[key]["locations"].append(loc)

        for key, rec in by_value.items():
            findings.append(
                Finding(
                    module="secrets",
                    subtype=f"secrets_{rec['type']}",
                    severity=rec["severity"],
                    route=rec["locations"][0]["file"],
                    parameter=None,
                    reproducible=True,
                    evidence={
                        "secret_type": rec["type"],
                        "matched_value_redacted": rec["redacted"],
                        "locations": rec["locations"][:50],
                    },
                )
            )
        return findings

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        low = value.lower()
        if any(d in low for d in PLACEHOLDER_DENYLIST):
            return True
        if len(set(value)) <= 2:
            return True
        return False

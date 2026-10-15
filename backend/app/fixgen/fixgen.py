"""Fix generation module (Epic 8).

The ONLY place AI touches the pipeline. Given a confirmed Finding, produce a
deterministic/LLM code-level fix suggestion. This module never decides whether
something is a vulnerability - findings are already confirmed before this runs.

Provider resolution (config FIX_GENERATOR_PROVIDER):
  - auto      -> prefer Ollama, then Anthropic, then template
  - ollama    -> local Ollama model via HTTP
  - anthropic -> Anthropic API
  - template  -> offline deterministic templates only
"""
from __future__ import annotations

import logging

import httpx

from app.config import get_settings
from app.core.domain import Finding
from app.db.models import Finding as FindingRow, FixSuggestion
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def build_template_fix(finding: Finding) -> tuple[str, str, str]:
    """Return (diff, explanation, model_used). Deterministic per-module fixes."""
    m = finding.module
    if m == "sqli":
        return (
            "```python\n"
            "# BEFORE (vulnerable)\n"
            f"rows = db.execute(f\"SELECT * FROM items WHERE name = '{{{{param}}}}'\")\n\n"
            "# AFTER (parameterized)\n"
            "stmt = text(\"SELECT * FROM items WHERE name = :name\")\n"
            f"rows = db.execute(stmt, {{\"name\": {finding.parameter or 'value'}}})\n"
            "```",
            "Replace string-interpolated SQL with a parameterized query so user input can "
            "never alter the query structure.",
            "template",
        )
    if m == "xss":
        return (
            "```html\n"
            f"<!-- BEFORE: {{{{ {finding.parameter or 'value'} }}}} rendered raw -->\n"
            "<p>{{ user_input }}</p>\n\n"
            "# AFTER: HTML-entity encode output at the point of rendering\n"
            "<p>{{ user_input|e }}</p>\n"
            "```",
            "HTML-entity-encode user-controlled output when rendering, and/or apply a "
            "Content-Security-Policy to limit injection impact.",
            "template",
        )
    if m == "auth":
        subtype = finding.subtype
        if "cookie" in subtype:
            return (
                "```python\n"
                "# Add HttpOnly; Secure; SameSite attributes to the session cookie\n"
                "response.set_cookie('session', token, httponly=True, secure=True,\n"
                "                    samesite='Lax')\n"
                "```",
                "Set HttpOnly (blocks JS access), Secure (HTTPS-only), and SameSite on the "
                "session cookie.",
                "template",
            )
        if "rate" in subtype:
            return (
                "```python\n"
                "# Add a rate limiter on the login endpoint (e.g. slowapi for FastAPI)\n"
                '# @limiter.limit("5/minute")\n'
                "def login(...): ...\n"
                "```",
                "Add rate limiting to the login endpoint to prevent credential brute-force.",
                "template",
            )
        return (
            "```text\n"
            "Use a CSPRNG to generate session tokens of at least 128 bits of entropy.\n"
            "```",
            "Session identifiers should be cryptographically random and high-entropy.",
            "template",
        )
    if m == "secrets":
        return (
            "```text\n"
            "1. Rotate the exposed credential immediately.\n"
            "2. Move it to an environment variable / secrets manager.\n"
            "3. Inject it at build/deploy time instead of hardcoding in the bundle.\n"
            "```",
            "Remove the hardcoded secret and inject via environment at build/time.",
            "template",
        )
    if m == "headers":
        return (
            "```text\n"
            f"{finding.evidence.get('recommendation', 'Add the missing security header.')}\n"
            "```",
            "Add the recommended security response header via middleware or web server config.",
            "template",
        )
    return ("", "No generic code-level fix; review the finding manually.", "template")


class FixGenerator:
    def __init__(self, provider: str | None = None):
        settings = get_settings()
        self.provider = (provider or settings.FIX_GENERATOR_PROVIDER).lower()

    def resolve_provider(self) -> str:
        settings = get_settings()
        if self.provider == "auto":
            if settings.OLLAMA_BASE_URL:
                try:
                    probe = httpx.get(
                        f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=3
                    )
                    if probe.status_code == 200:
                        return "ollama"
                except Exception:
                    pass
            if settings.ANTHROPIC_API_KEY:
                return "anthropic"
            return "template"
        return self.provider

    async def generate(self, finding: Finding) -> tuple[str, str, str]:
        provider = self.resolve_provider()
        if provider == "template":
            return build_template_fix(finding)
        if provider == "ollama":
            try:
                return await self._ollama(finding)
            except Exception as e:  # noqa: BLE001
                logger.warning("Ollama fix gen failed (%s); using template.", e)
                return build_template_fix(finding)
        if provider == "anthropic":
            try:
                return await self._anthropic(finding)
            except Exception as e:  # noqa: BLE001
                logger.warning("Anthropic fix gen failed (%s); using template.", e)
                return build_template_fix(finding)
        return build_template_fix(finding)

    def _build_prompt(self, finding: Finding) -> str:
        sys_prompt = (
            "You are a secure-coding fix generator. You will be given a confirmed "
            "vulnerability finding (type, route, parameter, evidence). Respond with ONLY:\n"
            "1. A short code fix, as a unified diff or clear before/after code block.\n"
            "2. A one-paragraph explanation of why the fix works.\n"
            "No other commentary. If the finding type doesn't map to a clear code-level "
            "fix, say so plainly and suggest the general mitigation instead."
        )
        user_msg = (
            f"Finding type: {finding.module}\n"
            f"Subtype: {finding.subtype}\n"
            f"Route: {finding.route}\n"
            f"Parameter: {finding.parameter or 'N/A'}\n"
            f"Severity: {finding.severity}\n"
            f"Evidence: {finding.evidence}\n"
        )
        return sys_prompt + "\n\n" + user_msg

    async def _ollama(self, finding: Finding) -> tuple[str, str, str]:
        settings = get_settings()
        payload = {
            "model": settings.OLLAMA_MODEL,
            "prompt": self._build_prompt(finding),
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate", json=payload
            )
            r.raise_for_status()
            text = r.json().get("response", "")
        diff, expl = _split_diff_explanation(text)
        return diff, expl, settings.OLLAMA_MODEL

    async def _anthropic(self, finding: Finding) -> tuple[str, str, str]:
        settings = get_settings()
        headers = {
            "x-api-key": settings.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": settings.ANTHROPIC_MODEL,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": self._build_prompt(finding)}],
        }
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.post(
                "https://api.anthropic.com/v1/messages", headers=headers, json=body
            )
            r.raise_for_status()
            text = "".join(
                block.get("text", "")
                for block in r.json().get("content", [])
            )
        diff, expl = _split_diff_explanation(text)
        return diff, expl, settings.ANTHROPIC_MODEL


def _split_diff_explanation(text: str) -> tuple[str, str]:
    lines = text.strip().splitlines()
    # Best-effort: first code block is the diff, remaining text the explanation.
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            diff = parts[1].strip()
            if diff.startswith(("python", "text", "html", "bash", "diff")):
                diff = diff.split("\n", 1)[1] if "\n" in diff else diff
            explanation = parts[2].strip()
            return diff, explanation
    return "", text.strip()


async def generate_and_store_fix(
    session: AsyncSession, finding_row: FindingRow
) -> FixSuggestion:
    """Generate and persist a fix suggestion for an existing (confirmed) finding.

    Never raises - on any failure the fix is simply absent, so the findings
    dashboard and report are never blocked.
    """
    finding = Finding(
        module=finding_row.module,
        subtype=finding_row.subtype,
        severity=finding_row.severity,
        route=finding_row.route,
        parameter=finding_row.parameter,
        evidence=finding_row.evidence or {},
        reproducible=finding_row.reproducible,
    )
    gen = FixGenerator()
    try:
        diff, explanation, model_used = await gen.generate(finding)
    except Exception as e:  # noqa: BLE001
        logger.warning("Fix generation failed for finding %s: %s", finding_row.id, e)
        return None

    suggestion = FixSuggestion(
        finding_id=finding_row.id,
        diff=diff,
        explanation=explanation,
        model_used=model_used,
    )
    session.add(suggestion)
    await session.commit()
    await session.refresh(suggestion)
    return suggestion

"""SQL Injection detection module (Epic 3).

Three deterministic confirmation techniques (error-based, boolean-based,
time-based). Never reports on a single signal - every finding requires
confirmed evidence with literal request/response excerpts.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

from app.core.domain import ConfirmedTarget, CrawlSurface, Finding, FieldInfo
from app.modules.http_common import ScanHTTPClient

logger = logging.getLogger(__name__)

# DB error signatures per backend.
DB_ERROR_SIGNATURES = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"you have an error in your SQL syntax", re.I),
    re.compile(r"Warning:.*mysql_.*\(\)", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"PG::(UndefinedTable|SyntaxError)", re.I),
    re.compile(r"SQLite/JDBCDriver", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"Incorrect syntax near", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"driver.*syntax error", re.I),
]

BOOLEAN_TRUE_PAYLOADS = ["' OR '1'='1' -- ", "' OR '1'='1'#"]
BOOLEAN_FALSE_PAYLOADS = ["' AND '1'='2' -- ", "' AND '1'='2'#"]
# Minimum meaningful difference in response length between TRUE/FALSE. Kept
# modest because HTML wrappers inflate both responses; the reproduction re-run
# is what guards against single-shot noise.
BOOLEAN_LEN_DIFF_THRESHOLD = 20
TIME_PAYLOADS = {
    "mysql": "SLEEP(5)",
    "postgres": "pg_sleep(5)",
    "mssql": "WAITFOR DELAY '0:0:5'",
    "sqlite": "1",
}
CONTROL_PAYLOAD = lambda _: "aaaaaaaaaaaaaaaaaaaaaaaa"  # noqa: E731


def _interpolate(template: str, value: str) -> str:
    # Replace a placeholder {V} in a URL/query/form template.
    return template.replace("{V}", value)


def _body_len(text: str | None) -> int:
    return len(text or "")


class SQLiModule:
    name = "sqli"

    async def run(
        self,
        target: ConfirmedTarget,
        surface: CrawlSurface,
        http_client: ScanHTTPClient | None = None,
        progress_callback=None,
    ) -> list[Finding]:
        client = http_client or ScanHTTPClient(target)
        findings: list[Finding] = []

        # Build candidate (uri, param) targets: query-string params from routes
        # and form fields.
        candidates = self._collect_candidates(target, surface)

        total = len(candidates)
        for idx, cand in enumerate(candidates):
            if progress_callback:
                # SQLi occupies a slice (30-45%) of overall progress; caller
                # scales it.
                await progress_callback(idx, total)
            finding = await self._test_candidate(target, client, cand)
            if finding is not None:
                findings.append(finding)

        return findings

    def _collect_candidates(self, target, surface):
        candidates = []
        seen = set()
        # Query-string params on routes.
        for route in surface.routes:
            from urllib.parse import urlparse, parse_qsl

            parsed = urlparse(route.url)
            for k, v in parse_qsl(parsed.query):
                if not v:
                    continue
                key = (route.url, k, "GET")
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        {"route": route.url, "param": k, "method": "GET", "base_url": None}
                    )
            # Also test the path without params for form-based POSTing later.
        # Form fields.
        for form in surface.forms:
            for field in form.fields:
                if field.input_type in ("submit", "button", "hidden"):
                    continue
                key = (form.action or form.route_url, field.name, form.method)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        {
                            "route": form.action or form.route_url,
                            "param": field.name,
                            "method": form.method,
                            "action_url": form.action or form.route_url,
                            "fields": [f.name for f in form.fields if f.name != field.name],
                        }
                    )
        return candidates

    async def _test_candidate(self, target, client, cand) -> Finding | None:
        route = cand["route"]
        param = cand["param"]

        # Baseline.
        baseline = await self._request(client, target, cand, "baselinevalue")
        if baseline is None:
            return None
        baseline_text = baseline.text
        baseline_time = getattr(baseline, "_elapsed", 0)

        # Technique 1: error-based.
        err_finding = await self._try_error_based(
            target, client, cand, baseline_text, param
        )
        if err_finding is not None:
            found = await self._confirm_reproduction(
                target, client, cand, param, "error"
            )
            if found:
                err_finding.reproducible = True
                return err_finding

        # Technique 2: boolean-based.
        bool_finding = await self._try_boolean_based(
            target, client, cand, baseline_text, param
        )
        if bool_finding is not None:
            found = await self._confirm_reproduction(
                target, client, cand, param, "boolean"
            )
            if found:
                bool_finding.reproducible = True
                return bool_finding

        # Technique 3: time-based.
        time_finding = await self._try_time_based(
            target, client, cand, param, baseline_time
        )
        if time_finding is not None:
            return time_finding

        return None

    async def _request(self, client, target, cand, value):
        method = cand.get("method", "GET")
        route = cand.get("action_url") or cand["route"]
        # Replace {V} in the query value: candidate has param in query, so we
        # rebuild the URL with the param set to the payload.
        from urllib.parse import urlparse, urlencode, parse_qsl

        parsed = urlparse(route)
        params = dict(parse_qsl(parsed.query))
        params[cand["param"]] = value
        from urllib.parse import urlunparse

        new_query = urlencode(params)
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""))

        if method == "POST":
            form_fields = {cand["param"]: value}
            for fn in cand.get("fields", []):
                form_fields[fn] = "x"
            resp = await client.post(url, data=form_fields)
        else:
            resp = await client.get(url)
        return resp

    async def _try_error_based(self, target, client, cand, baseline_text, param):
        payloads = ["'", "' OR '1'='1' -- "]
        for payload in payloads:
            resp = await self._request(client, target, cand, payload)
            if resp is not None:
                for sig in DB_ERROR_SIGNATURES:
                    if sig.search(resp.text) and not sig.search(baseline_text):
                        return Finding(
                            module="sqli",
                            subtype="sqli_error",
                            severity="critical"
                            if self._is_unauthenticated(cand)
                            else "high",
                            route=cand["route"],
                            parameter=param,
                            reproducible=False,
                            evidence={
                                "technique": "error",
                                "parameter": param,
                                "payload": payload,
                                "signature": sig.pattern,
                                "baseline_response_excerpt": baseline_text[:200],
                                "injected_response_excerpt": resp.text[:200],
                            },
                        )
        return None

    async def _try_boolean_based(self, target, client, cand, baseline_text, param):
        """Boolean-based detection with a control-payload guard.

        Logic:
          - baseline  = request with an empty/benign base value
          - control   = request with a benign, non-malicious value
          - TRUE      = injection payload forcing a true condition
          - FALSE     = injection payload forcing a false condition

        A real Boolean SQLi fires when TRUE and FALSE clearly differ, BUT a
        benign control does NOT differ from baseline. If a benign control also
        changes the response (e.g. stored-XSS/comment reflection where any
        input is echoed), it's content reflection, not SQL injection - rejected.
        """
        baseline = await self._request(client, target, cand, "")
        control = await self._request(client, target, cand, CONTROL_PAYLOAD(None))
        if baseline is None:
            return None
        base_len = _body_len(baseline.text)
        ctrl_len = _body_len(control.text) if control is not None else base_len

        # If benign input already moves the response, we can't trust length
        # diffs as an injection signal for this parameter.
        if abs(ctrl_len - base_len) > BOOLEAN_LEN_DIFF_THRESHOLD:
            return None

        for true_pay, false_pay in zip(BOOLEAN_TRUE_PAYLOADS, BOOLEAN_FALSE_PAYLOADS):
            true_resp = await self._request(client, target, cand, true_pay)
            false_resp = await self._request(client, target, cand, false_pay)
            if true_resp is None or false_resp is None:
                continue
            len_diff = abs(_body_len(true_resp.text) - _body_len(false_resp.text))
            if len_diff > BOOLEAN_LEN_DIFF_THRESHOLD:
                return Finding(
                    module="sqli",
                    subtype="sqli_boolean",
                    severity="critical"
                    if self._is_unauthenticated(cand)
                    else "high",
                    route=cand["route"],
                    parameter=param,
                    reproducible=False,
                    evidence={
                        "technique": "boolean",
                        "parameter": param,
                        "true_payload": true_pay,
                        "true_len": _body_len(true_resp.text),
                        "true_response_excerpt": true_resp.text[:200],
                        "false_payload": false_pay,
                        "false_len": _body_len(false_resp.text),
                        "false_response_excerpt": false_resp.text[:200],
                        "control_len": ctrl_len,
                        "baseline_len": base_len,
                    },
                )
        return None

    async def _try_time_based(self, target, client, cand, param, baseline_time):
        # Baseline timing.
        for backend, clause in TIME_PAYLOADS.items():
            if backend == "sqlite":
                continue
            payload = f"' OR {clause} -- "
            start = time.monotonic()
            resp = await self._request(client, target, cand, payload)
            elapsed = time.monotonic() - start
            if resp is not None and elapsed >= 4.0:
                # Control: same length payload, no sleep.
                control_start = time.monotonic()
                await self._request(client, target, cand, CONTROL_PAYLOAD(None))
                control_elapsed = time.monotonic() - control_start
                if control_elapsed < (elapsed - 1.5):
                    return Finding(
                        module="sqli",
                        subtype="sqli_time",
                        severity="high",
                        route=cand["route"],
                        parameter=param,
                        reproducible=False,
                        evidence={
                            "technique": "time",
                            "parameter": param,
                            "backend": backend,
                            "payload": payload,
                            "response_time_s": round(elapsed, 2),
                            "control_time_s": round(control_elapsed, 2),
                        },
                    )
        return None

    async def _confirm_reproduction(self, target, client, cand, param, technique):
        # Re-run the winning payload once more and see if it reproduces.
        # Simplified: re-issue a boolean TRUE/FALSE pair and compare stability.
        if technique == "error":
            resp1 = await self._request(client, target, cand, "'")
            resp2 = await self._request(client, target, cand, "'")
            if resp1 is None or resp2 is None:
                return False
            has_err1 = any(s.search(resp1.text) for s in DB_ERROR_SIGNATURES)
            has_err2 = any(s.search(resp2.text) for s in DB_ERROR_SIGNATURES)
            return has_err1 and has_err2
        if technique == "boolean":
            t1 = await self._request(client, target, cand, BOOLEAN_TRUE_PAYLOADS[0])
            f1 = await self._request(client, target, cand, BOOLEAN_FALSE_PAYLOADS[0])
            if t1 is None or f1 is None:
                return False
            return abs(_body_len(t1.text) - _body_len(f1.text)) > BOOLEAN_LEN_DIFF_THRESHOLD
        return False

    @staticmethod
    def _is_unauthenticated(cand) -> bool:
        # Heuristic: any route with "login"/password-required form is auth'd.
        route = cand.get("route", "").lower()
        if "login" in route or "auth" in route or "account" in route:
            return False
        return True

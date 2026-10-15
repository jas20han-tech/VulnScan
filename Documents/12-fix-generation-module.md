# 12 — Fix Generation Module (Epic 8)

**Depends on:** `07`, `08`, `09`, `10`, `11` (needs finished, confirmed findings)
**Feeds into:** `13-reporting-dashboard-backend.md`

## The one place AI touches the pipeline (per spec — keep this boundary strict)

Detection above is 100% deterministic. This module's **only** job is: given one confirmed `Finding`, produce a concrete code-level fix suggestion. It never decides whether something is a vulnerability — that's already decided by the time a `Finding` row exists.

## Trigger

Runs once per finding after a scan reaches `report_ready`-pending state (or can be triggered lazily via `GET /findings/{id}/fix` if not pre-generated — pick pre-generated for the demo, since a live "generating fix..." spinner is also a good demo beat per spec step 5, either works).

## Prompt design — constrained to code-diff output only

System prompt (fixed, not user-editable):

```
You are a secure-coding fix generator. You will be given a confirmed vulnerability
finding (type, route, parameter, evidence). Respond with ONLY:
1. A short code fix, as a unified diff or clear before/after code block.
2. A one-paragraph explanation of why the fix works.
No other commentary. If the finding type doesn't map to a clear code-level fix
(e.g. a heuristic session-ID finding), say so plainly and suggest the general
mitigation instead of inventing code that wasn't asked for.
```

User message per finding — build a small template per module type:

- **SQLi** → "Here's a confirmed SQL injection on `{route}` parameter `{parameter}`, technique `{technique}`. Assume the backend is [inferred stack, e.g. FastAPI + SQLAlchemy — fall back to generic parameterized-query example if stack unknown]. Provide a parameterized-query rewrite."
- **XSS** → "Confirmed XSS on `{route}` parameter `{parameter}`, context `{payload_context}`. Provide an output-encoding fix appropriate to that context (HTML entity encoding, attribute encoding, or JS string escaping)."
- **Auth** → cookie flags → "Show the exact `Set-Cookie` / framework config line to add `HttpOnly`/`Secure`/`SameSite`." Rate limiting → generic middleware suggestion (e.g. `slowapi` for FastAPI), not app-specific since login-endpoint code isn't visible to the scanner.
- **Secrets** → "Explain remediation: rotate the credential, move to environment variable / secrets manager, and give a short before/after example of removing a hardcoded key from a JS bundle build step (env var injected at build/deploy time instead)."
- **Headers** → "Give the exact header line to add" — this one is close to deterministic already; the LLM call here is really just formatting/framework-specific config syntax (e.g. FastAPI middleware snippet vs Nginx config line) — feel free to template this one directly without an LLM call if you want a fallback that works offline.

## Output storage

Store `diff` + `explanation` + `model_used` in `fix_suggestions` (see `03`). If the model's response doesn't match the expected "diff + explanation" shape, retry once with a stricter reminder; if it still doesn't match, store the raw text in `explanation` and leave `diff` empty rather than failing the whole scan.

## Failure handling

Fix generation failure must **never** fail the scan or hide the underlying finding — findings are the core value, fixes are a bonus. If `ANTHROPIC_API_KEY` is missing or the call errors, mark `fix_suggestions` absent and let the frontend show "fix generation unavailable" without blocking the findings dashboard or report.

## Acceptance checklist
- [ ] LLM call happens only after a finding is already confirmed and persisted — never in the detection path.
- [ ] Prompt explicitly constrains output to diff + explanation.
- [ ] One fix per finding, stored and retrievable via `GET /findings/{id}/fix`.
- [ ] Failure to generate a fix doesn't block report generation.
- [ ] Headers module has a working template-based fallback that needs no LLM call (nice fallback for demo reliability).

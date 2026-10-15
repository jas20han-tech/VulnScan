# 07 — SQL Injection Detection Module (Epic 3)

**Depends on:** `06-crawler-module.md`
**Feeds into:** `12-fix-generation-module.md`

## Core rule (from spec, non-negotiable)
Never report on a single signal. Every SQLi finding needs at least one **confirmed** technique below, with the raw before/after evidence stored — not "payload sent, looks suspicious."

## Targets within `CrawlSurface`
Every form field and every query-string parameter discovered by the crawler, tested one at a time (don't combine multiple injected params in one request — you need to know which parameter is vulnerable).

## Technique 1 — Error-based
1. Send a baseline request with a benign value.
2. Send the same request with a single-quote-breaking payload (e.g. `'`, `' OR '1'='1`).
3. Check the response for known DB error signatures (MySQL, Postgres, MSSQL, SQLite error strings/patterns — maintain a small signature list).
4. **Confirm**: signature must be absent in baseline and present in injected response.

## Technique 2 — Boolean-based
1. Send a `TRUE`-condition payload (e.g. `' OR '1'='1' -- `) and a `FALSE`-condition payload (e.g. `' AND '1'='2' -- `) for the same parameter.
2. Diff response length and/or key content markers between the two.
3. **Confirm**: TRUE and FALSE responses must differ meaningfully AND this difference must be reproduced on a second run (rules out request-to-request noise like ads/timestamps).

## Technique 3 — Time-based
1. Send baseline, record response time.
2. Send a `SLEEP(5)`-style payload appropriate to likely DB backend (try a small set: MySQL `SLEEP()`, Postgres `pg_sleep()`, MSSQL `WAITFOR DELAY`).
3. **Confirm**: response time must exceed baseline by close to the injected delay (e.g. ≥4s for a 5s sleep) — and a control request *without* the sleep clause but same payload length must NOT show the delay, to rule out the parameter just being slow generally.

## Evidence shape (stored in `findings.evidence`)

```json
{
  "technique": "boolean",
  "parameter": "q",
  "baseline_request": "...", "baseline_response_excerpt": "...",
  "true_payload": "' OR '1'='1' -- ", "true_response_excerpt": "...", "true_len": 4213,
  "false_payload": "' AND '1'='2' -- ", "false_response_excerpt": "...", "false_len": 812,
  "reproduced": true
}
```

## Severity mapping
- Error-based or boolean-based with data-bearing difference → `critical` if on an unauthenticated route, `high` if it requires an existing session token to reach.
- Time-based only (no data leakage confirmed, just blind confirmation) → `high`.

## False-positive guards
- Always run a **control payload** (syntactically similar but non-malicious, e.g. same length string of letters) alongside TRUE/FALSE to rule out generic response variance.
- Re-run the winning payload once more before persisting the finding — one-shot results don't get reported.
- Respect the crawler's rate limit even during confirmation retries — don't hammer the same endpoint.

## Acceptance checklist
- [ ] All three techniques implemented and independently testable.
- [ ] Every finding has reproducible=true only after a second confirming run.
- [ ] Evidence includes literal request/response excerpts, not just a boolean flag.
- [ ] Tested against OWASP Juice Shop's known SQLi endpoint (`/rest/products/search`) as the module's own test fixture.

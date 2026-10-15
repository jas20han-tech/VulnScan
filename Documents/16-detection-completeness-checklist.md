# 16 — Detection Completeness Checklist

**Depends on:** `07`–`11`
**Purpose:** a single cross-module list to sanity-check "did we actually cover every vulnerability possibility we scoped in," used at the end of Week 4 and again before the final demo.

This is a coverage audit, not a new module — walk it against the actual running scanner and check off what's genuinely confirmed working, not what's merely coded.

## SQL Injection (`07`)
- [ ] Error-based detection fires on a known-vulnerable field and stays silent on a safe one (test both directions).
- [ ] Boolean-based detection fires and reproduces on a second run.
- [ ] Time-based detection fires and a control (same-length payload, no sleep clause) does *not* fire.
- [ ] Tested on both GET query params and POST form fields.
- [ ] Confirmed silent (no false positive) against a parameterized-query endpoint if the test app has one.

## XSS (`08`)
- [ ] Reflected XSS confirmed via canary-token callback, not string match.
- [ ] Stored XSS confirmed via a second-pass revisit.
- [ ] At least raw-HTML, attribute-breakout, and JS-string-breakout contexts each have a working payload.
- [ ] Confirmed silent against an endpoint that HTML-encodes output properly.
- [ ] Screenshot evidence captured on every confirmed hit.

## Broken Auth / Session (`09`)
- [ ] Missing `HttpOnly` detected.
- [ ] Missing `Secure` detected.
- [ ] Missing/weak `SameSite` detected.
- [ ] Login rate-limit absence detected against an endpoint with no throttling.
- [ ] Login rate-limit check correctly stays silent (or at least reports differently) against an endpoint that does throttle, if you have a test case for that.
- [ ] Session ID heuristic flags an obviously sequential/short ID and stays quiet on a long random one.

## Secrets Exposure (`10`)
- [ ] AWS key pattern caught.
- [ ] Generic API key pattern caught.
- [ ] JWT pattern caught.
- [ ] Private key block caught.
- [ ] Placeholder/example strings correctly filtered out (test with `"apikey": "your-api-key-here"` — must NOT fire).
- [ ] File+line location correct in evidence.
- [ ] Value is redacted in storage — verified by direct DB inspection with a planted test secret.

## Security Headers (`11`)
- [ ] Each of the six headers in the baseline table individually testable (missing → flagged, present-and-good → not flagged, present-and-weak → flagged).
- [ ] Site-wide duplicate collapsing works (doesn't spam one finding per route).

## Cross-module
- [ ] Every finding, regardless of module, has severity + evidence + reproducible flag populated — no module ships a finding missing any of these three fields.
- [ ] No detection module ever calls the LLM to decide whether something is a vulnerability (grep the module directories for any Anthropic API usage — should only appear in `fixgen/`).
- [ ] No detection module ever issues a request outside `target.domain`.

## Known, accepted gaps (explicitly out of scope — have this answer ready if asked in an interview)
- CSRF token analysis — deferred to v2 per spec.
- Business-logic vulnerabilities — not automatable generically.
- Anything behind a login flow — v1 tests unauthenticated surface only.
- Coverage breadth vs. Burp/ZAP — this project trades breadth for depth-with-proof; say so directly rather than implying broader coverage than it has.

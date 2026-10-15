# 09 — Auth & Session Checks Module (Epic 5)

**Depends on:** `06-crawler-module.md`
**Feeds into:** `12-fix-generation-module.md`

v1 scope note (from spec): unauthenticated-surface checks only — no multi-step authenticated crawling. These checks look *at* the login/session mechanism, they don't log in and crawl behind it.

## Check 1 — Cookie flags

For every `Set-Cookie` header seen during the crawl (baseline headers from `06`, plus specifically the login endpoint's response if discovered):
- Missing `HttpOnly` → finding (JS-readable session token = XSS-to-session-theft chain).
- Missing `Secure` → finding (token sent over plain HTTP if ever available).
- Missing/weak `SameSite` (absent or `None` without `Secure`) → finding (CSRF exposure, even though full CSRF analysis is out of scope, the header itself is checkable).

Evidence: literal `Set-Cookie` header value, which flag is missing, and the route it came from.

## Check 2 — Login rate limiting

1. Identify the login endpoint (form with a password-type field, or a route path containing `login`/`signin`/`auth`).
2. Send N rapid attempts (config, default 10) with a fixed wrong password within a short window.
3. **Confirm** absence of protection: if none of the responses show a lockout/throttle signal (HTTP 429, increasing delay, CAPTCHA challenge, account-lock message) after N attempts, report "no rate limiting detected."
4. Respect ethics here too — cap N low enough not to actually lock out a real account on someone's production system; this check is inherently more invasive, so gate it explicitly and mention it in the consent screen copy ("this scan will attempt N rapid logins against your login endpoint").

## Check 3 — Session ID predictability

1. Trigger the app to issue several session identifiers (e.g., multiple fresh unauthenticated sessions, or multiple login responses if safe to do so).
2. Check entropy characteristics: length, character set, and whether IDs are sequential or show an obvious pattern (e.g., timestamp-prefixed, incrementing).
3. This is a heuristic check, not a cryptographic proof — report it as `medium` severity "session ID appears low-entropy / patterned" with the sampled IDs as evidence, and phrase the finding as a signal to investigate further rather than a certainty.

## Evidence shape

```json
{
  "check": "cookie_flags",
  "route": "/rest/user/login",
  "cookie_name": "session",
  "raw_set_cookie": "session=abc123; Path=/",
  "missing_flags": ["HttpOnly", "Secure"]
}
```

## Severity mapping
- Missing `HttpOnly` on a session cookie → `high`.
- Missing `Secure` → `medium` (lower if the whole app is HTTPS-only already, since the header is somewhat redundant there — still flag it, note the context).
- No login rate limiting → `high`.
- Patterned session IDs → `medium`.

## Acceptance checklist
- [ ] Cookie flag check runs against every `Set-Cookie` seen, not just login.
- [ ] Rate-limit check has a hard cap on attempts and is mentioned in consent-screen copy.
- [ ] Session ID check reports as a heuristic, not an absolute claim.
- [ ] Tested against Juice Shop's login endpoint as the module's own test fixture.

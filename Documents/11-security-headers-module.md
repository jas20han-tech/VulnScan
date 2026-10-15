# 11 — Security Headers Module (Epic 7)

**Depends on:** `06-crawler-module.md`
**Feeds into:** `12-fix-generation-module.md`

## Responsibility
Compare `baseline_headers` per route (already captured by the crawler in `06`) against a recommended-headers baseline. This module needs **no new network requests** — it operates purely on data the crawler already collected, which keeps it cheap and fast.

## Baseline to check against

| Header | What "good" looks like | Why it matters |
|---|---|---|
| `Content-Security-Policy` | present, not `unsafe-inline`/`unsafe-eval` in `script-src` | mitigates XSS impact |
| `Strict-Transport-Security` | present, `max-age` ≥ 15768000 (6 months), ideally `includeSubDomains` | prevents downgrade to HTTP |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` (or CSP `frame-ancestors` doing the same job) | clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing attacks |
| `Referrer-Policy` | present, not `unsafe-url` | info leakage via referrer |
| `Permissions-Policy` | present (nice-to-have, lower severity if missing) | limits browser feature abuse |

## Process

1. For each route in `crawl_results`, read `baseline_headers`.
2. For each header in the table above, check presence and (where applicable) value quality — not just presence. E.g. `X-Frame-Options: ALLOWALL` should still flag, presence alone isn't enough.
3. One finding per **missing or misconfigured header per distinct value seen** — but collapse across routes: if every route on the site is missing the same header (common case), report it once as a site-wide finding listing affected route count, not one finding per route (avoids findings-list spam).

## Evidence shape

```json
{
  "header": "Content-Security-Policy",
  "status": "missing",
  "affected_routes": ["/", "/login", "/rest/products/search"],
  "affected_route_count": 3,
  "recommendation": "Add a CSP restricting script-src to 'self' and required CDNs."
}
```

## Severity mapping
- Missing CSP or HSTS → `high`.
- Missing X-Frame-Options / X-Content-Type-Options → `medium`.
- Missing Referrer-Policy / Permissions-Policy → `low`.
- Misconfigured (present but weak, e.g. `unsafe-inline` in CSP) → treat as same severity as missing, don't downgrade just because something is present.

## Acceptance checklist
- [ ] No new HTTP requests made by this module — reuses crawler data.
- [ ] Value-quality checks implemented, not just presence checks.
- [ ] Site-wide duplicate findings collapsed into one with an affected-route list.
- [ ] Recommendation text is specific enough to hand straight to the Fix Generator (`12`).

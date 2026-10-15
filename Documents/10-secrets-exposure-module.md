# 10 — Secrets Exposure Module (Epic 6)

**Depends on:** `06-crawler-module.md`
**Feeds into:** `12-fix-generation-module.md`

## Responsibility
Fetch every JS bundle URL from `CrawlSurface.js_bundles` and pattern-match for accidentally-shipped secrets.

## Pattern library (maintain as a config list, not hardcoded inline, so it's easy to extend)

| Secret type | Pattern approach |
|---|---|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | 40-char base64-ish string near an `aws_secret` variable name — pair regex with proximity to keyword to cut false positives |
| Generic API key | keyword (`api_key`, `apikey`, `secret`, `token`) `=` or `:` followed by a 20+ char alphanumeric string |
| JWT-looking string | `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` (three base64url segments) |
| Private key block | `-----BEGIN (RSA |EC )?PRIVATE KEY-----` |
| Internal URLs | hostnames matching internal-looking patterns (`.internal`, `localhost`, private IP ranges) hardcoded into otherwise-public JS |
| Generic connection string | `postgres://`, `mongodb://`, `redis://` followed by credentials |

## Process

1. Fetch each JS bundle (respecting rate limit / same-origin from `06`).
2. Run all patterns against the raw text.
3. For each match, compute file + **line number** (spec explicitly asks for file+line location) by counting newlines up to the match offset.
4. De-duplicate: same secret value appearing in multiple files → one finding, `evidence.locations` as a list, not N separate findings.
5. **Reduce false positives**: skip matches inside obvious example/placeholder patterns (`XXXXXXXX`, `your-api-key-here`, repeated same character) — maintain a small denylist of placeholder strings.

## Evidence shape

```json
{
  "secret_type": "aws_access_key",
  "matched_value_redacted": "AKIA********************",
  "locations": [
    { "file": "https://target/static/js/main.a1b2c3.js", "line": 4821 }
  ]
}
```

Always store the matched value **redacted** in the finding (show first 4 / last 0 chars, mask the rest) — a scanner that stores plaintext secrets in its own findings DB is a bad look and a real risk if the DB is ever exposed. Full value is never persisted, even encrypted, for v1 — the redacted form plus file+line is enough to act on.

## Severity mapping
- Private key block, AWS secret key, DB connection string with credentials → `critical`.
- Generic API key pattern (lower confidence) → `high`.
- JWT-looking string (could be a legitimately-issued client-side auth token, not always a "secret") → `medium`, phrase the finding as "review recommended" rather than certain compromise.
- Internal hostname/IP leakage → `low`–`medium` depending on what it reveals.

## Acceptance checklist
- [ ] Pattern list lives in config, not scattered inline regex.
- [ ] File+line captured for every match.
- [ ] Duplicate secret values across files collapse into one finding.
- [ ] Matched values are redacted before persistence — verify with a test that greps the DB for a known test secret and confirms it's not present in full.
- [ ] Placeholder/example strings are filtered out.

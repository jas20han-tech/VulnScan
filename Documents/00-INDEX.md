# VulnScan — Build Doc Index

This folder is the full build plan for VulnScan, broken into agent-sized parts. Each file is self-contained enough to hand to an AI coding agent on its own, but they all share the **same data model, API contract, and module boundaries** defined here so nothing drifts out of sync.

**Give the agent files in roughly this order.** Each file states its own dependencies at the top.

| # | File | Epic (from spec) | Depends on |
|---|---|---|---|
| 01 | `01-architecture.md` | — | 00 |
| 02 | `02-tech-stack-setup.md` | — | 01 |
| 03 | `03-database-schema.md` | — | 01, 02 |
| 04 | `04-api-contract.md` | — | 03 |
| 05 | `05-consent-target-management.md` | Epic 1 | 03, 04 |
| 06 | `06-crawler-module.md` | Epic 2 | 03, 05 |
| 07 | `07-sqli-detection-module.md` | Epic 3 | 06 |
| 08 | `08-xss-detection-module.md` | Epic 4 | 06 |
| 09 | `09-auth-session-checks.md` | Epic 5 | 06 |
| 10 | `10-secrets-exposure-module.md` | Epic 6 | 06 |
| 11 | `11-security-headers-module.md` | Epic 7 | 06 |
| 12 | `12-fix-generation-module.md` | Epic 8 | 07, 08, 09, 10, 11 |
| 13 | `13-reporting-dashboard-backend.md` | Epic 9 (backend half) | 12 |
| 14 | `14-frontend-react.md` | Epic 9 (frontend half) | 04, 13 |
| 15 | `15-build-order-milestones.md` | — | all |
| 16 | `16-detection-completeness-checklist.md` | — | 07–11 |

## Non-negotiable project rules (repeat these to the agent in every session)

1. **Nothing scans without consent.** Every module that touches a target over the network must go through the Consent Gate (`05`) first — no exceptions, no debug bypass flags left in.
2. **Same-origin only.** The crawler (`06`) never follows or scans a link that resolves to a different registrable domain than the confirmed target.
3. **Detection must be deterministic and explainable.** SQLi/XSS/auth/secrets/headers modules (`07`–`11`) never use an LLM to decide "is this a vulnerability" — only to draft the fix in `12`. Every finding must carry the raw evidence (request/response diff, screenshot, timing) that proves it, not just a label.
4. **Rate-limit everything.** Default delay between requests per target, configurable, documented in `06`.
5. **Log every scan.** Timestamp, target, consent record, who initiated it — see `03` (schema) and `05`.
6. **This tool is for authorized targets only** — apps you own, or deliberately-vulnerable test apps (OWASP Juice Shop, DVWA, your own PricePulse with a reintroduced bug). The README and the CLI/UI should say so explicitly.

## Source of truth

All ten files below trace back to `vulnscan-project-spec.md` (the original spec). If anything here seems to contradict it, the original spec wins on scope decisions; these docs win on implementation detail.

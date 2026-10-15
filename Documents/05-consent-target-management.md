# 05 — Consent & Target Management (Epic 1)

**Depends on:** `03-database-schema.md`, `04-api-contract.md`
**Feeds into:** `06-crawler-module.md` (nothing downstream runs without this)

This is "the single most interview-relevant design decision" per the spec — build it as enforced code, not a form checkbox.

## Two-step flow

1. **Register** (`POST /targets`) — just records domain/base_url/note. Nothing scannable yet.
2. **Confirm** (`POST /targets/{id}/consent`) — user must type an exact phrase back, e.g. `"I own or am authorized to test juice-shop.local"`. Generate the expected phrase server-side from the domain (template in `.env`), compare exact match (case-sensitive), only then set `consent_confirmed_at`.

Why typed confirmation and not a checkbox: a checkbox is a UI affordance a script can click; a typed string that includes the actual domain forces the human to consciously read and confirm *that specific domain*, and it's what the spec explicitly calls for.

## Enforcement points (defense in depth — all three, not just one)

1. **Type system**: crawler/module functions accept `ConfirmedTarget`, not `Target`. Constructing a `ConfirmedTarget` requires an assert on `consent_confirmed_at is not None` — see `01`.
2. **Service layer**: `start_scan(target_id)` re-fetches the target from DB and checks `consent_confirmed_at` before enqueuing — never trust a value passed in from an earlier request.
3. **DB constraint**: from `03`, a scan can't be inserted for an unconfirmed target.

## Consent audit log

Every confirmed consent action writes an immutable record: `target_id`, `domain`, `typed_phrase`, `timestamp`, and (if you want to go further) the requester's IP if running as a hosted service. Store this in `targets.consent_phrase_typed` + `consent_confirmed_at`, and copy it into `scans.consent_snapshot` at scan start so the record survives even if the target is later edited.

## Same-origin scope for this epic

`targets.domain` is the single source of truth for "in scope." The crawler (`06`) must resolve every discovered link's registrable domain (use `tldextract` or similar, not naive substring match — `evil-juice-shop.local.attacker.com` must not pass a substring check against `juice-shop.local`) and reject anything that doesn't match.

## Rate-limit config lives here too

Since this is where "target" is defined, also store per-target overrides if useful later (e.g., a slower target needs a longer delay) — but for v1, a single global `SCAN_DEFAULT_DELAY_MS` from `.env` is enough; don't over-build this.

## UI requirements (feeds `14`)

- Add-target form: domain, base URL, note.
- Consent screen: shows the exact phrase to type, a text input, disabled "Start Scan" button until it matches.
- Target list shows consent status clearly (confirmed timestamp or "not confirmed" badge) — this should be the first screen in the demo script (spec step 1).

## Acceptance checklist
- [ ] Registering a target never allows a scan to start.
- [ ] Wrong typed phrase → 422, no state change.
- [ ] Correct typed phrase → consent recorded with timestamp.
- [ ] Attempting to scan an unconfirmed target → 400 with `error: "consent_not_confirmed"`.
- [ ] Subdomain/lookalike domains discovered during crawl are rejected, with a test case proving it (e.g. `attacker.com/juice-shop.local` as a path, not a domain, should NOT be treated as in-scope).

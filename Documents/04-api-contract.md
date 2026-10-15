# 04 — API Contract

**Depends on:** `03-database-schema.md`
**Feeds into:** `05`–`13`, `14-frontend-react.md`

Full REST surface, expanding the endpoint list from the spec into request/response shapes.

## `POST /targets`
Register a target. Does **not** confirm consent by itself — see `05` for the two-step flow.

**Request**
```json
{ "domain": "juice-shop.local", "base_url": "https://juice-shop.local", "owner_note": "local test instance" }
```
**Response 201**
```json
{ "id": "uuid", "domain": "juice-shop.local", "consent_confirmed_at": null }
```

## `POST /targets/{id}/consent`
The typed-confirmation step (see `05`). Required before any scan can be started.

**Request**
```json
{ "typed_phrase": "I own or am authorized to test juice-shop.local" }
```
**Response 200** — target with `consent_confirmed_at` set, or **422** if the phrase doesn't exactly match the expected string for that domain.

## `POST /targets/{id}/scans`
Start a scan. **400** if target has no confirmed consent.

**Response 202**
```json
{ "scan_id": "uuid", "status": "queued" }
```

## `GET /scans/{id}`
```json
{
  "id": "uuid", "status": "scanning", "progress_pct": 42,
  "started_at": "...", "completed_at": null
}
```

## `GET /scans/{id}/findings`
```json
{
  "findings": [
    {
      "id": "uuid", "module": "sqli", "subtype": "sqli_boolean",
      "severity": "critical", "route": "/rest/products/search",
      "parameter": "q", "reproducible": true,
      "evidence_summary": "TRUE payload returned 42 rows, FALSE payload returned 0"
    }
  ]
}
```
(Full evidence blob is available at the per-finding endpoint below, not inlined here — keep the list endpoint light for the dashboard table.)

## `GET /findings/{id}`
Full finding record including raw `evidence` jsonb (requests, responses, diffs, screenshots-as-base64 for XSS).

## `GET /findings/{id}/fix`
```json
{ "diff": "...", "explanation": "...", "model_used": "claude-sonnet-4-6" }
```
**404** if fix generation hasn't run yet for this finding — frontend should poll or trigger `POST /findings/{id}/fix` (regenerate) if needed.

## `GET /scans/{id}/report`
Returns the PDF file (`application/pdf`) or a link to it, depending on how `13` implements storage.

## `GET /targets` / `GET /targets/{id}/scans`
List endpoints for the target management and scan-history views — straightforward, paginate if list grows.

## Error shape (consistent across all endpoints)
```json
{ "error": "consent_not_confirmed", "message": "Target has not completed the consent confirmation step." }
```
Use stable `error` codes (not just messages) so the frontend can branch on them — especially `consent_not_confirmed`, `target_not_found`, `scan_in_progress`.

## Auth note
v1 has no multi-user auth (out of scope per spec) — this is a single-operator tool. Don't build user accounts; leave a comment in `main.py` noting where auth middleware would go if this became multi-tenant later.

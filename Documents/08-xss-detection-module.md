# 08 — XSS Detection Module (Epic 4)

**Depends on:** `06-crawler-module.md`
**Feeds into:** `12-fix-generation-module.md`

## Core rule (from spec, non-negotiable)
"Payload appears in HTML" is not a finding. The payload must **actually execute** in a real browser DOM — confirmed via Playwright, not string matching.

## Confirmation technique — the "canary callback" pattern

1. Generate a unique per-attempt token, e.g. `vs_7f3a2c`.
2. Build a payload that, if it executes as JS, calls a detectable hook with that token — e.g.
   `<script>window.__vulnscan_hit && window.__vulnscan_hit('vs_7f3a2c')</script>`
   plus event-handler variants (`<img src=x onerror="window.__vulnscan_hit('vs_7f3a2c')">`) to catch filtered `<script>` tags but open attribute injection.
3. Before loading the page in Playwright, inject `window.__vulnscan_hit = (token) => { window.__vulnscan_results.push(token) }` via `page.add_init_script`.
4. Submit the payload (form POST or query param GET, matching how the crawler found the field).
5. Load the resulting page in headless Chromium.
6. **Confirm**: `window.__vulnscan_results` contains the exact token used for this attempt. This proves execution, not presence, and the per-attempt token prevents false positives from a stale/cached hit.

## Reflected vs Stored

- **Reflected**: payload in the request → check for the hit on the immediate response page.
- **Stored**: payload in the request → then separately navigate to every other discovered route (or at minimum, the route that's most likely to render it — e.g. a comment list, profile page) and check for the hit there. This requires two passes: submit-and-move-on for all stored candidates, then a second sweep re-visiting pages to check for delayed execution.

## Payload set (context-aware, not just one canned string)

Maintain a small library covering common injection contexts, each with the canary pattern:
- Raw HTML context: `<script>`, `<img onerror>`, `<svg onload>`
- Attribute context (breaking out of `value="..."`): `"><script>...`
- JS string context (breaking out of an inline `<script>var x="..."</script>`): `';window.__vulnscan_hit('TOKEN');//`

Test each field against 2–3 of these rather than just one — different apps sanitize differently, and the spec wants depth over a single hardcoded payload (explicitly called out as the thing to avoid).

## Evidence shape

```json
{
  "type": "reflected",
  "parameter": "comment",
  "payload_context": "html_raw",
  "payload": "<img src=x onerror=\"window.__vulnscan_hit('vs_7f3a2c')\">",
  "token": "vs_7f3a2c",
  "execution_confirmed": true,
  "screenshot_base64": "...",
  "dom_snapshot_excerpt": "..."
}
```

Store a screenshot at the moment of confirmed execution — this is the single most compelling piece of evidence in the demo (spec step 4).

## Severity mapping
- Stored XSS → `critical` (persists, affects other users).
- Reflected XSS on an authenticated/session-bearing route → `high`.
- Reflected XSS requiring unusual user interaction to trigger → `medium`.

## Rate/scope guards
- Route Playwright traffic through the same same-origin check as the crawler — don't let a payload cause the headless browser to navigate off-target.
- Cap total Playwright confirmation attempts per scan (config) — headless browser checks are expensive; don't fire on every field with every payload variant if the app is huge, prioritize by field type (search boxes, comments, profile fields first).

## Acceptance checklist
- [ ] Confirmation requires the unique-token callback to fire, not a string-presence check.
- [ ] Both reflected and stored paths implemented.
- [ ] At least 3 payload contexts covered.
- [ ] Screenshot evidence captured on confirmed hits.
- [ ] Tested against Juice Shop's known reflected XSS endpoint (search box) as the module's own test fixture.

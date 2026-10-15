# 13 — Reporting & Dashboard (Backend Half, Epic 9)

**Depends on:** `12-fix-generation-module.md`
**Feeds into:** `14-frontend-react.md`

## Two things this doc covers
1. Live scan progress delivery (for the frontend dashboard).
2. PDF/HTML report generation (for the exportable artifact).

## Live progress

Simplest approach for v1: **polling**, not WebSocket — `GET /scans/{id}` returns `status` + `progress_pct`, frontend polls every 2s while status isn't terminal. Only reach for WebSocket if polling feels laggy in the demo; it's not worth the complexity for a single-operator tool. Update `progress_pct` at clear milestones (crawl 0–30%, each detection module gets an even slice of 30–90%, fix generation 90–95%, report 95–100%) so the bar moves visibly and honestly reflects real work, not a fake animation.

## Findings dashboard data shape

Backend just serves `GET /scans/{id}/findings` (from `04`) sorted by severity descending, then module. Frontend groups/filters — keep backend dumb here, it's just a query with an `ORDER BY`.

## Historical scan comparison ("did this fix work?")

`GET /targets/{id}/scans` returns scan history for a target. To compare two scans:
- New endpoint `GET /scans/{id}/compare/{other_id}` (or client-side diff if simpler) — matches findings between the two scans by `(module, subtype, route, parameter)` and classifies each as `resolved` (was in old, not in new), `new` (in new, not old), or `persisting` (in both).
- This is what makes the "did this fix work?" story land — a security tool that can prove regression fixing, not just report once.

## Report generation

1. Render an HTML template (Jinja2) with: target info, scan metadata, consent record, findings grouped by severity, evidence excerpts (redacted secrets, screenshots for XSS, request/response diffs for SQLi), and fix suggestions inline next to each finding.
2. Convert to PDF with WeasyPrint.
3. Save to `REPORT_OUTPUT_DIR`, record path in `reports` table.
4. `GET /scans/{id}/report` streams the file.

## Report structure (matches demo script order)

1. Cover: target, scan date, consent record (proves this was authorized).
2. Executive summary: finding counts by severity.
3. Per-finding detail: evidence, severity, fix suggestion.
4. Appendix: crawl coverage stats (routes discovered, any depth/page limits hit).

## Acceptance checklist
- [ ] Progress percentage reflects real module boundaries, not a fake timer.
- [ ] Findings endpoint sorted by severity by default.
- [ ] Report includes the consent record — this doubles as proof of authorized testing.
- [ ] Scan comparison correctly classifies resolved/new/persisting findings — test with two scans against Juice Shop before/after toggling a known vuln off (if the testbed allows it) or a synthetic before/after fixture.
- [ ] PDF renders without layout breakage when a finding has a very long evidence blob (truncate/scroll in report, don't let WeasyPrint choke).

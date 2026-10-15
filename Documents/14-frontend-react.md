# 14 — Frontend (React, Epic 9 frontend half)

**Depends on:** `04-api-contract.md`, `13-reporting-dashboard-backend.md`
**Feeds into:** nothing (leaf) — but drives the demo script

## Screens

### 1. Targets list
- Table: domain, consent status badge, last scan date, "Start Scan" (disabled if not consented) / "Confirm Consent" button.
- "Add Target" form → calls `POST /targets`.

### 2. Consent screen
- Shows the exact phrase to type (fetched from target detail or computed client-side from a known template + domain).
- Text input, live-diffed against expected phrase (grey out "Confirm" until exact match).
- On confirm → `POST /targets/{id}/consent` → redirect to target detail.
- This is demo script step 1 — make it visually clear this is a real gate, not a formality (e.g. red/green state, no way to skip it).

### 3. Scan progress
- Started right after "Start Scan" → `POST /targets/{id}/scans` → redirect here.
- Poll `GET /scans/{id}` every 2s, progress bar + current stage label ("Crawling…", "Testing for SQL injection…", etc. — derive stage label from `progress_pct` bucket per `13`).
- On `report_ready`, auto-navigate to findings dashboard.

### 4. Findings dashboard
- Severity-grouped list (Critical/High/Medium/Low), filterable by module.
- Each row expands to show evidence summary + a "Show full evidence" toggle (raw request/response, screenshot for XSS, etc.).
- Each finding shows its fix suggestion inline (diff rendered with a code-diff view — a simple syntax-highlighted `<pre>` block is fine for v1, don't over-engineer a diff viewer).
- "Export PDF Report" button → `GET /scans/{id}/report`.

### 5. Scan history / comparison
- Per target, list past scans.
- Select two scans → show resolved/new/persisting findings (from `13`'s compare endpoint).

## Component structure (suggested, not mandatory)

```
src/
├── api/               # thin fetch wrappers matching 04-api-contract.md exactly
├── pages/
│   ├── TargetsList.jsx
│   ├── ConsentGate.jsx
│   ├── ScanProgress.jsx
│   ├── FindingsDashboard.jsx
│   └── ScanHistory.jsx
├── components/
│   ├── SeverityBadge.jsx
│   ├── FindingCard.jsx
│   ├── EvidenceViewer.jsx     # handles diff/screenshot/text evidence per module type
│   └── FixDiffView.jsx
└── App.jsx
```

## Design notes

- Severity color coding should be immediately legible (critical=red, high=orange, medium=yellow, low=blue/grey) — this is a dashboard that needs to read at a glance in a live demo.
- Keep the consent screen visually distinct (different background/border) from the rest of the app — it should look like a gate, not just another form.
- No auth/login screens needed for v1 (single-operator tool, per `04`).

## Acceptance checklist
- [ ] Consent gate cannot be bypassed by direct URL navigation to the scan-start action (backend enforces this per `05`, but frontend shouldn't even expose the button).
- [ ] Progress screen shows real stage transitions, not a spinner with no state.
- [ ] Findings dashboard groups by severity by default, matches backend sort order.
- [ ] Evidence viewer correctly renders all five evidence shapes (SQLi diff, XSS screenshot+token, auth cookie flags, secrets redacted match, headers missing-list).
- [ ] PDF export button works end-to-end against a real completed scan.

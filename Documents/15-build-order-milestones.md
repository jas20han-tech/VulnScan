# 15 — Build Order & Milestones

**Depends on:** all prior docs
**Purpose:** what to hand the AI agent, session by session, so it never builds a module before its dependency exists.

Matches the spec's 6-week suggested schedule, expanded to concrete doc references and per-session deliverables.

## Week 1 — Foundation
- Session A: `02` + `03` → repo scaffold, Postgres running, Alembic migration applied, models match schema exactly.
- Session B: `04` + `05` → consent/target endpoints working, all three enforcement layers in place, tested with curl/pytest (no frontend yet).
- Session C: `06` → crawler working standalone against Juice Shop, verified same-origin rejection with a test case, `CrawlSurface` persisted correctly.

**Week 1 exit criteria**: `POST /targets` → `POST /targets/{id}/consent` → `POST /targets/{id}/scans` → crawl runs and populates `crawl_results`, all via curl/Postman, no UI needed yet.

## Week 2 — SQLi
- Session A: implement all three techniques from `07` against a controllable local test case (Juice Shop's search endpoint, or a tiny intentionally-vulnerable Flask app if faster to iterate against).
- Session B: evidence storage, false-positive guards (control payload, reproduction re-run), severity mapping.

**Exit criteria**: a scan against Juice Shop produces at least one confirmed, reproducible SQLi finding with full evidence in the DB.

## Week 3 — XSS
- Session A: Playwright setup, canary-callback confirmation pattern from `08` working for one payload context.
- Session B: extend to reflected + stored, add remaining payload contexts, screenshot capture.

**Exit criteria**: confirmed reflected XSS finding with screenshot evidence against Juice Shop's search box.

## Week 4 — Auth, Secrets, Headers (parallelizable — least interdependent modules)
- Session A: `09` (cookie flags + rate-limit check + session ID heuristic).
- Session B: `10` (secrets patterns + redaction, verified with a test secret that never lands in the DB unredacted).
- Session C: `11` (headers, reusing crawler data, no new requests).

**Exit criteria**: all three modules produce findings against Juice Shop with correct evidence shapes.

## Week 5 — Fix Generation + Dashboard backend
- Session A: `12` — LLM integration, one prompt template per module type, failure handling that never blocks the scan.
- Session B: `13` — progress reporting wired to real module boundaries, findings/report endpoints, PDF rendering.

**Exit criteria**: a full scan end-to-end produces findings + fixes + a downloadable PDF, all via API calls.

## Week 6 — Frontend, polish, demo prep
- Session A: `14` — all five screens, wired to the real API (no mock data).
- Session B: run against 2–3 real target apps (Juice Shop, DVWA, PricePulse-with-reintroduced-bug per spec), fix whatever breaks against real-world messiness.
- Session C: rehearse the demo script (spec section 8) end-to-end, time it, make sure every step is visually clean.

## Cross-cutting reminder for every session
Re-state to the agent at the start of each session: *"Detection modules are deterministic. Consent gate is enforced at three layers. Every finding needs reproducible evidence. Same-origin only."* Repetition here is cheap insurance against scope creep or a shortcut that undermines the project's core interview pitch.

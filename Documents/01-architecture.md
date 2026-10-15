# 01 — System Architecture

**Depends on:** `00-INDEX.md`
**Feeds into:** everything else

## Goal
Give the agent one mental model of the whole system before it writes any code, so module boundaries stay clean.

## Component diagram

```
                        ┌───────────────────────────┐
                        │        React Frontend       │
                        │ (targets, scan progress,    │
                        │  findings, report viewer)   │
                        └──────────────┬──────────────┘
                                       │ REST (+ polling or WS)
                        ┌──────────────▼──────────────┐
                        │        FastAPI Backend       │
                        │  ┌────────────────────────┐  │
                        │  │   Consent Gate          │  │
                        │  ├────────────────────────┤  │
                        │  │   Job Queue / Scheduler │  │
                        │  └───────────┬────────────┘  │
                        └──────────────┼───────────────┘
                                       │ enqueues scan job
                        ┌──────────────▼───────────────┐
                        │           Scan Worker          │
                        │  Crawler → discovers surface    │
                        │     │                            │
                        │     ├─ SQLi Module                │
                        │     ├─ XSS Module (Playwright)     │
                        │     ├─ Auth/Session Module          │
                        │     ├─ Secrets Module                │
                        │     └─ Headers Module                 │
                        │              │                          │
                        │              ▼                          │
                        │        Findings Store (Postgres)          │
                        │              │                              │
                        │              ▼                                │
                        │        Fix Generator (LLM, code-diff only)      │
                        │              │                                    │
                        │              ▼                                      │
                        │        Report Engine (PDF/HTML)                       │
                        └───────────────────────────────────────────────────────┘
```

## Process model

- **API process** (FastAPI/uvicorn): handles all HTTP requests, enqueues scan jobs, never runs a scan inline (scans are slow and must not block request handlers).
- **Worker process**: pulls jobs from the queue, runs the pipeline (crawl → detect → store → fix → report), writes progress updates the API can poll/stream.
- Start with a simple in-process `asyncio` task queue for v1 (see `02`); only reach for Celery/Redis if scan volume or duration makes that necessary. Keep the queue interface abstract so swapping implementations later doesn't touch module code.

## Module contract (applies to every detection module: 07–11)

Every module implements the same interface so the orchestrator (`06`) can run them uniformly:

```python
class DetectionModule(Protocol):
    name: str  # "sqli", "xss", "auth", "secrets", "headers"

    async def run(self, target: ConfirmedTarget, surface: CrawlSurface) -> list[Finding]:
        ...
```

- `ConfirmedTarget` — only ever constructed after the Consent Gate passes (see `05`). Modules must not accept a raw URL string; they must accept this type, so it's structurally impossible to scan something unconsented.
- `CrawlSurface` — the crawler's output: list of routes, forms (with fields), discovered JS bundle URLs, baseline response headers per route.
- `Finding` — see schema in `03`. Must always include: type, severity, confirmed evidence, the exact request(s) that produced it, and a reproducibility flag (did re-running the payload reproduce the result).

## Data flow for one finding

1. Crawler emits a `CrawlSurface`.
2. A detection module receives it, sends payload(s), evaluates evidence, and — only if the confirmation criteria in that module's doc are met — emits a `Finding` with raw evidence attached.
3. Finding is persisted immediately (don't batch — if the scan crashes mid-way, partial results should survive).
4. After the scan completes, the Fix Generator (`12`) is run once per finding, synchronously to the finding, and stores a `FixSuggestion` linked to it.
5. Report Engine (`13`) reads all findings + fixes for a scan and renders the PDF/HTML.

## Why this shape (for interview answers)

- Detection and confirmation are pure Python/deterministic — auditable, testable, no hallucination risk in the part that decides "is this real."
- The LLM is isolated to one call, one job (fix drafting), with constrained output (diff only) — keeps the "AI-wrapper" criticism off the table.
- Consent Gate sits structurally between the API and every module that touches the network — not just a checkbox in a form.

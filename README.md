# VulnScan

An **authorized-targets-only** web application vulnerability scanner.

VulnScan crawls a web app, runs several detection modules (SQL injection, XSS,
auth/session checks, exposed-secrets detection, missing security headers), and
produces an HTML report with per-finding remediation suggestions. It is a
single-operator, consent-gated tool: **every target must be explicitly
authorized before any scan can start.**

> **⚠️ Authorized use only.** Scanning systems you do not own or are not
> explicitly authorized to test is illegal in most jurisdictions. VulnScan's
> consent gate exists to enforce this and cannot be bypassed. Use it only on
> your own applications or deliberately-vulnerable test targets (like the
> bundled testbed). You are solely responsible for what you scan.

---

## Architecture

```
vulnscan/
├── backend/                  # FastAPI + SQLAlchemy (async), SQLite
│   ├── app/
│   │   ├── main.py           # app + lifespan (DB init)
│   │   ├── config.py         # settings / env
│   │   ├── db/               # models + async session
│   │   ├── consent/          # target registration + typed-consent gate
│   │   ├── crawler/          # same-origin crawl (httpx + BS4)
│   │   ├── modules/          # sqli / xss / auth / secrets / headers
│   │   ├── fixgen/           # template + optional LLM fix generation
│   │   ├── reporting/        # HTML report + scan comparison
│   │   ├── queue/            # in-process asyncio job queue
│   │   └── api/              # targets / scans / findings routers
│   └── tests/                # 24 pytest tests (unit + live E2E)
├── frontend/                 # React (Vite) dashboard
│   └── src/pages,components,api
├── testbeds/vulnerable_app/  # deliberately-vulnerable test target
└── Documents/                # original spec docs (16 files)
```

**Pipeline:** crawl → detect (sql & xss & auth & secrets & headers) → persist
findings → generate fix suggestions → build HTML report.

## Consent model (non-negotiable)

1. `POST /targets` registers a target. Consent is **not** confirmed yet.
2. `POST /targets/{id}/consent` requires typing an exact authorization phrase —
   computed from the domain. The scan endpoint returns **400
   `consent_not_confirmed`** otherwise.
3. Enforced at multiple layers: type-level (`ConfirmedTarget`), service-layer,
   and the API. There is **no path** to start a scan without confirmed consent.
4. It is **authorized-targets only**: the crawler is restricted to the target's
   own origin (lookalike/related domains are rejected).

## Quick start

Requires Python 3.11+, Node 18+, and Playwright's Chromium (for XSS detection).

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate                # Windows
pip install -e ".[dev]"              # backend + dev/test deps
playwright install chromium
uvicorn app.main:app --reload        # -> http://localhost:8000
```

> Note: the DB defaults to SQLite (`vulnscan.db`) for local dev. Models are
> written to swap to PostgreSQL later — set `DATABASE_URL` if you do.

### 2. Testbed (vulnerable target)

```bash
cd testbeds/vulnerable_app
uvicorn testbed_app:app --port 8011  # -> http://127.0.0.1:8011
```

This app is intentionally vulnerable (SQLi, reflected XSS, weak auth, a leaked
AWS key, missing security headers) so you can see the scanner work safely.

### 3. Frontend

```bash
cd frontend
npm install
npm run dev                          # -> http://localhost:5173
```

Vite proxies `/api/*` to the backend on `:8000`. Open the app, register
`127.0.0.1` → `http://127.0.0.1:8011`, complete the consent gate, start a scan,
and watch the progress → findings → fix → report flow.

## One-command start / stop

The `start.ps1` / `stop.ps1` scripts bring up the whole stack (backend + testbed +
frontend) and tear it down again. They track PIDs and write logs to `.run/`.

```powershell
.\start.ps1     # or .\start.cmd
.\stop.ps1      # or .\stop.cmd
```

After `start.ps1`, open `http://localhost:5173`; the API docs are at
`http://localhost:8000/docs`. `stop.ps1` reliably shuts everything down,
including orphaned servers left over from a previous run.

## Running the tests

```bash
cd backend
.venv\Scripts\python -m pytest tests/ -v
```

24 tests covering the consent gate, same-origin lookalike rejection, every
detection module, fix generation, and a full live HTTP contract test
(register → consent → scan → poll → findings → fix → report).

## Configuration

See `backend/.env.example`. Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./vulnscan.db` | DB connection |
| `CONSENT_CONFIRMATION_PHRASE_TEMPLATE` | `I own or am authorized to test {domain}` | Consent phrase template |
| `FIX_GENERATOR_PROVIDER` | `auto` | `template` (offline), `ollama`, `anthropic`, or `auto` |
| `SCAN_DEFAULT_DELAY_MS` | `250` | polite request pacing |
| `REPORT_OUTPUT_DIR` | `./reports` | where reports are written |

Fix generation defaults to a deterministic offline template so it works with no
external API keys. It can optionally call a local Ollama instance or the
Anthropic API — detection is always deterministic; no LLM is involved in
finding vulnerabilities.

# 02 — Tech Stack & Project Setup

**Depends on:** `01-architecture.md`
**Feeds into:** `03-database-schema.md`

## Stack (from spec, pinned)

| Layer | Choice |
|---|---|
| Crawler / HTTP | Python 3.11+, `httpx` (async), `BeautifulSoup4` |
| Headless browser | Playwright (Python) |
| Backend API | FastAPI + `uvicorn` |
| Job queue | `asyncio` task queue in v1; abstracted so it can be swapped for Celery+Redis later |
| Frontend | React (Vite), fetch/axios for API calls |
| Database | PostgreSQL 15+ |
| ORM | SQLAlchemy 2.x (async) + Alembic for migrations |
| Report generation | WeasyPrint (HTML → PDF) |
| Fix generation | Anthropic API (Claude), constrained-output prompt — see `12` |

## Repo layout

```
vulnscan/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI app entrypoint
│   │   ├── config.py                # env/settings
│   │   ├── db/
│   │   │   ├── models.py             # SQLAlchemy models (see 03)
│   │   │   ├── session.py
│   │   │   └── migrations/           # Alembic
│   │   ├── consent/                  # Epic 1 — see 05
│   │   ├── crawler/                  # Epic 2 — see 06
│   │   ├── modules/
│   │   │   ├── sqli/                 # Epic 3 — see 07
│   │   │   ├── xss/                  # Epic 4 — see 08
│   │   │   ├── auth/                 # Epic 5 — see 09
│   │   │   ├── secrets/              # Epic 6 — see 10
│   │   │   └── headers/              # Epic 7 — see 11
│   │   ├── fixgen/                   # Epic 8 — see 12
│   │   ├── reporting/                # Epic 9 backend — see 13
│   │   ├── queue/                    # job queue abstraction
│   │   └── api/
│   │       ├── targets.py
│   │       ├── scans.py
│   │       └── findings.py
│   ├── tests/
│   ├── pyproject.toml
│   └── .env.example
├── frontend/                        # see 14
│   ├── src/
│   └── package.json
├── testbeds/                        # OWASP Juice Shop / DVWA docker-compose for demo
│   └── docker-compose.yml
└── docs/                            # this folder, copied into the repo
```

## Environment variables (`.env.example`)

```
DATABASE_URL=postgresql+asyncpg://vulnscan:vulnscan@localhost:5432/vulnscan
ANTHROPIC_API_KEY=
SCAN_DEFAULT_DELAY_MS=250
SCAN_MAX_CONCURRENT_REQUESTS=5
CONSENT_CONFIRMATION_PHRASE_TEMPLATE="I own or am authorized to test {domain}"
REPORT_OUTPUT_DIR=./reports
```

## Local dev bring-up (what the agent should get working first)

1. `docker compose up -d db` — Postgres only, for local dev.
2. `alembic upgrade head` — apply schema from `03`.
3. `uvicorn app.main:app --reload` — backend on `:8000`.
4. `npm run dev` in `frontend/` — on `:5173`, proxy `/api` to `:8000`.
5. `docker compose -f testbeds/docker-compose.yml up -d` — bring up OWASP Juice Shop locally as the default authorized test target for development and demo.

## Dependencies to pin (backend)

```
fastapi
uvicorn[standard]
httpx
beautifulsoup4
playwright
sqlalchemy[asyncio]
asyncpg
alembic
weasyprint
pydantic-settings
anthropic
pytest
pytest-asyncio
```

Run `playwright install chromium` after `pip install` — this is a common setup miss, call it out explicitly to the agent.

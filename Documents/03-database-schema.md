# 03 — Database Schema

**Depends on:** `01-architecture.md`, `02-tech-stack-setup.md`
**Feeds into:** `04-api-contract.md`, all Epic modules (`05`–`13`)

This is the single schema every other doc references. Do not let individual module docs invent their own tables — extend this file and regenerate the migration instead.

## Tables

### `targets`
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| domain | text, unique | registrable domain, e.g. `juice-shop.local` |
| base_url | text | e.g. `https://juice-shop.local` |
| owner_note | text | free-text: "my own PricePulse deploy", etc. |
| consent_confirmed_at | timestamptz, nullable | null until consent gate passed |
| consent_phrase_typed | text, nullable | exact string the user typed |
| created_at | timestamptz | |

A target with `consent_confirmed_at IS NULL` must be structurally unscannable — enforce this in the query layer, not just the API layer (see `05`).

### `scans`
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| target_id | UUID FK → targets | |
| status | enum: `queued`, `crawling`, `scanning`, `generating_fixes`, `report_ready`, `failed` | |
| started_at | timestamptz | |
| completed_at | timestamptz, nullable | |
| progress_pct | int | 0–100, updated by worker |
| error_message | text, nullable | |
| consent_snapshot | jsonb | copy of the consent record at scan time (domain + phrase + timestamp) — audit trail survives even if `targets` row later changes |

### `crawl_results`
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | |
| route | text | path discovered |
| method | text | GET/POST |
| forms | jsonb | list of `{action, method, fields:[{name,type}]}` |
| js_bundles | jsonb | list of discovered script URLs |
| baseline_headers | jsonb | response headers captured for this route |

### `findings`
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans | |
| module | enum: `sqli`, `xss`, `auth`, `secrets`, `headers` | |
| subtype | text | e.g. `sqli_boolean`, `xss_reflected`, `auth_missing_httponly` |
| severity | enum: `critical`, `high`, `medium`, `low` | |
| route | text | where it was found |
| parameter | text, nullable | which field/param |
| evidence | jsonb | raw proof — see per-module doc for shape |
| reproducible | boolean | did a re-run confirm it |
| created_at | timestamptz | |

### `fix_suggestions`
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| finding_id | UUID FK → findings, unique | one fix per finding |
| diff | text | unified diff or before/after code block |
| explanation | text | short human-readable why |
| model_used | text | e.g. `claude-sonnet-4-6` |
| created_at | timestamptz | |

### `reports`
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans, unique | |
| file_path | text | where the PDF/HTML landed |
| generated_at | timestamptz | |

## Relationships

```
targets 1──* scans 1──* crawl_results
                    1──* findings 1──1 fix_suggestions
                    1──1 reports
```

## Migration notes for the agent

- Use Alembic autogenerate off these SQLAlchemy models, then hand-review the migration — autogenerate sometimes misses enum types.
- Add a Postgres `CHECK` constraint (or app-level guard) that no `scans` row can be inserted where `target.consent_confirmed_at IS NULL` — this is the DB-level enforcement of rule #1 in `00-INDEX.md`.
- Index `findings.scan_id` and `crawl_results.scan_id` — the findings dashboard queries by scan constantly.

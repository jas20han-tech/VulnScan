# 06 — Crawler Module (Epic 2)

**Depends on:** `03`, `05`
**Feeds into:** `07`, `08`, `09`, `10`, `11` (every detection module consumes `CrawlSurface`)

## Responsibility
Turn a `ConfirmedTarget` into a `CrawlSurface`: the full same-origin map of routes, forms, JS bundles, and baseline headers that detection modules operate on. The crawler itself does **not** detect vulnerabilities — keep that boundary clean.

## Algorithm

1. Start from `target.base_url`. BFS over links found in HTML (`<a href>`, `<form action>`, `<script src>`).
2. For each discovered URL:
   - Resolve to absolute URL.
   - Check registrable domain matches `target.domain` (reuse the same-origin check from `05`) — **discard immediately** if not, log it as "skipped (out of scope)" for transparency in the report.
   - Skip if already visited (dedupe by normalized URL, stripping tracking params but keeping functional query params).
   - Fetch with `httpx.AsyncClient`, respecting `SCAN_DEFAULT_DELAY_MS` between requests (use a semaphore for `SCAN_MAX_CONCURRENT_REQUESTS`).
3. Parse HTML with BeautifulSoup:
   - Extract all `<form>` elements: action, method, and every `<input>/<select>/<textarea>` with `name` + inferred `type`.
   - Extract all `<script src>` pointing to same-origin JS bundles → queue for the Secrets module.
   - Extract all links for further crawling.
4. Record baseline response headers per route (used by Headers module, `11`).
5. Stop conditions: max depth (config, default 5), max pages (config, default 200) — prevents runaway crawls on large apps; log if a limit was hit so the report can say "partial coverage."

## Output shape — `CrawlSurface`

```python
@dataclass
class CrawlSurface:
    routes: list[RouteInfo]       # {url, method, baseline_headers, baseline_status}
    forms: list[FormInfo]         # {route_url, action, method, fields:[{name, input_type}]}
    js_bundles: list[str]         # absolute URLs, same-origin only
```

This gets persisted to `crawl_results` (see `03`) as the scan progresses, not just held in memory — if the worker crashes mid-crawl, partial results should be visible.

## Rate limiting & politeness

- Default 250ms between requests to the same host (configurable).
- Respect `robots.txt` for crawl *discovery* as a politeness default, but note in the report that authorized security testing may need to override it for specific paths — leave a config flag `RESPECT_ROBOTS_TXT=true` rather than hardcoding.
- Set a distinctive `User-Agent: VulnScan/1.0 (authorized-scan; contact=<owner_note>)` so target-side logs are honest about what's happening.

## Progress reporting

Update `scans.progress_pct` as the crawl proceeds (e.g., proportion of discovered-but-not-yet-fetched queue) so the frontend progress bar (`14`) has something real to show, not a fake animation.

## Acceptance checklist
- [ ] Crawl never issues a request to a different registrable domain.
- [ ] Every form's fields are captured with name + type.
- [ ] JS bundle URLs feed the Secrets module input list exactly.
- [ ] Crawl results survive a worker crash (persisted incrementally).
- [ ] Depth/page limits are enforced and logged when hit.

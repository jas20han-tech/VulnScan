"""Same-origin crawler (Epic 2).

Turns a ConfirmedTarget into a CrawlSurface: BFS over same-origin routes,
forms, JS bundles, and baseline headers. The crawler does NOT detect
vulnerabilities; that boundary is kept clean.
"""
from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

from app.config import get_settings
from app.core.domain import ConfirmedTarget, CrawlSurface, FieldInfo, FormInfo, RouteInfo
from app.core.same_origin import registrable_domain

logger = logging.getLogger(__name__)

# Query params stripped for dedupe purposes (tracking params), while keeping
# functional ones.
_IGNORE_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref"}

_USER_AGENT_TEMPLATE = "VulnScan/1.0 (authorized-scan; contact={owner_note})"


def _normalize_url(url: str, base_url: str) -> str:
    parsed = urlparse(urljoin(base_url, url))
    query = "&".join(
        f"{k}={v}"
        for k, v in (
            (p.split("=")[0], "=".join(p.split("=")[1:]))
            for p in parsed.query.split("&")
            if p
        )
        if k not in _IGNORE_PARAMS
    )
    # Drop fragment.
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))


def _is_same_origin_url(url: str, target: ConfirmedTarget) -> bool:
    parsed = urlparse(urljoin(target.base_url, url))
    url_reg = registrable_domain(url, target.base_url)
    target_reg = registrable_domain(target.base_url, target.base_url)
    return url_reg == target_reg


class Crawler:
    def __init__(self, target: ConfirmedTarget):
        self.target = target
        settings = get_settings()
        self.delay = settings.SCAN_DEFAULT_DELAY_MS / 1000.0
        self.max_concurrent = settings.SCAN_MAX_CONCURRENT_REQUESTS
        self.max_depth = settings.CRAWL_MAX_DEPTH
        self.max_pages = settings.CRAWL_MAX_PAGES
        self.respect_robots = settings.RESPECT_ROBOTS_TXT
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._user_agent = _USER_AGENT_TEMPLATE.format(
            owner_note=target.owner_note or "default"
        )

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> httpx.Response | None:
        async with self._semaphore:
            try:
                resp = await client.get(url, follow_redirects=True)
                await asyncio.sleep(self.delay)
                return resp
            except httpx.HTTPError:
                return None

    async def crawl(self, progress_callback=None) -> CrawlSurface:
        surface = CrawlSurface()
        visited: set[str] = set()
        robots_disallowed = self._load_robots_disallowed()

        headers = {"User-Agent": self._user_agent}
        client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(15.0),
            follow_redirects=True,
        )

        # Seed queue: (url, depth)
        start_url = self.target.base_url
        queue: list[tuple[str, int]] = [(start_url, 0)]
        page_count = 0
        limits_hit = False

        try:
            while queue and page_count < self.max_pages:
                url, depth = queue.pop(0)
                norm = _normalize_url(url, self.target.base_url)
                if norm in visited:
                    continue
                if not _is_same_origin_url(norm, self.target):
                    logger.info("skipped (out of scope): %s", norm)
                    continue
                if self.respect_robots and self._is_disallowed(robots_disallowed, norm):
                    logger.info("skipped (robots.txt): %s", norm)
                    continue
                if depth > self.max_depth:
                    limits_hit = True
                    continue

                visited.add(norm)
                page_count += 1

                resp = await self._fetch(client, norm)
                if resp is None:
                    continue

                # Baseline headers + set-cookie for the auth module.
                final_url = str(resp.url)
                route = RouteInfo(
                    url=final_url,
                    method="GET",
                    baseline_headers=dict(resp.headers),
                    baseline_status=resp.status_code,
                )
                surface.routes.append(route)

                set_cookies = resp.headers.get_list("set-cookie")
                if set_cookies:
                    surface.set_cookie_headers[final_url] = set_cookies

                ctype = resp.headers.get("content-type", "")
                if "html" not in ctype:
                    # If it's a JS file, queue it for the secrets module.
                    if "javascript" in ctype or final_url.endswith((".js", ".mjs")):
                        surface.js_bundles.append(final_url)
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Forms.
                for form in soup.find_all("form"):
                    form_info = self._parse_form(final_url, form)
                    if form_info is not None:
                        surface.forms.append(form_info)

                # JS bundles.
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    abs_src = urljoin(final_url, src)
                    if _is_same_origin_url(abs_src, self.target):
                        if abs_src not in surface.js_bundles:
                            surface.js_bundles.append(abs_src)

                # Links for further crawling.
                next_depth = depth + 1
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    abs_href = urljoin(final_url, href)
                    if _is_same_origin_url(abs_href, self.target):
                        n = _normalize_url(abs_href, self.target.base_url)
                        if n not in visited and (n, next_depth) not in queue:
                            queue.append((n, next_depth))

                if progress_callback:
                    remaining = len(queue)
                    done = page_count
                    pct = min(30, int((done / max(1, done + remaining)) * 30))
                    await progress_callback(pct)
        finally:
            await client.aclose()

        if limits_hit or page_count >= self.max_pages:
            surface.coverage_limits_hit.append("crawl limits hit (depth or page cap)")

        return surface

    def _parse_form(self, route_url: str, form) -> FormInfo | None:
        action = form.get("action") or route_url
        action = urljoin(route_url, action)
        method = (form.get("method") or "GET").upper()
        fields = []
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            typ = inp.get("type") or "text"
            if typ in ("submit", "button", "hidden") and not name:
                continue
            fields.append(FieldInfo(name=name, input_type=typ))
        return FormInfo(route_url=route_url, action=action, method=method, fields=fields)

    def _load_robots_disallowed(self) -> list[re.Pattern]:
        if not self.respect_robots:
            return []
        robots = []
        try:
            import httpx as _h

            r = _h.get(
                urljoin(self.target.base_url, "/robots.txt"),
                headers={"User-Agent": self._user_agent},
                timeout=5,
            )
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            robots.append(re.compile(re.escape(path)))
        except Exception:
            pass
        # Always disallow nothing if robots fetch fails; authorize override.
        return robots

    @staticmethod
    def _is_disallowed(patterns, url: str) -> bool:
        path = urlparse(url).path
        return any(p.search(path) for p in patterns)

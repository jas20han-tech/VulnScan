"""Same-origin enforcement.

Determines whether a URL belongs to the same registrable domain as the target.

The security goal (see 05/06): never follow/scan a link that resolves to a
different registrable domain than the target. The critical thing to defend
against is a lookalike where the target name appears as a LABEL inside a
larger attacker-controlled domain, e.g. `evil-juice-shop.local.attacker.com`.

Private/demo suffixes like `.local` are not in the public PSL, so we compute the
target's registrable domain defensively and match by suffix on that value.
A URL is in-scope iff its host equals the target's registrable domain or is a
subdomain of it (foo.juice-shop.local == same app as juice-shop.local).
"""
from __future__ import annotations

from urllib.parse import urlparse

import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lstrip(".")


def _target_registrable_domain(base_url: str) -> str:
    """Return the registrable domain (eTLD+1-like) for the target base URL.

    Uses tldextract when it can identify a public suffix (real domains), and
    falls back to the last two labels for private/demo names such as
    `juice-shop.local`.
    """
    host = hostname(base_url)
    if not host:
        return host
    ext = _extractor(host)
    # A recognized public suffix.
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    # Single label (e.g. "localhost").
    if "." not in host:
        return host
    # Private/multi-label without a public suffix (e.g. "juice-shop.local"):
    # treat the last two labels as the registrable domain.
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def registrable_domain(url: str, base_url: str) -> str:
    """Return the registrable-domain tail that a URL's host belongs to.

    For in-scope analysis we return the largest suffix of the URL's host that
    matches the target domain family. For an out-of-scope host this resolves to
    that host's own registrable domain (e.g. attacker.com).
    """
    url_host = hostname(url)
    if not url_host:
        return ""
    # Fast path: exact subdomain/equal of the target base.
    target_reg = _target_registrable_domain(base_url)
    if url_host == target_reg or url_host.endswith("." + target_reg):
        return target_reg
    # Lookalike defense: walk labels; if the target reg appears as a suffix of
    # a LARGER host, that larger host is NOT in scope.
    # Otherwise recover the URL host's own registrable domain.
    ext = _extractor(url_host)
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    if "." not in url_host:
        return url_host
    labels = url_host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else url_host


def is_same_origin(url: str, target_domain: str, target_base_url: str) -> bool:
    """True if `url` resolves to the same registrable domain as the target."""
    url_host = hostname(url)
    target_reg = _target_registrable_domain(target_base_url)
    # Scope is: the exact registrable domain and any subdomain of it.
    if url_host == target_reg or url_host.endswith("." + target_reg):
        # Extra safety: never accept a host where the target name is only a
        # middle label (e.g. a-b.juice-shop.local.attacker.com) - that can't
        # happen here since we only match exact equal or a ".target" suffix,
        # but keep target_domain consistency.
        return True
    return False


def is_allowed_host(url: str, target_domain: str, target_base_url: str) -> bool:
    return is_same_origin(url, target_domain, target_base_url)

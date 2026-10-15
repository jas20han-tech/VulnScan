"""Core domain types shared across modules.

ConfirmedTarget is the single structural guarantee of consent: it can only be
constructed when consent has been confirmed, so a module that accepts a
ConfirmedTarget cannot (structurally) scan an unconsented target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


class ConsentNotConfirmedError(Exception):
    """Raised when a ConfirmedTarget is constructed without confirmed consent."""


@dataclass(frozen=True)
class ConfirmedTarget:
    id: str
    domain: str
    base_url: str
    owner_note: str
    consent_confirmed_at: datetime

    def __post_init__(self) -> None:
        if self.consent_confirmed_at is None:
            raise ConsentNotConfirmedError(
                f"Target {self.domain} has not completed consent confirmation."
            )


@dataclass
class RouteInfo:
    url: str
    method: str = "GET"
    baseline_headers: dict = field(default_factory=dict)
    baseline_status: int = 200


@dataclass
class FieldInfo:
    name: str
    input_type: str = "text"


@dataclass
class FormInfo:
    route_url: str
    action: str
    method: str = "GET"
    fields: list[FieldInfo] = field(default_factory=list)


@dataclass
class CrawlSurface:
    routes: list[RouteInfo] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    js_bundles: list[str] = field(default_factory=list)
    # Map of route -> list of Set-Cookie header values, for the auth module.
    set_cookie_headers: dict[str, list[str]] = field(default_factory=dict)
    coverage_limits_hit: list[str] = field(default_factory=list)


@dataclass
class Finding:
    module: str
    subtype: str
    severity: str
    route: str
    parameter: str | None
    evidence: dict
    reproducible: bool = False

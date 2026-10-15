"""Consent gate + same-origin enforcement tests (Epic 1 & 2).

The consent gate is the single most interview-relevant design decision: it must
be enforced structurally (ConfirmedTarget), in the service layer, and reject
lookalike domains.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.core.domain import ConfirmedTarget, ConsentNotConfirmedError
from app.core.same_origin import is_same_origin, registrable_domain
from app.db.session import async_session, init_db


# --- Same-origin enforcement ---
@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://juice-shop.local:3000/path", True),
        ("http://juice-shop.local/rest/search", True),
        ("http://api.juice-shop.local/x", True),  # subdomain = same registrable domain
        ("http://evil-juice-shop.local.attacker.com/", False),  # lookalike - MUST fail
        ("http://attacker.com/juice-shop.local", False),  # path, not domain
        ("http://juice-shop.local.attacker.com/x", False),
        ("https://juice-shop.com/", False),  # different suffix
    ],
)
def test_same_origin(url, expected):
    result = is_same_origin(
        url, target_domain="juice-shop.local", target_base_url="http://juice-shop.local"
    )
    assert result == expected, f"{url} expected {expected}"


def test_registrable_domain_lookalike():
    assert registrable_domain(
        "http://juice-shop.local.attacker.com/x", "http://juice-shop.local"
    ) == "attacker.com"
    assert registrable_domain(
        "http://juice-shop.local", "http://juice-shop.local"
    ) == "juice-shop.local"


def test_registrable_domain_subdomain():
    assert registrable_domain(
        "http://api.juice-shop.local/x", "http://juice-shop.local"
    ) == "juice-shop.local"


# --- ConfirmedTarget structural enforcement ---
def test_confirmed_target_rejects_without_consent():
    with pytest.raises(ConsentNotConfirmedError):
        ConfirmedTarget(
            id="x",
            domain="a.local",
            base_url="http://a.local",
            owner_note="",
            consent_confirmed_at=None,
        )


def test_confirmed_target_accepts_with_consent():
    t = ConfirmedTarget(
        id="x",
        domain="a.local",
        base_url="http://a.local",
        owner_note="",
        consent_confirmed_at=datetime.now(timezone.utc),
    )
    assert t.consent_confirmed_at is not None


# --- Service-layer consent enforcement ---
@pytest.mark.asyncio
async def test_start_scan_rejects_unconfirmed_target():
    await init_db()
    from app.db.models import Base
    from app.db.session import engine

    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())

    from app.consent.service import register_target
    from app.consent.service import build_confirmed_target

    async with async_session() as s:
        target = await register_target(s, "u.local", "http://u.local", "note")
        tid = target.id

    with pytest.raises(ConsentNotConfirmedError):
        async with async_session() as s:
            await build_confirmed_target(s, tid)


@pytest.mark.asyncio
async def test_consent_requires_exact_phrase():
    from app.db.models import Base
    from app.db.session import engine

    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())

    from app.consent.service import (
        confirm_consent,
        expected_consent_phrase,
        PhraseMismatchError,
        register_target,
    )

    async with async_session() as s:
        target = await register_target(s, "p.local", "http://p.local", "")
        tid = target.id
        phrase = expected_consent_phrase("p.local")

    # Wrong phrase -> error, no state change.
    with pytest.raises(PhraseMismatchError):
        async with async_session() as s:
            await confirm_consent(s, tid, "this is not the phrase")
    async with async_session() as s:
        from app.db.models import Target

        t = await s.get(Target, tid)
        assert t.consent_confirmed_at is None

    # Correct phrase -> consent recorded.
    async with async_session() as s:
        t = await confirm_consent(s, tid, phrase)
        assert t.consent_confirmed_at is not None
        assert t.consent_phrase_typed == phrase

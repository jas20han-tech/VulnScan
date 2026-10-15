"""Consent & target management service (Epic 1).

Implements the two-step flow (register -> typed-confirm) and the three
enforcement layers that make unconsented scanning structurally impossible.
"""
from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.domain import ConfirmedTarget, ConsentNotConfirmedError
from app.db.models import Target


class TargetNotFoundError(Exception):
    pass


class PhraseMismatchError(Exception):
    pass


class DomainAlreadyRegisteredError(Exception):
    pass


def expected_consent_phrase(domain: str) -> str:
    settings = get_settings()
    return settings.CONSENT_CONFIRMATION_PHRASE_TEMPLATE.format(domain=domain)


def normalize_base_url(base_url: str) -> str:
    """Trim trailing slashes so routes are compared consistently."""
    return base_url.rstrip("/")


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("domain is required")
    return domain


async def register_target(
    session: AsyncSession,
    domain: str,
    base_url: str,
    owner_note: str = "",
) -> Target:
    domain = validate_domain(domain)
    base_url = normalize_base_url(base_url)
    existing = await get_target_by_domain(session, domain)
    if existing is not None:
        raise DomainAlreadyRegisteredError(domain)
    target = Target(domain=domain, base_url=base_url, owner_note=owner_note)
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


async def confirm_consent(
    session: AsyncSession,
    target_id: str,
    typed_phrase: str,
) -> Target:
    target = await session.get(Target, target_id)
    if target is None:
        raise TargetNotFoundError()

    expected = target.consent_phrase_typed or expected_consent_phrase(target.domain)
    if typed_phrase.strip() != expected:
        raise PhraseMismatchError()

    from app.db.models import utcnow

    target.consent_confirmed_at = utcnow()
    target.consent_phrase_typed = typed_phrase.strip()
    await session.commit()
    await session.refresh(target)
    return target


async def get_target(session: AsyncSession, target_id: str) -> Target | None:
    return await session.get(Target, target_id)


async def get_target_by_domain(
    session: AsyncSession, domain: str
) -> Target | None:
    result = await session.execute(
        select(Target).where(Target.domain == domain)
    )
    return result.scalar_one_or_none()


async def build_confirmed_target(
    session: AsyncSession, target_id: str
) -> ConfirmedTarget:
    """Construct a ConfirmedTarget, enforcing the service-layer consent check.

    Raises ConsentNotConfirmedError if the target has not confirmed consent.
    """
    target = await session.get(Target, target_id)
    if target is None:
        raise TargetNotFoundError()
    if target.consent_confirmed_at is None:
        raise ConsentNotConfirmedError(
            f"Target {target.domain} has not completed the consent confirmation step."
        )
    return ConfirmedTarget(
        id=target.id,
        domain=target.domain,
        base_url=target.base_url,
        owner_note=target.owner_note,
        consent_confirmed_at=target.consent_confirmed_at,
    )


async def list_targets(session: AsyncSession) -> list[Target]:
    result = await session.execute(
        select(Target).order_by(Target.created_at.desc())
    )
    return list(result.scalars().all())


def domain_from_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    return parsed.hostname or ""

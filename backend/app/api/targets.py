"""Target + consent API endpoints (Epic 1)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import api_error
from app.consent.service import (
    DomainAlreadyRegisteredError,
    PhraseMismatchError,
    TargetNotFoundError,
    confirm_consent,
    expected_consent_phrase,
    list_targets,
    register_target,
)
from app.db.session import get_session
from app.db.models import Scan, Target
from app.schemas.schemas import (
    ConsentConfirmIn,
    ConsentConfirmOut,
    ErrorOut,
    ScanMetadata,
    ScanStartOut,
    TargetCreate,
    TargetOut,
)

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", response_model=TargetOut, status_code=201)
async def create_target(
    body: TargetCreate,
    session: AsyncSession = Depends(get_session),
):
    try:
        target = await register_target(
            session, body.domain, body.base_url, body.owner_note
        )
    except DomainAlreadyRegisteredError:
        return api_error(409, "target_already_registered", "A target with this domain is already registered.")
    except ValueError as e:
        return api_error(422, "invalid_target", str(e))
    return TargetOut.model_validate(target, from_attributes=True)


@router.get("", response_model=list[TargetOut])
async def list_all_targets(session: AsyncSession = Depends(get_session)):
    targets = await list_targets(session)
    return [TargetOut.model_validate(t, from_attributes=True) for t in targets]


@router.get("/{target_id}", response_model=TargetOut)
async def get_target_detail(
    target_id: str, session: AsyncSession = Depends(get_session)
):
    target = await session.get(Target, target_id)
    if target is None:
        return api_error(404, "target_not_found", "Target not found.")
    return TargetOut.model_validate(target, from_attributes=True)


@router.post(
    "/{target_id}/consent",
    response_model=ConsentConfirmOut,
    responses={422: {"model": ErrorOut}, 404: {"model": ErrorOut}},
)
async def confirm_target_consent(
    target_id: str,
    body: ConsentConfirmIn,
    session: AsyncSession = Depends(get_session),
):
    try:
        target = await confirm_consent(session, target_id, body.typed_phrase)
    except TargetNotFoundError:
        return api_error(404, "target_not_found", "Target not found.")
    except PhraseMismatchError:
        return api_error(
            422,
            "consent_phrase_mismatch",
            "Typed phrase does not match the required phrase.",
        )
    return ConsentConfirmOut(
        id=target.id, domain=target.domain, consent_confirmed_at=target.consent_confirmed_at
    )


@router.get("/{target_id}/consent/phrase")
async def get_consent_phrase(
    target_id: str, session: AsyncSession = Depends(get_session)
):
    target = await session.get(Target, target_id)
    if target is None:
        return api_error(404, "target_not_found", "Target not found.")
    return {"phrase": expected_consent_phrase(target.domain)}


@router.get("/{target_id}/scans", response_model=list[ScanMetadata])
async def list_target_scans(
    target_id: str, session: AsyncSession = Depends(get_session)
):
    result = await session.execute(
        select(Scan).where(Scan.target_id == target_id).order_by(Scan.started_at.desc())
    )
    return [
        ScanMetadata.model_validate(s, from_attributes=True)
        for s in result.scalars().all()
    ]


@router.post(
    "/{target_id}/scans",
    response_model=ScanStartOut,
    status_code=202,
    responses={400: {"model": ErrorOut}, 404: {"model": ErrorOut}},
)
async def start_scan(target_id: str, session: AsyncSession = Depends(get_session)):
    """Start a scan on a target. 400 if consent not confirmed (Epic 1/2)."""
    from app.consent.service import build_confirmed_target
    from app.core.domain import ConsentNotConfirmedError
    from app.core.worker import run_scan
    from app.db.models import utcnow
    from app.queue.queue import get_queue

    try:
        confirmed = await build_confirmed_target(session, target_id)
    except TargetNotFoundError:
        return api_error(404, "target_not_found", "Target not found.")
    except ConsentNotConfirmedError as e:
        return api_error(400, "consent_not_confirmed", str(e))

    # Snapshot the consent record for the audit trail.
    from app.db.models import Target as TargetModel

    target_row = await session.get(TargetModel, target_id)
    scan = Scan(
        target_id=target_id,
        status="queued",
        consent_snapshot={
            "domain": confirmed.domain,
            "consent_confirmed_at": confirmed.consent_confirmed_at.isoformat(),
            "phrase_typed": target_row.consent_phrase_typed if target_row else "",
        },
        started_at=utcnow(),
        progress_pct=0,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    queue = get_queue()
    queue.start()
    queue.submit(lambda: run_scan(scan.id))

    return ScanStartOut(scan_id=scan.id, status="queued")

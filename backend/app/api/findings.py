"""Findings API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import api_error
from app.db.models import Finding, FixSuggestion
from app.db.session import get_session
from app.fixgen.fixgen import generate_and_store_fix
from app.schemas.schemas import (
    FindingDetailOut,
    FindingOut,
    FixOut,
)

router = APIRouter(tags=["findings"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _summary(f: Finding) -> str:
    ev = f.evidence or {}
    if f.module == "sqli":
        return (
            f"{ev.get('technique', '?')}-based injection; "
            f"TRUE payload {ev.get('true_len')} vs FALSE {ev.get('false_len')} bytes"
        )
    if f.module == "xss":
        return (
            f"{ev.get('type', '?')} XSS; canary token {ev.get('token')} "
            f"fired (execution confirmed)"
        )
    if f.module == "auth":
        return f"check={ev.get('check')} route={f.route}"
    if f.module == "secrets":
        return (
            f"{ev.get('secret_type')} at "
            f"{len(ev.get('locations', []))} location(s)"
        )
    if f.module == "headers":
        return f"header {ev.get('header')} {ev.get('status')} across {ev.get('affected_route_count')} routes"
    return str(ev)[:120]


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
async def list_scan_findings(
    scan_id: str, session: AsyncSession = Depends(get_session)
):
    result = await session.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    rows = list(result.scalars().all())
    rows.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    out = []
    for f in rows:
        out.append(
            FindingOut(
                id=f.id,
                module=f.module,
                subtype=f.subtype,
                severity=f.severity,
                route=f.route,
                parameter=f.parameter,
                reproducible=f.reproducible,
                created_at=f.created_at,
                evidence_summary=_summary(f),
            )
        )
    return out


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
async def get_finding(
    finding_id: str, session: AsyncSession = Depends(get_session)
):
    f = await session.get(Finding, finding_id)
    if f is None:
        return api_error(404, "finding_not_found", "Finding not found.")
    return FindingDetailOut(
        id=f.id,
        module=f.module,
        subtype=f.subtype,
        severity=f.severity,
        route=f.route,
        parameter=f.parameter,
        reproducible=f.reproducible,
        created_at=f.created_at,
        evidence=f.evidence or {},
    )


@router.get("/findings/{finding_id}/fix", response_model=FixOut)
async def get_fix(finding_id: str, session: AsyncSession = Depends(get_session)):
    res = await session.execute(
        select(FixSuggestion).where(FixSuggestion.finding_id == finding_id)
    )
    fix = res.scalar_one_or_none()
    if fix is None:
        return api_error(
            404,
            "fix_not_generated",
            "Fix generation hasn't run for this finding yet.",
        )
    return FixOut(diff=fix.diff, explanation=fix.explanation, model_used=fix.model_used)


@router.post("/findings/{finding_id}/fix", response_model=FixOut)
async def generate_fix(finding_id: str, session: AsyncSession = Depends(get_session)):
    f = await session.get(Finding, finding_id)
    if f is None:
        return api_error(404, "finding_not_found", "Finding not found.")
    # Delete existing suggestion if present, then regenerate.
    res = await session.execute(
        select(FixSuggestion).where(FixSuggestion.finding_id == finding_id)
    )
    existing = res.scalar_one_or_none()
    if existing is not None:
        await session.delete(existing)
        await session.commit()
    fix = await generate_and_store_fix(session, f)
    if fix is None:
        return api_error(500, "fix_generation_failed", "Fix generation failed.")
    return FixOut(diff=fix.diff, explanation=fix.explanation, model_used=fix.model_used)

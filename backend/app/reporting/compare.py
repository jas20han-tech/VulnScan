"""Scan comparison - "did this fix work?"

Matches findings between two scans by (module, subtype, route, parameter) and
classifies each as resolved / new / persisting.
"""
from __future__ import annotations

from collections import defaultdict

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding
from app.schemas.schemas import CompareFinding, CompareOut


def _key(f: Finding):
    return (f.module, f.subtype, f.route, f.parameter)


async def compare_scans(old_id: str, new_id: str, session: AsyncSession):
    old_res = await session.execute(select(Finding).where(Finding.scan_id == old_id))
    new_res = await session.execute(select(Finding).where(Finding.scan_id == new_id))
    old_rows = list(old_res.scalars().all())
    new_rows = list(new_res.scalars().all())

    old_map = {_key(f): f for f in old_rows}
    new_map = {_key(f): f for f in new_rows}

    findings: list[CompareFinding] = []
    # Persisting / resolved: every finding in old scan.
    for k, old_f in old_map.items():
        if k in new_map:
            findings.append(
                CompareFinding(
                    module=old_f.module,
                    subtype=old_f.subtype,
                    severity=old_f.severity,
                    route=old_f.route,
                    parameter=old_f.parameter,
                    status="persisting",
                )
            )
        else:
            findings.append(
                CompareFinding(
                    module=old_f.module,
                    subtype=old_f.subtype,
                    severity=old_f.severity,
                    route=old_f.route,
                    parameter=old_f.parameter,
                    status="resolved",
                )
            )
    # New: in new scan but not old.
    for k, new_f in new_map.items():
        if k not in old_map:
            findings.append(
                CompareFinding(
                    module=new_f.module,
                    subtype=new_f.subtype,
                    severity=new_f.severity,
                    route=new_f.route,
                    parameter=new_f.parameter,
                    status="new",
                )
            )
    return CompareOut(old_scan_id=old_id, new_scan_id=new_id, findings=findings)

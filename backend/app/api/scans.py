"""Scan API endpoints (Epic 2 start / orchestration)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import api_error
from app.db.session import get_session
from app.db.models import Scan
from app.schemas.schemas import (
    CompareOut,
    ScanMetadata,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/{scan_id}", response_model=ScanMetadata)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return api_error(404, "scan_not_found", "Scan not found.")
    return ScanMetadata.model_validate(scan, from_attributes=True)


@router.get("/{scan_id}/compare/{other_id}", response_model=CompareOut)
async def compare_scans(
    scan_id: str, other_id: str, session: AsyncSession = Depends(get_session)
):
    from app.reporting.compare import compare_scans

    return await compare_scans(scan_id, other_id, session)


@router.get("/{scan_id}/report")
async def get_report(scan_id: str, session: AsyncSession = Depends(get_session)):
    from fastapi.responses import FileResponse

    from app.db.models import Report

    res = await session.execute(select(Report).where(Report.scan_id == scan_id))
    report = res.scalar_one_or_none()
    if report is None:
        return api_error(404, "report_not_ready", "Report not generated yet.")
    path = report.file_path
    if path.endswith(".pdf"):
        return FileResponse(path, media_type="application/pdf", filename=f"vulnscan_{scan_id}.pdf")
    return FileResponse(path, media_type="text/html", filename=f"vulnscan_{scan_id}.html")

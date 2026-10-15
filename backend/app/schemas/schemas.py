from datetime import datetime

from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    domain: str
    base_url: str
    owner_note: str = ""


class TargetOut(BaseModel):
    id: str
    domain: str
    base_url: str
    owner_note: str = ""
    consent_confirmed_at: datetime | None = None
    consent_phrase_typed: str | None = None
    created_at: datetime


class ConsentConfirmIn(BaseModel):
    typed_phrase: str


class ConsentConfirmOut(BaseModel):
    id: str
    domain: str
    consent_confirmed_at: datetime


class ScanMetadata(BaseModel):
    id: str
    status: str
    progress_pct: int
    started_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None
    consent_snapshot: dict = Field(default_factory=dict)


class ScanStartOut(BaseModel):
    scan_id: str
    status: str = "queued"


class FindingOut(BaseModel):
    id: str
    module: str
    subtype: str
    severity: str
    route: str
    parameter: str | None = None
    reproducible: bool
    created_at: datetime
    evidence_summary: str


class FindingDetailOut(BaseModel):
    id: str
    module: str
    subtype: str
    severity: str
    route: str
    parameter: str | None = None
    reproducible: bool
    created_at: datetime
    evidence: dict


class FixOut(BaseModel):
    diff: str
    explanation: str
    model_used: str


class CompareFinding(BaseModel):
    module: str
    subtype: str
    severity: str
    route: str
    parameter: str | None = None
    status: str  # resolved | new | persisting


class CompareOut(BaseModel):
    old_scan_id: str
    new_scan_id: str
    findings: list[CompareFinding]


class ErrorOut(BaseModel):
    error: str
    message: str

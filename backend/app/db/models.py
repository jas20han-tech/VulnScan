import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def uuid_str() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=uuid_str)
    domain: Mapped[str] = mapped_column(Text, unique=True, index=True)
    base_url: Mapped[str] = mapped_column(Text)
    owner_note: Mapped[str] = mapped_column(Text, default="")
    consent_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consent_phrase_typed: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=uuid_str)
    target_id: Mapped[str] = mapped_column(
        Text, ForeignKey("targets.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "queued",
            "crawling",
            "scanning",
            "generating_fixes",
            "report_ready",
            "failed",
            name="scan_status",
        ),
        nullable=False,
        default="queued",
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    consent_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    target: Mapped["Target"] = relationship(back_populates="scans")
    crawl_results: Mapped[list["CrawlResult"]] = relationship(back_populates="scan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")
    report: Mapped["Report | None"] = relationship(back_populates="scan")


class CrawlResult(Base):
    __tablename__ = "crawl_results"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=uuid_str)
    scan_id: Mapped[str] = mapped_column(
        Text, ForeignKey("scans.id"), nullable=False, index=True
    )
    route: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(Text, nullable=False, default="GET")
    forms: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    js_bundles: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    baseline_headers: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    scan: Mapped["Scan"] = relationship(back_populates="crawl_results")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=uuid_str)
    scan_id: Mapped[str] = mapped_column(
        Text, ForeignKey("scans.id"), nullable=False, index=True
    )
    module: Mapped[str] = mapped_column(
        Enum("sqli", "xss", "auth", "secrets", "headers", name="finding_module"),
        nullable=False,
    )
    subtype: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", name="finding_severity"),
        nullable=False,
    )
    route: Mapped[str] = mapped_column(Text, nullable=False)
    parameter: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reproducible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    fix_suggestion: Mapped["FixSuggestion | None"] = relationship(
        back_populates="finding", uselist=False
    )


class FixSuggestion(Base):
    __tablename__ = "fix_suggestions"
    __table_args__ = (
        UniqueConstraint("finding_id", name="uq_fix_suggestion_finding"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=uuid_str)
    finding_id: Mapped[str] = mapped_column(
        Text, ForeignKey("findings.id"), nullable=False, unique=True
    )
    diff: Mapped[str] = mapped_column(Text, nullable=False, default="")
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    model_used: Mapped[str] = mapped_column(Text, nullable=False, default="template")

    finding: Mapped["Finding"] = relationship(back_populates="fix_suggestion")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=uuid_str)
    scan_id: Mapped[str] = mapped_column(
        Text, ForeignKey("scans.id"), nullable=False, unique=True
    )
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="report")

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.config import get_settings

settings = get_settings()

# NOTE: SQLite for v1 local dev. In production, point DATABASE_URL at
# postgresql+asyncpg://...; the models are written to be DB-agnostic.
engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}
    if settings.DATABASE_URL.startswith("sqlite")
    else {},
    poolclass=StaticPool if settings.DATABASE_URL.startswith("sqlite") else None,
    echo=False,
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


async def init_db() -> None:
    from app.db import models  # noqa: F401  (register models)

    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)

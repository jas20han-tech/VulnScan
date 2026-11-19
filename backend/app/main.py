"""VulnScan FastAPI backend entrypoint.

NOTE: This is a single-operator, authorized-targets-only tool. There is no
multi-user auth in v1 by design (out of scope per spec). If this were to become
multi-tenant, auth middleware would be inserted here, before the routers.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import findings, scans, targets
from app.db.session import init_db

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="VulnScan API",
    description="Authorized-targets-only web application vulnerability scanner.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(findings.router)


@app.get("/")
async def root():
    return {
        "service": "vulnscan",
        "message": "VulnScan API. Authorized targets only - scan only apps you own "
        "or deliberately-vulnerable test apps.",
    }

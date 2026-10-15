"""Shared API error helper.

Returns the documented error shape directly as the response body:
    {"error": "<stable_code>", "message": "<human message>"}
(rather than FastAPI's HTTPException wrapping it under {"detail": {...}}).
"""
from __future__ import annotations

from fastapi.responses import JSONResponse


def api_error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": code, "message": message},
    )

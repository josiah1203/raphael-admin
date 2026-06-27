"""Raphael service: raphael-admin."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from raphael_contracts.db import ensure_migrations
from raphael_contracts.errors import ErrorResponse
from raphael_admin.routes import router

ensure_migrations()

app = FastAPI(
    title="raphael-admin",
    description="User/policy/billing/security/compliance administration",
    version="0.1.0",
    openapi_url="/v1/admin/openapi.json" if "/v1/admin" else "/openapi.json",
)

app.include_router(router, prefix="/v1/admin" if "/v1/admin" else "")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "raphael-admin"}


@app.exception_handler(Exception)
async def unhandled(_request, exc: Exception) -> JSONResponse:
    err = ErrorResponse(code="internal_error", message=str(exc))
    return JSONResponse(status_code=500, content=err.model_dump())

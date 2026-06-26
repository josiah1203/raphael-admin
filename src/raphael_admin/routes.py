"""API routes for raphael-admin."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["raphael-admin"])


@router.get("")
def list_root() -> dict[str, str]:
  return {"service": "raphael-admin", "status": "stub"}

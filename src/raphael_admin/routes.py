"""Admin API — compliance, billing hooks."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException

from raphael_admin.compliance.iam_store import IAMStore

router = APIRouter(tags=["admin"])
_iam = IAMStore()


@router.get("")
def admin_status() -> dict[str, str]:
    return {"service": "raphael-admin", "status": "ok"}


@router.get("/billing")
def billing_status() -> dict[str, Any]:
    stripe_key = os.environ.get("RAPHAEL_STRIPE_SECRET_KEY", "")
    metronome_key = os.environ.get("RAPHAEL_METRONOME_API_KEY", "")
    return {
        "stripe_configured": bool(stripe_key),
        "metronome_configured": bool(metronome_key),
        "plan": "team",
    }


@router.post("/gdpr-delete")
def gdpr_delete(body: dict[str, Any]) -> dict[str, str]:
    subject_id = body.get("subject_id", "")
    if not subject_id:
        raise HTTPException(400, detail="subject_id_required")
    ok = _iam.anonymize(subject_id)
    return {"status": "scheduled" if ok else "not_found", "subject_id": subject_id}


@router.get("/subjects/{subject_id}")
def get_subject(subject_id: str) -> dict[str, Any]:
    subject = _iam.get_subject(subject_id)
    if not subject:
        raise HTTPException(404, detail="not_found")
    return {**subject, "pii_fields": [], "holds": subject.get("has_hold", False)}


@router.get("/iam/subjects/{subject_id}")
def iam_subject(subject_id: str) -> dict[str, Any]:
    return get_subject(subject_id)


@router.post("/iam/gdpr-delete")
def iam_gdpr_delete(body: dict[str, Any]) -> dict[str, str]:
    return gdpr_delete(body)

"""Admin API — compliance, billing hooks."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from raphael_admin.billing import StripeBilling
from raphael_admin.compliance.iam_store import IAMStore
from raphael_admin.plan_templates import PlanTemplateStore

router = APIRouter(tags=["admin"])
_iam = IAMStore()
_billing = StripeBilling()
_templates = PlanTemplateStore()


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


@router.post("/billing/checkout")
def billing_checkout(body: dict[str, Any], x_raphael_org_id: str | None = Header(default=None)) -> dict[str, Any]:
    org_id = body.get("org_id") or x_raphael_org_id or "org_default"
    plan = body.get("plan", "team")
    success_url = body.get("success_url", "http://localhost:5173/settings?billing=success")
    cancel_url = body.get("cancel_url", "http://localhost:5173/settings?billing=cancel")
    result = _billing.create_checkout_session(
        org_id=org_id,
        plan=plan,
        success_url=success_url,
        cancel_url=cancel_url,
        email=body.get("email"),
    )
    if "error" in result:
        raise HTTPException(400, detail=result)
    return result


@router.get("/billing/portal")
def billing_portal(
    return_url: str = "http://localhost:5173/settings",
    x_raphael_org_id: str | None = Header(default=None),
) -> dict[str, Any]:
    org_id = x_raphael_org_id or "org_default"
    result = _billing.create_portal_session(org_id, return_url)
    if "error" in result:
        raise HTTPException(400, detail=result)
    return result


@router.post("/billing/webhook")
async def billing_webhook(request: Request, stripe_signature: str | None = Header(default=None, alias="Stripe-Signature")) -> dict[str, Any]:
    payload = await request.body()
    result = _billing.handle_webhook(payload, stripe_signature)
    if "error" in result:
        raise HTTPException(400, detail=result)
    return result


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


@router.get("/iam/holds")
def list_holds() -> dict[str, list]:
    return {"holds": _iam.list_holds()}


@router.post("/iam/holds")
def add_hold(body: dict[str, Any]) -> dict[str, str]:
    entity_id = body.get("entity_id", "")
    if not entity_id:
        raise HTTPException(400, detail="entity_id_required")
    from datetime import UTC, datetime

    _iam.add_hold(entity_id, datetime.now(UTC).isoformat())
    return {"status": "held", "entity_id": entity_id}


@router.get("/licensing/templates")
def license_templates() -> dict[str, list]:
    templates = _templates.list_templates()
    return {
        "templates": [
            {"id": t["id"], "name": t["name"], "seats": t["seats"]}
            for t in templates
        ]
    }


@router.post("/domain/verify")
def verify_domain(body: dict[str, Any]) -> dict[str, Any]:
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        raise HTTPException(400, detail="domain_required")
    token = domain.replace(".", "-")
    return {
        "domain": domain,
        "status": "pending",
        "txt_record": f"hblabs-verify={token}",
    }

"""Domain tests — GDPR, IAM holds, billing, plan templates."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from raphael_admin.app import app
from raphael_admin.billing import BillingStore, StripeBilling
from raphael_admin.compliance.iam_store import IAMStore
from raphael_admin.plan_templates import PlanTemplateStore
from raphael_admin import routes


@pytest.fixture
def stores(tmp_path, monkeypatch):
    """Isolated SQLite stores for each test."""
    monkeypatch.setenv("RAPHAEL_STRIPE_SECRET_KEY", "sk_test_fake")
    monkeypatch.setenv("RAPHAEL_STRIPE_PRICE_TEAM", "price_team_test")
    monkeypatch.setenv("RAPHAEL_STRIPE_PRICE_ENTERPRISE", "price_enterprise_test")
    monkeypatch.setenv("RAPHAEL_STRIPE_WEBHOOK_SECRET", "whsec_test_secret")

    db_dir = tmp_path / "admin"
    db_dir.mkdir()
    iam_db = db_dir / "iam.db"
    billing_db = db_dir / "billing.db"

    iam = IAMStore(db_path=iam_db)
    billing = StripeBilling()
    billing.store = BillingStore(db_path=billing_db)
    templates = PlanTemplateStore(db_path=billing_db)

    routes._iam = iam
    routes._billing = billing
    routes._templates = templates

    yield {"iam": iam, "billing": billing, "templates": templates, "billing_db": billing_db}

    iam.close()


@pytest.fixture
def client(stores):
    return TestClient(app)


def _store_subject(iam: IAMStore, subject_id: str, email: str = "user@example.com") -> None:
    iam.store_pii(
        subject_id,
        {"email": email, "status": "active"},
        datetime.now(UTC).isoformat(),
    )


# --- GDPR ---


def test_gdpr_delete_anonymizes_subject(client, stores) -> None:
    subject_id = "subj_gdpr_1"
    _store_subject(stores["iam"], subject_id)

    res = client.post("/v1/admin/gdpr-delete", json={"subject_id": subject_id})
    assert res.status_code == 200
    assert res.json() == {"status": "scheduled", "subject_id": subject_id}

    subject = stores["iam"].get_subject(subject_id)
    assert subject is not None
    assert subject["status"] == "anonymized"


def test_gdpr_delete_not_found(client) -> None:
    res = client.post("/v1/admin/gdpr-delete", json={"subject_id": "missing-subject"})
    assert res.status_code == 200
    assert res.json()["status"] == "not_found"


def test_gdpr_delete_requires_subject_id(client) -> None:
    res = client.post("/v1/admin/gdpr-delete", json={})
    assert res.status_code == 400


def test_iam_gdpr_delete_alias(client, stores) -> None:
    subject_id = "subj_iam_gdpr"
    _store_subject(stores["iam"], subject_id)

    res = client.post("/v1/admin/iam/gdpr-delete", json={"subject_id": subject_id})
    assert res.status_code == 200
    assert res.json()["status"] == "scheduled"


# --- IAM holds ---


def test_add_and_list_holds(client, stores) -> None:
    res = client.post("/v1/admin/iam/holds", json={"entity_id": "entity-hold-1"})
    assert res.status_code == 200
    assert res.json() == {"status": "held", "entity_id": "entity-hold-1"}

    res = client.get("/v1/admin/iam/holds")
    assert res.status_code == 200
    holds = res.json()["holds"]
    assert len(holds) == 1
    assert holds[0]["entity_id"] == "entity-hold-1"
    assert "created_at" in holds[0]


def test_subject_reflects_hold(client, stores) -> None:
    subject_id = "subj_with_hold"
    _store_subject(stores["iam"], subject_id)
    stores["iam"].add_hold(subject_id, datetime.now(UTC).isoformat())

    res = client.get(f"/v1/admin/subjects/{subject_id}")
    assert res.status_code == 200
    body = res.json()
    assert body["holds"] is True
    assert body["has_hold"] is True


def test_add_hold_requires_entity_id(client) -> None:
    res = client.post("/v1/admin/iam/holds", json={})
    assert res.status_code == 400


def test_get_subject_not_found(client) -> None:
    res = client.get("/v1/admin/subjects/does-not-exist")
    assert res.status_code == 404


# --- Plan templates ---


def test_license_templates_from_db(client, stores) -> None:
    res = client.get("/v1/admin/licensing/templates")
    assert res.status_code == 200
    templates = res.json()["templates"]
    ids = {t["id"] for t in templates}
    assert "team" in ids
    assert "enterprise" in ids
    team = next(t for t in templates if t["id"] == "team")
    assert team["name"] == "Team"
    assert team["seats"] == 25


# --- Billing (Stripe SDK mocked) ---


@patch("raphael_admin.billing.stripe.checkout.Session.create")
@patch("raphael_admin.billing.stripe.Customer.create")
def test_billing_checkout_creates_session(mock_customer, mock_session, client, stores) -> None:
    mock_customer.return_value = MagicMock(id="cus_test123")
    mock_session.return_value = MagicMock(
        url="https://checkout.stripe.com/c/pay/cs_test",
        id="cs_test_session",
    )

    res = client.post(
        "/v1/admin/billing/checkout",
        json={"org_id": "org_checkout", "plan": "team"},
        headers={"X-Raphael-Org-Id": "org_checkout"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["checkout_url"] == "https://checkout.stripe.com/c/pay/cs_test"
    assert body["session_id"] == "cs_test_session"

    mock_customer.assert_called_once()
    mock_session.assert_called_once()
    assert stores["billing"].store.get_customer("org_checkout") == "cus_test123"


@patch("raphael_admin.billing.stripe.billing_portal.Session.create")
def test_billing_portal_requires_customer(mock_portal, client, stores) -> None:
    res = client.get("/v1/admin/billing/portal", headers={"X-Raphael-Org-Id": "org_no_customer"})
    assert res.status_code == 400

    stores["billing"].store.set_customer("org_portal", "cus_portal", plan="team")
    mock_portal.return_value = MagicMock(url="https://billing.stripe.com/portal/test")

    res = client.get("/v1/admin/billing/portal", headers={"X-Raphael-Org-Id": "org_portal"})
    assert res.status_code == 200
    assert res.json()["portal_url"] == "https://billing.stripe.com/portal/test"


def test_billing_checkout_not_configured(client, stores, monkeypatch) -> None:
    monkeypatch.delenv("RAPHAEL_STRIPE_SECRET_KEY", raising=False)
    stores["billing"].secret_key = ""
    stores["billing"].store = BillingStore(db_path=stores["billing_db"])

    res = client.post("/v1/admin/billing/checkout", json={"org_id": "org_x", "plan": "team"})
    assert res.status_code == 400
    assert res.json()["detail"]["error"] == "stripe_not_configured"


@patch("raphael_admin.billing.stripe.Webhook.construct_event")
def test_billing_webhook_checkout_completed(mock_construct, client, stores) -> None:
    mock_construct.return_value = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_webhook",
                "metadata": {"org_id": "org_webhook", "plan": "enterprise"},
            }
        },
    }

    res = client.post(
        "/v1/admin/billing/webhook",
        content=b"{}",
        headers={"Stripe-Signature": "sig_test"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "processed"

    assert stores["billing"].store.get_customer("org_webhook") == "cus_webhook"
    assert stores["billing"].store.get_plan("org_webhook") == "enterprise"


@patch("raphael_admin.billing.stripe.Webhook.construct_event")
def test_billing_webhook_subscription_updates_plan(mock_construct, client, stores) -> None:
    stores["billing"].store.set_customer("org_sub", "cus_sub", plan="free")

    mock_construct.return_value = {
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "status": "active",
                "metadata": {"org_id": "org_sub"},
            }
        },
    }

    res = client.post(
        "/v1/admin/billing/webhook",
        content=b"{}",
        headers={"Stripe-Signature": "sig_test"},
    )
    assert res.status_code == 200
    assert stores["billing"].store.get_plan("org_sub") == "team"

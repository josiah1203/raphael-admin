"""Stripe billing — checkout, portal, webhooks."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import stripe


class BillingStore:
    def __init__(self, db_path: Path | None = None) -> None:
        from raphael_contracts import db as rdb

        self._postgres = rdb.is_postgres()
        if self._postgres:
            rdb.ensure_migrations()
            self.db_path = Path("postgres")
        else:
            path = db_path or Path(os.environ.get("RAPHAEL_ADMIN_DB", "/tmp/raphael-admin-billing.db"))
            self.db_path = path
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS billing_customers (
                        org_id TEXT PRIMARY KEY,
                        stripe_customer_id TEXT NOT NULL,
                        plan TEXT DEFAULT 'free',
                        updated_at TEXT NOT NULL
                    )
                    """
                )

    def _table(self) -> str:
        return "admin_billing_customers" if self._postgres else "billing_customers"

    def _execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        if self._postgres:
            from raphael_contracts.db import pg_execute

            pg_execute(sql, params)
            return
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(sql, params)
            conn.commit()

    def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> Any | None:
        if self._postgres:
            from raphael_contracts.db import pg_fetchone

            return pg_fetchone(sql, params)
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(sql, params).fetchone()

    def get_customer(self, org_id: str) -> str | None:
        table = self._table()
        row = self._fetchone(
            f"SELECT stripe_customer_id FROM {table} WHERE org_id = ?",
            (org_id,),
        )
        if not row:
            return None
        return row["stripe_customer_id"] if isinstance(row, dict) else row[0]

    def set_customer(self, org_id: str, stripe_customer_id: str, plan: str = "free") -> None:
        now = datetime.now(timezone.utc).isoformat()
        table = self._table()
        if self._postgres:
            from raphael_contracts.db import adapt_insert_or_replace

            sql = adapt_insert_or_replace(
                f"""
                INSERT OR REPLACE INTO {table} (org_id, stripe_customer_id, plan, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                "org_id",
                "stripe_customer_id = EXCLUDED.stripe_customer_id, "
                "plan = EXCLUDED.plan, updated_at = EXCLUDED.updated_at",
            )
            self._execute(sql, (org_id, stripe_customer_id, plan, now))
        else:
            self._execute(
                f"""
                INSERT OR REPLACE INTO {table} (org_id, stripe_customer_id, plan, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (org_id, stripe_customer_id, plan, now),
            )

    def set_plan(self, org_id: str, plan: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        table = self._table()
        self._execute(
            f"UPDATE {table} SET plan = ?, updated_at = ? WHERE org_id = ?",
            (plan, now, org_id),
        )

    def get_plan(self, org_id: str) -> str | None:
        table = self._table()
        row = self._fetchone(f"SELECT plan FROM {table} WHERE org_id = ?", (org_id,))
        if not row:
            return None
        return row["plan"] if isinstance(row, dict) else row[0]


class StripeBilling:
    def __init__(self) -> None:
        self.secret_key = os.environ.get("RAPHAEL_STRIPE_SECRET_KEY", "")
        self.webhook_secret = os.environ.get("RAPHAEL_STRIPE_WEBHOOK_SECRET", "")
        self.price_team = os.environ.get("RAPHAEL_STRIPE_PRICE_TEAM", "")
        self.price_enterprise = os.environ.get("RAPHAEL_STRIPE_PRICE_ENTERPRISE", "")
        self.store = BillingStore()
        if self.secret_key:
            stripe.api_key = self.secret_key

    @property
    def configured(self) -> bool:
        return bool(self.secret_key)

    def _price_for_plan(self, plan: str) -> str:
        if plan == "enterprise":
            return self.price_enterprise
        return self.price_team

    def _ensure_customer(self, org_id: str, email: str | None = None) -> str:
        existing = self.store.get_customer(org_id)
        if existing:
            return existing
        customer = stripe.Customer.create(
            metadata={"org_id": org_id},
            email=email,
        )
        self.store.set_customer(org_id, customer.id)
        return customer.id

    def create_checkout_session(
        self,
        org_id: str,
        plan: str,
        success_url: str,
        cancel_url: str,
        email: str | None = None,
    ) -> dict[str, Any]:
        if not self.configured:
            return {"error": "stripe_not_configured"}
        price_id = self._price_for_plan(plan)
        if not price_id:
            return {"error": "price_not_configured", "plan": plan}
        customer_id = self._ensure_customer(org_id, email)
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={"org_id": org_id, "plan": plan},
        )
        return {"checkout_url": session.url, "session_id": session.id}

    def create_portal_session(self, org_id: str, return_url: str) -> dict[str, Any]:
        if not self.configured:
            return {"error": "stripe_not_configured"}
        customer_id = self.store.get_customer(org_id)
        if not customer_id:
            return {"error": "customer_not_found"}
        session = stripe.billing_portal.Session.create(customer=customer_id, return_url=return_url)
        return {"portal_url": session.url}

    def handle_webhook(self, payload: bytes, sig_header: str | None) -> dict[str, Any]:
        if not self.webhook_secret:
            return {"error": "webhook_not_configured"}
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, self.webhook_secret)
        except ValueError:
            return {"error": "invalid_payload"}
        except stripe.error.SignatureVerificationError:
            return {"error": "invalid_signature"}

        event_type = event["type"]
        data = event["data"]["object"]

        if event_type == "checkout.session.completed":
            org_id = (data.get("metadata") or {}).get("org_id", "org_default")
            plan = (data.get("metadata") or {}).get("plan", "team")
            customer_id = data.get("customer")
            if customer_id:
                self.store.set_customer(org_id, customer_id, plan=plan)

        if event_type in ("customer.subscription.updated", "customer.subscription.created"):
            org_id = (data.get("metadata") or {}).get("org_id")
            if org_id:
                status = data.get("status", "")
                plan = "team" if status == "active" else "free"
                self.store.set_plan(org_id, plan)

        return {"status": "processed", "type": event_type}

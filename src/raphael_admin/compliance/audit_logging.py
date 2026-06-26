import logging
from enum import Enum
from typing import Any

# Dedicated audit logger
logger = logging.getLogger("calliope.audit")

class AuditEvent(Enum):
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    API_KEY_CREATED = "API_KEY_CREATED"
    API_KEY_REVOKED = "API_KEY_REVOKED"
    WEBHOOK_SECRET_CHANGED = "WEBHOOK_SECRET_CHANGED"
    ENCRYPTION_KEY_ACCESSED = "ENCRYPTION_KEY_ACCESSED"
    DATA_DECRYPTED = "DATA_DECRYPTED"
    ADMIN_OPERATION = "ADMIN_OPERATION"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    DATA_INGESTED = "DATA_INGESTED"

def log_audit(event: AuditEvent, principal: str | None = None, resource: str | None = None, **kwargs: Any) -> None:
    """Record a security-sensitive event to the audit log."""
    msg = f"AUDIT: event={event.value} principal={principal or 'anonymous'} resource={resource or 'none'}"
    if kwargs:
        msg += " " + " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.info(msg)

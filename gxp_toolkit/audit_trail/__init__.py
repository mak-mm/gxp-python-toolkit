"""
Audit Trail Module - GxP-compliant audit logging.

Provides comprehensive audit trail functionality including automatic logging,
immutable storage, and compliance reporting per 21 CFR Part 11.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from .decorators import (
    audit_activity,
    audit_approve,
    audit_create,
    audit_delete,
    audit_log,
    audit_reject,
    audit_update,
)
from .logger import AuditLogger
from .models import AuditAction, AuditEntry, AuditQuery, AuditReport
from .storage import AuditStorage, get_audit_storage

# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def audit_event(
    action: str,
    resource_type: str,
    resource_id: str,
    user_id: Optional[str] = None,
    result: str = "success",
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
) -> None:
    """
    Log an audit event.

    This is a convenience function for logging audit events without
    needing to instantiate an AuditLogger.

    Args:
        action: Action performed (e.g., "create", "update", "delete")
        resource_type: Type of resource affected
        resource_id: ID of the resource
        user_id: ID of user performing action
        result: Result of action ("success" or "failure")
        details: Additional details about the event
        timestamp: Event timestamp (defaults to now)
    """
    # For now, this is a stub that can be implemented properly later
    # In production, this would integrate with the async audit logger
    pass


__all__ = [
    # Logger
    "AuditLogger",
    "get_audit_logger",
    # Convenience function
    "audit_event",
    # Decorators
    "audit_log",
    "audit_activity",
    "audit_create",
    "audit_update",
    "audit_delete",
    "audit_approve",
    "audit_reject",
    # Models
    "AuditEntry",
    "AuditAction",
    "AuditReport",
    "AuditQuery",
    # Storage
    "AuditStorage",
    "get_audit_storage",
]

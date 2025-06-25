"""Exceptions for soft delete operations."""

from typing import Optional


class SoftDeleteError(Exception):
    """Base exception for soft delete operations."""

    def __init__(self, message: str, entity_id: Optional[str] = None):
        self.entity_id = entity_id
        super().__init__(message)


class AlreadyDeletedException(SoftDeleteError):
    """Raised when attempting to delete an already deleted entity."""

    def __init__(self, entity_id: str):
        super().__init__(
            f"Entity {entity_id} is already deleted and cannot be deleted again",
            entity_id=entity_id,
        )


class NotDeletedException(SoftDeleteError):
    """Raised when attempting to restore a non-deleted entity."""

    def __init__(self, entity_id: str):
        super().__init__(
            f"Entity {entity_id} is not deleted and cannot be restored",
            entity_id=entity_id,
        )


class RestoreNotAllowedException(SoftDeleteError):
    """Raised when restoration is not allowed due to business rules."""

    def __init__(self, entity_id: str, reason: str):
        super().__init__(
            f"Entity {entity_id} cannot be restored: {reason}",
            entity_id=entity_id,
        )


class RetentionPolicyViolation(SoftDeleteError):
    """Raised when an operation violates retention policy."""

    def __init__(self, message: str):
        super().__init__(message)

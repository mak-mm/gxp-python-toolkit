"""
Soft Delete Module - GxP-compliant data retention.

Provides mixins, services, and utilities for implementing soft delete patterns
that comply with 21 CFR Part 11 and EU Annex 11 requirements.
"""

from .exceptions import (
    AlreadyDeletedException,
    NotDeletedException,
    RestoreNotAllowedException,
    RetentionPolicyViolation,
    SoftDeleteError,
)
from .mixins import CascadeSoftDeleteMixin, SoftDeleteMixin
from .models import DeletionRequest, RestoreRequest, RetentionCategory, RetentionPolicy
from .services import SoftDeleteService

__all__ = [
    # Mixins
    "SoftDeleteMixin",
    "CascadeSoftDeleteMixin",
    # Services
    "SoftDeleteService",
    # Models
    "DeletionRequest",
    "RestoreRequest",
    "RetentionPolicy",
    "RetentionCategory",
    # Exceptions
    "SoftDeleteError",
    "AlreadyDeletedException",
    "NotDeletedException",
    "RestoreNotAllowedException",
    "RetentionPolicyViolation",
]

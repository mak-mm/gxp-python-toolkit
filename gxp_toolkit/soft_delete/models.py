"""
Data models for soft delete operations.

These models define the structure for deletion requests, restoration requests,
and retention policies in compliance with GxP requirements.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator


class DeletionRequestStatus(str, Enum):
    """Status values for deletion requests."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    CANCELLED = "cancelled"


class RetentionCategory(str, Enum):
    """Categories for data retention policies."""

    CRITICAL_GXP = "critical_gxp"  # Never delete (e.g., batch records)
    STANDARD_GXP = "standard_gxp"  # 7+ years retention
    SUPPORTING = "supporting"  # 3+ years retention
    TEMPORARY = "temporary"  # 90+ days retention


class DeletionRequest(BaseModel):
    """Model for requesting soft deletion with approval workflow."""

    model_config = ConfigDict(use_enum_values=True)

    entity_type: str = Field(
        ..., description="Type of entity to delete", min_length=1, max_length=100
    )
    entity_id: str = Field(
        ..., description="ID of entity to delete", min_length=1, max_length=100
    )
    requester_id: str = Field(
        ..., description="ID of user requesting deletion", min_length=1, max_length=100
    )
    reason: str = Field(
        ..., description="Detailed reason for deletion", min_length=10, max_length=500
    )
    reference_id: Optional[str] = Field(
        None, description="Reference to change request, ticket, etc.", max_length=100
    )
    password: Optional[str] = Field(
        None, description="Password for electronic signature if required"
    )
    urgency: str = Field(
        "normal",
        description="Urgency level: low, normal, high, critical",
        pattern="^(low|normal|high|critical)$",
    )

    @field_validator("reason")
    @classmethod
    def validate_reason_quality(cls, v: str) -> str:
        """Ensure meaningful deletion reasons."""
        generic_reasons = {
            "not needed",
            "delete",
            "remove",
            "n/a",
            "test",
            "cleanup",
            "mistake",
            "error",
            "wrong",
            "duplicate",
            "temp",
            "old",
        }

        if v.lower().strip() in generic_reasons:
            raise ValueError(
                "Please provide a specific reason for deletion. "
                "Generic reasons are not acceptable for audit purposes. "
                "Include context such as: contamination found, "
                "obsolete per change request CR-123, "
                "data entry error - incorrect batch number, etc."
            )

        # Check for minimum word count to ensure detail
        word_count = len(v.split())
        if word_count < 3:
            raise ValueError(
                "Deletion reason must contain at least 3 words "
                "to ensure adequate justification"
            )

        return v.strip()


class RestoreRequest(BaseModel):
    """Model for requesting restoration of soft-deleted data."""

    model_config = ConfigDict(use_enum_values=True)

    entity_type: str = Field(
        ..., description="Type of entity to restore", min_length=1, max_length=100
    )
    entity_id: str = Field(
        ..., description="ID of entity to restore", min_length=1, max_length=100
    )
    requester_id: str = Field(
        ...,
        description="ID of user requesting restoration",
        min_length=1,
        max_length=100,
    )
    reason: str = Field(
        ...,
        description="Detailed reason for restoration",
        min_length=10,
        max_length=500,
    )
    reference_id: Optional[str] = Field(
        None, description="Reference to approval, ticket, etc.", max_length=100
    )

    @field_validator("reason")
    @classmethod
    def validate_reason_quality(cls, v: str) -> str:
        """Ensure meaningful restoration reasons."""
        generic_reasons = {
            "restore",
            "undelete",
            "bring back",
            "need it",
            "mistake",
            "error",
            "wrong",
            "accident",
        }

        if v.lower().strip() in generic_reasons:
            raise ValueError(
                "Please provide a specific reason for restoration. "
                "Include context such as: deleted in error - needed for audit, "
                "required for investigation INV-456, "
                "restore per management approval MA-789, etc."
            )

        # Check for minimum word count
        word_count = len(v.split())
        if word_count < 3:
            raise ValueError("Restoration reason must contain at least 3 words")

        return v.strip()


class RetentionPolicy(BaseModel):
    """Defines retention requirements for different data types."""

    model_config = ConfigDict(use_enum_values=True)

    entity_type: str = Field(..., description="Type of entity this policy applies to")
    category: RetentionCategory = Field(..., description="Retention category")
    minimum_retention_days: int = Field(
        ..., description="Minimum days to retain after deletion", gt=0
    )
    requires_approval_to_purge: bool = Field(
        True, description="Whether purging requires approval"
    )
    archive_after_days: Optional[int] = Field(
        None, description="Days before moving to archive storage", gt=0
    )
    purge_allowed: bool = Field(True, description="Whether data can ever be purged")

    def can_purge(self, deleted_date: datetime) -> bool:
        """
        Check if data can be permanently purged.

        Args:
            deleted_date: When the data was soft deleted

        Returns:
            True if purging is allowed based on policy
        """
        if not self.purge_allowed:
            return False

        if self.category == RetentionCategory.CRITICAL_GXP:
            return False  # Never purge critical GxP data

        days_deleted = (datetime.utcnow() - deleted_date).days
        return days_deleted >= self.minimum_retention_days

    def should_archive(self, deleted_date: datetime) -> bool:
        """
        Check if data should be moved to archive storage.

        Args:
            deleted_date: When the data was soft deleted

        Returns:
            True if data should be archived
        """
        if not self.archive_after_days:
            return False

        days_deleted = (datetime.utcnow() - deleted_date).days
        return days_deleted >= self.archive_after_days

    @field_validator("minimum_retention_days")
    @classmethod
    def validate_retention_period(cls, v: int, info: ValidationInfo) -> int:
        """Ensure retention periods meet regulatory minimums."""
        if "category" in info.data:
            category = info.data["category"]

            # Enforce minimum retention by category
            if category == RetentionCategory.CRITICAL_GXP and v < 999999:
                # Effectively never delete
                return 999999
            elif category == RetentionCategory.STANDARD_GXP and v < 2555:
                # Minimum 7 years
                raise ValueError(
                    "Standard GxP data must be retained for at least 7 years "
                    "(2555 days)"
                )
            elif category == RetentionCategory.SUPPORTING and v < 1095:
                # Minimum 3 years
                raise ValueError(
                    "Supporting data must be retained for at least 3 years (1095 days)"
                )
            elif category == RetentionCategory.TEMPORARY and v < 90:
                # Minimum 90 days
                raise ValueError("Temporary data must be retained for at least 90 days")

        return v


class DeletionApproval(BaseModel):
    """Model for deletion approval records."""

    request_id: str = Field(..., description="ID of deletion request")
    approver_id: str = Field(..., description="ID of approver")
    approved_at: datetime = Field(
        default_factory=datetime.utcnow, description="When approval was granted"
    )
    comments: Optional[str] = Field(
        None, description="Approval comments", max_length=500
    )
    electronic_signature_id: Optional[str] = Field(
        None, description="ID of electronic signature if required"
    )


class DeletionReport(BaseModel):
    """Model for deletion compliance reports."""

    start_date: datetime = Field(..., description="Report period start")
    end_date: datetime = Field(..., description="Report period end")
    total_deletions: int = Field(..., description="Total records deleted")
    by_type: Dict[str, int] = Field(
        default_factory=dict, description="Deletions by entity type"
    )
    by_user: Dict[str, int] = Field(
        default_factory=dict, description="Deletions by user"
    )
    by_reason_category: Dict[str, int] = Field(
        default_factory=dict, description="Deletions by reason category"
    )
    pending_approvals: int = Field(0, description="Number of pending deletion requests")
    restorations: int = Field(0, description="Number of restorations in period")

    def add_deletion(
        self, entity_type: str, user_id: str, reason_category: str
    ) -> None:
        """Add a deletion to the report statistics."""
        self.total_deletions += 1

        # Update by type
        if entity_type not in self.by_type:
            self.by_type[entity_type] = 0
        self.by_type[entity_type] += 1

        # Update by user
        if user_id not in self.by_user:
            self.by_user[user_id] = 0
        self.by_user[user_id] += 1

        # Update by reason category
        if reason_category not in self.by_reason_category:
            self.by_reason_category[reason_category] = 0
        self.by_reason_category[reason_category] += 1

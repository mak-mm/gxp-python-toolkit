"""
Data models for audit trail functionality.

These models define the structure for audit entries and reports
in compliance with 21 CFR Part 11 requirements.
"""

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)


class AuditAction(str, Enum):
    """Standard audit actions for GxP systems."""

    # Data operations
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"

    # Authentication events
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    LOGIN_FAILED = "LOGIN_FAILED"
    SESSION_EXPIRED = "SESSION_EXPIRED"

    # Authorization events
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"

    # Approval events
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    SIGN = "SIGN"
    COUNTERSIGN = "COUNTERSIGN"

    # System events
    SYSTEM_START = "SYSTEM_START"
    SYSTEM_STOP = "SYSTEM_STOP"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    BACKUP_CREATED = "BACKUP_CREATED"

    # Data integrity events
    VALIDATION_PASSED = "VALIDATION_PASSED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    CHECKSUM_VERIFIED = "CHECKSUM_VERIFIED"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
    INTEGRITY_CHECK = "INTEGRITY_CHECK"

    # Archive events
    ARCHIVE_CREATED = "ARCHIVE_CREATED"
    ARCHIVE_RESTORED = "ARCHIVE_RESTORED"

    # Report events
    REPORT_GENERATED = "REPORT_GENERATED"

    # Custom actions
    CUSTOM = "CUSTOM"


class AuditEntry(BaseModel):
    """
    Immutable audit trail entry compliant with 21 CFR Part 11.

    Each entry captures the complete context of an action including
    who, what, when, where, and why.
    """

    model_config = ConfigDict(use_enum_values=True)

    # Unique identifier
    id: str = Field(..., description="Unique identifier for the audit entry")

    # When - Temporal information
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="UTC timestamp of the action"
    )
    local_timestamp: Optional[datetime] = Field(
        None, description="Local timestamp with timezone info"
    )

    # Who - User information
    user_id: str = Field(..., description="ID of user performing the action")
    user_name: Optional[str] = Field(None, description="Display name of user")
    user_roles: List[str] = Field(
        default_factory=list, description="User's roles at time of action"
    )

    # What - Action details
    action: AuditAction = Field(..., description="Type of action performed")
    entity_type: Optional[str] = Field(None, description="Type of entity affected")
    entity_id: Optional[str] = Field(None, description="ID of entity affected")

    # Changes - For UPDATE actions
    old_values: Optional[Dict[str, Any]] = Field(
        None, description="Previous values (for updates)"
    )
    new_values: Optional[Dict[str, Any]] = Field(
        None, description="New values (for updates)"
    )

    # Why - Reason and context
    reason: Optional[str] = Field(
        None, description="Reason for the action", min_length=10
    )
    reference_id: Optional[str] = Field(
        None, description="Reference to change request, ticket, etc."
    )

    # Where - System context
    application: str = Field(..., description="Application name")
    module: Optional[str] = Field(None, description="Module or component")
    function: Optional[str] = Field(None, description="Function or method name")

    # Network context
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="Client user agent")
    session_id: Optional[str] = Field(None, description="Session identifier")

    # Additional details
    details: Optional[Dict[str, Any]] = Field(
        None, description="Additional context-specific details"
    )

    # Result information
    success: bool = Field(True, description="Whether the action succeeded")
    error_message: Optional[str] = Field(
        None, description="Error message if action failed"
    )

    # Data integrity
    checksum: Optional[str] = Field(
        None, description="Checksum of the entry for integrity verification"
    )

    def calculate_checksum(self, algorithm: str = "sha256") -> str:
        """
        Calculate checksum for the audit entry.

        Args:
            algorithm: Hash algorithm to use

        Returns:
            Hex digest of the checksum
        """
        # Create a deterministic string representation
        data = {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "old_values": self.old_values,
            "new_values": self.new_values,
            "success": self.success,
        }

        # Sort keys for consistency
        json_str = json.dumps(data, sort_keys=True, default=str)

        # Calculate hash
        if algorithm == "sha256":
            return hashlib.sha256(json_str.encode()).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(json_str.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def verify_checksum(
        self, expected_checksum: str, algorithm: str = "sha256"
    ) -> bool:
        """
        Verify the integrity of the audit entry.

        Args:
            expected_checksum: Expected checksum value
            algorithm: Hash algorithm used

        Returns:
            True if checksum matches
        """
        calculated = self.calculate_checksum(algorithm)
        return calculated == expected_checksum

    @model_validator(mode="after")
    def validate_reason_for_critical_actions(self) -> "AuditEntry":
        """Ensure critical actions have reasons."""
        critical_actions = {
            AuditAction.DELETE,
            AuditAction.APPROVE,
            AuditAction.REJECT,
            AuditAction.CONFIG_CHANGE,
        }

        if self.action in critical_actions and not self.reason:
            raise ValueError(f"Reason is required for {self.action} actions")

        return self

    def to_log_format(self) -> str:
        """
        Convert to a standardized log format string.

        Returns:
            Formatted log string
        """
        parts = [
            f"[{self.timestamp.isoformat()}]",
            f"USER={self.user_id}",
            f"ACTION={self.action}",
        ]

        if self.entity_type and self.entity_id:
            parts.append(f"ENTITY={self.entity_type}:{self.entity_id}")

        if self.reason:
            parts.append(f"REASON='{self.reason}'")

        if not self.success:
            parts.append(f"ERROR='{self.error_message}'")

        return " ".join(parts)


class AuditQuery(BaseModel):
    """Query parameters for searching audit logs."""

    # Time range
    start_date: Optional[datetime] = Field(None, description="Start of time range")
    end_date: Optional[datetime] = Field(None, description="End of time range")

    # User filters
    user_ids: Optional[List[str]] = Field(None, description="Filter by user IDs")
    user_roles: Optional[List[str]] = Field(None, description="Filter by user roles")

    # Action filters
    actions: Optional[List[AuditAction]] = Field(
        None, description="Filter by action types"
    )

    # Entity filters
    entity_types: Optional[List[str]] = Field(
        None, description="Filter by entity types"
    )
    entity_ids: Optional[List[str]] = Field(None, description="Filter by entity IDs")

    # Result filters
    success_only: bool = Field(False, description="Only show successful actions")
    failures_only: bool = Field(False, description="Only show failed actions")

    # Search
    search_text: Optional[str] = Field(
        None, description="Text search in reasons and details"
    )

    # Pagination
    limit: int = Field(100, description="Maximum results to return", gt=0, le=1000)
    offset: int = Field(0, description="Result offset for pagination", ge=0)

    # Sorting
    sort_by: str = Field("timestamp", description="Field to sort by")
    sort_desc: bool = Field(True, description="Sort in descending order")

    @field_validator("end_date")
    @classmethod
    def validate_date_range(
        cls, v: Optional[datetime], info: ValidationInfo
    ) -> Optional[datetime]:
        """Ensure end date is after start date."""
        if v and "start_date" in info.data and info.data["start_date"]:
            if v < info.data["start_date"]:
                raise ValueError("End date must be after start date")
        return v


class AuditReport(BaseModel):
    """Audit report for compliance and analysis."""

    # Report metadata
    report_id: str = Field(..., description="Unique report identifier")
    generated_at: datetime = Field(
        default_factory=datetime.utcnow, description="When report was generated"
    )
    generated_by: str = Field(..., description="User who generated the report")

    # Report parameters
    start_date: datetime = Field(..., description="Report period start")
    end_date: datetime = Field(..., description="Report period end")
    filters: Dict[str, Any] = Field(
        default_factory=dict, description="Filters applied to report"
    )

    # Summary statistics
    total_entries: int = Field(0, description="Total audit entries in period")
    total_users: int = Field(0, description="Unique users in period")

    # Breakdown by action
    by_action: Dict[str, int] = Field(
        default_factory=dict, description="Entry count by action type"
    )

    # Breakdown by user
    by_user: Dict[str, int] = Field(
        default_factory=dict, description="Entry count by user"
    )

    # Breakdown by entity type
    by_entity_type: Dict[str, int] = Field(
        default_factory=dict, description="Entry count by entity type"
    )

    # Failure analysis
    total_failures: int = Field(0, description="Total failed actions")
    failure_rate: float = Field(0.0, description="Percentage of failed actions")
    failures_by_type: Dict[str, int] = Field(
        default_factory=dict, description="Failures by action type"
    )

    # Critical actions
    critical_actions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of critical actions (DELETE, APPROVE, etc.)",
    )

    # Anomalies detected
    anomalies: List[Dict[str, Any]] = Field(
        default_factory=list, description="Detected anomalies or suspicious patterns"
    )

    def add_entry(self, entry: AuditEntry) -> None:
        """Add an audit entry to the report statistics."""
        self.total_entries += 1

        # Update action breakdown
        action_key = entry.action
        if action_key not in self.by_action:
            self.by_action[action_key] = 0
        self.by_action[action_key] += 1

        # Update user breakdown
        if entry.user_id not in self.by_user:
            self.by_user[entry.user_id] = 0
        self.by_user[entry.user_id] += 1

        # Update entity type breakdown
        if entry.entity_type:
            if entry.entity_type not in self.by_entity_type:
                self.by_entity_type[entry.entity_type] = 0
            self.by_entity_type[entry.entity_type] += 1

        # Track failures
        if not entry.success:
            self.total_failures += 1
            if action_key not in self.failures_by_type:
                self.failures_by_type[action_key] = 0
            self.failures_by_type[action_key] += 1

        # Track critical actions
        critical_actions = {
            AuditAction.DELETE,
            AuditAction.APPROVE,
            AuditAction.REJECT,
            AuditAction.CONFIG_CHANGE,
            AuditAction.PERMISSION_CHANGED,
        }

        if entry.action in critical_actions:
            self.critical_actions.append(
                {
                    "timestamp": entry.timestamp.isoformat(),
                    "user_id": entry.user_id,
                    "action": entry.action,
                    "entity_type": entry.entity_type,
                    "entity_id": entry.entity_id,
                    "reason": entry.reason,
                }
            )

    def calculate_metrics(self) -> None:
        """Calculate derived metrics."""
        # Calculate failure rate
        if self.total_entries > 0:
            self.failure_rate = (self.total_failures / self.total_entries) * 100

        # Count unique users
        self.total_users = len(self.by_user)

    def detect_anomalies(self) -> None:
        """Detect potential anomalies in audit data."""
        # High failure rate
        if self.failure_rate > 10.0:
            self.anomalies.append(
                {
                    "type": "HIGH_FAILURE_RATE",
                    "description": (
                        f"Failure rate of {self.failure_rate:.1f}% " "exceeds threshold"
                    ),
                    "severity": "HIGH",
                }
            )

        # Unusual activity patterns
        for user_id, count in self.by_user.items():
            avg_actions = self.total_entries / max(self.total_users, 1)
            if count > avg_actions * 5:  # 5x average
                self.anomalies.append(
                    {
                        "type": "UNUSUAL_USER_ACTIVITY",
                        "description": (
                            f"User {user_id} has {count} actions " "(5x average)"
                        ),
                        "severity": "MEDIUM",
                        "user_id": user_id,
                    }
                )


class AuditRetentionPolicy(BaseModel):
    """Policy for audit log retention and archival."""

    # Retention settings
    retention_days: int = Field(
        2555, description="Days to retain audit logs", gt=0  # 7 years
    )

    # Archival settings
    archive_after_days: int = Field(
        365, description="Days before moving to archive storage", gt=0  # 1 year
    )
    archive_location: str = Field("archive", description="Archive storage location")

    # Purge settings (if allowed by regulations)
    purge_allowed: bool = Field(
        False, description="Whether audit logs can ever be purged"
    )
    purge_after_days: Optional[int] = Field(
        None, description="Days after which logs can be purged", gt=0
    )

    # Compliance settings
    require_approval_for_purge: bool = Field(
        True, description="Require approval before purging"
    )
    maintain_summary_after_purge: bool = Field(
        True, description="Keep summary statistics after purging details"
    )

    @field_validator("retention_days")
    @classmethod
    def validate_retention_compliance(cls, v: int) -> int:
        """Ensure retention meets regulatory requirements."""
        if v < 2555:  # 7 years
            raise ValueError(
                "Audit logs must be retained for at least 7 years (2555 days) "
                "to meet 21 CFR Part 11 requirements"
            )
        return v

    @field_validator("purge_after_days")
    @classmethod
    def validate_purge_timing(
        cls, v: Optional[int], info: ValidationInfo
    ) -> Optional[int]:
        """Ensure purge happens after retention period."""
        if v is not None and "retention_days" in info.data:
            if v < info.data["retention_days"]:
                raise ValueError("Purge must occur after retention period expires")
        return v

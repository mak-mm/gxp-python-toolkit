"""
Data integrity verification and change tracking.

Provides comprehensive integrity checking and change detection
for GxP compliance requirements.
"""

import difflib
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..audit_trail import audit_event
from ..config import get_config
from .checksums import ChecksumProvider, calculate_checksum
from .validation import DataValidator, ValidationResult, validate_data


@dataclass
class IntegrityReport:
    """Report of integrity check results."""

    timestamp: datetime
    is_valid: bool
    items_checked: int
    items_valid: int
    items_invalid: int
    errors: List[str] = field(default_factory=list)
    invalid_items: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.items_checked == 0:
            return 100.0
        return (self.items_valid / self.items_checked) * 100

    def add_error(self, item_id: str, error: str) -> None:
        """Add error for specific item."""
        self.errors.append(f"{item_id}: {error}")
        self.invalid_items.append({"id": item_id, "error": error})
        self.items_invalid += 1
        self.is_valid = False

    def add_warning(self, warning: str) -> None:
        """Add warning message."""
        self.warnings.append(warning)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "is_valid": self.is_valid,
            "items_checked": self.items_checked,
            "items_valid": self.items_valid,
            "items_invalid": self.items_invalid,
            "success_rate": self.success_rate,
            "errors": self.errors,
            "warnings": self.warnings,
            "invalid_items": self.invalid_items,
        }


@dataclass
class ChangeRecord:
    """Record of detected changes."""

    timestamp: datetime
    entity_type: str
    entity_id: str
    field: str
    old_value: Any
    new_value: Any
    change_type: str  # added, modified, deleted
    user_id: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "field": self.field,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "change_type": self.change_type,
            "user_id": self.user_id,
            "reason": self.reason,
        }


class IntegrityChecker:
    """Main integrity checker for data validation."""

    def __init__(self) -> None:
        """Initialize integrity checker."""
        self.config = get_config()
        self.checksum_provider = ChecksumProvider()
        self.validator = DataValidator()
        self._integrity_cache: Dict[str, str] = {}

    def verify_integrity(
        self,
        data: Any,
        expected_checksum: Optional[str] = None,
        validation_rules: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify data integrity.

        Args:
            data: Data to verify
            expected_checksum: Expected checksum value
            validation_rules: Optional validation rules

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Calculate current checksum
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)

        current_checksum = self.checksum_provider.calculate(data_str)

        # Verify checksum if provided
        if expected_checksum:
            if current_checksum != expected_checksum:
                return (
                    False,
                    f"Checksum mismatch: expected {expected_checksum}, got {current_checksum}",
                )

        # Validate data if rules provided
        if validation_rules:
            result = self.validator.validate(data, validation_rules)
            if not result.is_valid:
                return False, f"Validation failed: {', '.join(result.errors)}"

        return True, None

    def verify_collection(
        self,
        items: List[Dict[str, Any]],
        checksum_field: str = "checksum",
        id_field: str = "id",
    ) -> IntegrityReport:
        """
        Verify integrity of a collection of items.

        Args:
            items: List of items to verify
            checksum_field: Field containing checksum
            id_field: Field containing item ID

        Returns:
            IntegrityReport
        """
        report = IntegrityReport(
            timestamp=datetime.utcnow(),
            is_valid=True,
            items_checked=len(items),
            items_valid=0,
            items_invalid=0,
        )

        for item in items:
            item_id = item.get(id_field, "unknown")

            # Get expected checksum
            expected_checksum = item.get(checksum_field)
            if not expected_checksum:
                report.add_warning(f"Item {item_id} has no checksum field")
                continue

            # Remove checksum field for verification
            item_copy = item.copy()
            item_copy.pop(checksum_field, None)

            # Verify integrity
            is_valid, error = self.verify_integrity(item_copy, expected_checksum)

            if is_valid:
                report.items_valid += 1
            else:
                report.add_error(item_id, error or "Unknown error")

        # Audit the integrity check
        audit_event(
            action="integrity.check",
            resource_type="collection",
            resource_id=f"items:{len(items)}",
            result="success" if report.is_valid else "failure",
            details=report.to_dict(),
        )

        return report

    def track_changes(
        self,
        old_data: Dict[str, Any],
        new_data: Dict[str, Any],
        entity_type: str,
        entity_id: str,
        user_id: Optional[str] = None,
        reason: Optional[str] = None,
        ignore_fields: Optional[Set[str]] = None,
    ) -> List[ChangeRecord]:
        """
        Track changes between old and new data.

        Args:
            old_data: Previous data state
            new_data: New data state
            entity_type: Type of entity
            entity_id: Entity identifier
            user_id: User making changes
            reason: Reason for changes
            ignore_fields: Fields to ignore

        Returns:
            List of detected changes
        """
        changes = []
        ignore_fields = ignore_fields or set()
        timestamp = datetime.utcnow()

        # Get all fields
        all_fields = set(old_data.keys()) | set(new_data.keys())

        for field_name in all_fields:
            if field_name in ignore_fields:
                continue

            old_value = old_data.get(field_name)
            new_value = new_data.get(field_name)

            # Detect change type
            if field_name not in old_data:
                # Field added
                changes.append(
                    ChangeRecord(
                        timestamp=timestamp,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        field=field_name,
                        old_value=None,
                        new_value=new_value,
                        change_type="added",
                        user_id=user_id,
                        reason=reason,
                    )
                )
            elif field_name not in new_data:
                # Field deleted
                changes.append(
                    ChangeRecord(
                        timestamp=timestamp,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        field=field_name,
                        old_value=old_value,
                        new_value=None,
                        change_type="deleted",
                        user_id=user_id,
                        reason=reason,
                    )
                )
            elif old_value != new_value:
                # Field modified
                changes.append(
                    ChangeRecord(
                        timestamp=timestamp,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        field=field_name,
                        old_value=old_value,
                        new_value=new_value,
                        change_type="modified",
                        user_id=user_id,
                        reason=reason,
                    )
                )

        # Audit changes if any
        if changes:
            audit_event(
                action="data.changed",
                resource_type=entity_type,
                resource_id=entity_id,
                user_id=user_id,
                details={
                    "changes": len(changes),
                    "fields": [c.field for c in changes],
                    "reason": reason,
                },
            )

        return changes

    def calculate_data_signature(
        self, data: Dict[str, Any], fields_to_sign: Optional[List[str]] = None
    ) -> str:
        """
        Calculate cryptographic signature for data.

        Args:
            data: Data to sign
            fields_to_sign: Specific fields to include (all if None)

        Returns:
            Signature string
        """
        if fields_to_sign:
            # Only sign specific fields
            sign_data = {k: v for k, v in data.items() if k in fields_to_sign}
        else:
            sign_data = data

        # Sort and serialize
        data_str = json.dumps(sign_data, sort_keys=True)

        # Calculate signature
        return self.checksum_provider.calculate(data_str)

    def verify_data_lineage(
        self,
        data_items: List[Dict[str, Any]],
        parent_field: str = "parent_id",
        checksum_field: str = "checksum",
    ) -> ValidationResult:
        """
        Verify data lineage and parent-child relationships.

        Args:
            data_items: List of data items with lineage
            parent_field: Field containing parent reference
            checksum_field: Field containing checksum

        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)

        # Build lookup map
        items_by_id = {item.get("id"): item for item in data_items}

        for item in data_items:
            item_id = item.get("id")
            parent_id = item.get(parent_field)

            if parent_id:
                # Verify parent exists
                if parent_id not in items_by_id:
                    result.add_error(
                        f"Item {item_id} references non-existent parent {parent_id}"
                    )
                    continue

                # Verify parent integrity
                parent = items_by_id[parent_id]
                parent_checksum = parent.get(checksum_field)
                if parent_checksum:
                    parent_copy = parent.copy()
                    parent_copy.pop(checksum_field, None)
                    is_valid, error = self.verify_integrity(
                        parent_copy, parent_checksum
                    )
                    if not is_valid:
                        result.add_error(
                            f"Parent {parent_id} has integrity issues: {error}"
                        )

        return result


# Global integrity checker instance
_integrity_checker: Optional[IntegrityChecker] = None


def get_integrity_checker() -> IntegrityChecker:
    """Get global integrity checker instance."""
    global _integrity_checker
    if _integrity_checker is None:
        _integrity_checker = IntegrityChecker()
    return _integrity_checker


def verify_data_integrity(
    data: Any,
    expected_checksum: Optional[str] = None,
    validation_rules: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Verify data integrity.

    Args:
        data: Data to verify
        expected_checksum: Expected checksum
        validation_rules: Validation rules

    Returns:
        Tuple of (is_valid, error_message)
    """
    checker = get_integrity_checker()
    return checker.verify_integrity(data, expected_checksum, validation_rules)


def track_changes(
    old_data: Dict[str, Any],
    new_data: Dict[str, Any],
    entity_type: str,
    entity_id: str,
    user_id: Optional[str] = None,
    reason: Optional[str] = None,
    ignore_fields: Optional[Set[str]] = None,
) -> List[ChangeRecord]:
    """
    Track changes between data states.

    Args:
        old_data: Previous state
        new_data: New state
        entity_type: Entity type
        entity_id: Entity ID
        user_id: User ID
        reason: Change reason
        ignore_fields: Fields to ignore

    Returns:
        List of changes
    """
    checker = get_integrity_checker()
    return checker.track_changes(
        old_data, new_data, entity_type, entity_id, user_id, reason, ignore_fields
    )

"""
Service layer for soft delete operations.

Provides high-level business logic for deletion, restoration, and retention
management in compliance with GxP requirements.
"""

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Type

from sqlalchemy import and_
from sqlalchemy.orm import Session

from .exceptions import RestoreNotAllowedException, SoftDeleteError
from .mixins import CascadeSoftDeleteMixin, SoftDeleteMixin
from .models import (
    DeletionReport,
    DeletionRequest,
    RestoreRequest,
    RetentionCategory,
    RetentionPolicy,
)


class SoftDeleteService:
    """
    Service for managing soft deletes with full GxP compliance.

    Handles deletion approval workflows, restoration, retention policies,
    and compliance reporting.
    """

    def __init__(
        self,
        session: Session,
        audit_logger: Optional[Any] = None,
        permission_checker: Optional[Callable[..., bool]] = None,
        signature_service: Optional[Any] = None,
    ):
        """
        Initialize the soft delete service.

        Args:
            session: SQLAlchemy database session
            audit_logger: Optional audit logging service
            permission_checker: Optional function to check permissions
            signature_service: Optional electronic signature service
        """
        self.session = session
        self.audit_logger = audit_logger
        self.permission_checker = permission_checker
        self.signature_service = signature_service

        # Default retention policies by entity type
        self.retention_policies: Dict[str, RetentionPolicy] = {}
        self._initialize_default_policies()

    def _initialize_default_policies(self) -> None:
        """Initialize default retention policies for common entity types."""
        # Critical GxP data - never delete
        for entity_type in [
            "Batch",
            "AuditLog",
            "ElectronicSignature",
            "QualityRecord",
        ]:
            self.retention_policies[entity_type] = RetentionPolicy(
                entity_type=entity_type,
                category=RetentionCategory.CRITICAL_GXP,
                minimum_retention_days=999999,
                requires_approval_to_purge=True,
                archive_after_days=None,
                purge_allowed=False,
            )

        # Standard GxP data - 7 years minimum
        for entity_type in ["TestResult", "Deviation", "ChangeControl", "Training"]:
            self.retention_policies[entity_type] = RetentionPolicy(
                entity_type=entity_type,
                category=RetentionCategory.STANDARD_GXP,
                minimum_retention_days=2555,  # 7 years
                requires_approval_to_purge=True,
                archive_after_days=365,
                purge_allowed=True,
            )

        # Supporting data - 3 years minimum
        for entity_type in ["Report", "Document", "Specification"]:
            self.retention_policies[entity_type] = RetentionPolicy(
                entity_type=entity_type,
                category=RetentionCategory.SUPPORTING,
                minimum_retention_days=1095,  # 3 years
                requires_approval_to_purge=True,
                archive_after_days=180,
                purge_allowed=True,
            )

        # Temporary data - 90 days minimum
        for entity_type in ["TempData", "Draft", "WorkInProgress"]:
            self.retention_policies[entity_type] = RetentionPolicy(
                entity_type=entity_type,
                category=RetentionCategory.TEMPORARY,
                minimum_retention_days=90,
                requires_approval_to_purge=False,
                archive_after_days=None,
                purge_allowed=True,
            )

    def register_retention_policy(
        self, entity_type: str, policy: RetentionPolicy
    ) -> None:
        """
        Register a retention policy for an entity type.

        Args:
            entity_type: Type of entity
            policy: Retention policy to apply
        """
        self.retention_policies[entity_type] = policy

    async def delete_entity(
        self,
        entity: SoftDeleteMixin,
        request: DeletionRequest,
        require_signature: bool = False,
    ) -> Dict[str, Any]:
        """
        Soft delete an entity with full audit trail.

        Args:
            entity: Entity to delete
            request: Deletion request with reason and user info
            require_signature: Whether electronic signature is required

        Returns:
            Dictionary with deletion details

        Raises:
            PermissionError: User lacks delete permission
            SoftDeleteError: Various validation errors
        """
        entity_type = entity.__class__.__name__
        entity_id = str(getattr(entity, "id", "unknown"))

        # Check permissions
        if self.permission_checker:
            if not self.permission_checker(
                request.requester_id, "delete", entity_type, entity
            ):
                raise PermissionError(
                    f"User {request.requester_id} does not have permission "
                    f"to delete {entity_type}"
                )

        # Validate entity can be deleted
        if not self._can_delete(entity):
            raise SoftDeleteError(self._get_delete_error(entity), entity_id=entity_id)

        # Handle electronic signature if required
        signature_id = None
        if require_signature and self.signature_service:
            if not request.password:
                raise ValueError("Password required for electronic signature")

            signature_id = await self.signature_service.create_signature(
                user_id=request.requester_id,
                password=request.password,
                meaning=f"Delete {entity_type} {entity_id}",
                reason=request.reason,
            )

        # Perform soft delete
        deleted_entities = []

        if isinstance(entity, CascadeSoftDeleteMixin):
            # Handle cascade deletes
            deleted_entities = entity.soft_delete(
                user_id=request.requester_id,
                reason=request.reason,
                session=self.session,
            )
        else:
            entity.soft_delete(user_id=request.requester_id, reason=request.reason)
            deleted_entities = [entity]

        # Log the deletion
        if self.audit_logger:
            await self.audit_logger.log_activity(
                user_id=request.requester_id,
                activity_type="DELETE",
                entity_type=entity_type,
                entity_id=entity_id,
                details={
                    "reason": request.reason,
                    "reference_id": request.reference_id,
                    "signature_id": signature_id,
                    "cascade_count": len(deleted_entities) - 1,
                    "entity_summary": self._get_entity_summary(entity),
                },
            )

        # Commit the transaction
        self.session.commit()

        return {
            "success": True,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "deleted_at": entity.deleted_at.isoformat() if entity.deleted_at else None,
            "deleted_by": entity.deleted_by,
            "total_deleted": len(deleted_entities),
            "cascade_deleted": [
                {"type": e.__class__.__name__, "id": str(getattr(e, "id", "unknown"))}
                for e in deleted_entities[1:]  # Exclude primary entity
            ],
            "can_restore": True,
        }

    async def restore_entity(
        self,
        entity_type: str,
        entity_id: str,
        request: RestoreRequest,
        require_approval: bool = True,
    ) -> Any:
        """
        Restore a soft-deleted entity.

        Args:
            entity_type: Type of entity to restore
            entity_id: ID of entity to restore
            request: Restore request with reason and user info
            require_approval: Whether approval is required

        Returns:
            Restored entity

        Raises:
            PermissionError: User lacks restore permission
            RestoreNotAllowedException: Restoration not allowed
        """
        # Get the entity class
        entity_class = self._get_entity_class(entity_type)

        # Find the deleted entity
        entity = (
            self.session.query(entity_class)
            .filter(
                and_(entity_class.id == entity_id, entity_class.is_deleted.is_(True))
            )
            .first()
        )

        if not entity:
            raise SoftDeleteError(
                f"Deleted {entity_type} with ID {entity_id} not found"
            )

        # Check permissions
        if self.permission_checker:
            if not self.permission_checker(
                request.requester_id, "restore", entity_type, entity
            ):
                raise PermissionError(
                    f"User {request.requester_id} does not have permission "
                    f"to restore {entity_type}"
                )

        # Check if restoration is allowed
        if not self._can_restore(entity):
            raise RestoreNotAllowedException(entity_id, self._get_restore_error(entity))

        # TODO: Implement approval workflow if require_approval is True

        # Capture deletion timestamp before restoration clears it
        deleted_at = entity.deleted_at

        # Perform restoration
        entity.restore(user_id=request.requester_id, reason=request.reason)

        # Log the restoration
        if self.audit_logger:
            # Calculate deletion duration if timestamp was available
            deletion_duration = None
            if deleted_at:
                deletion_duration = datetime.utcnow() - deleted_at

            details = {
                "reference_id": request.reference_id,
                "original_deletion_reason": getattr(entity, "deletion_reason", None),
                "original_deleted_by": getattr(entity, "deleted_by", None),
            }

            # Add deletion duration if available
            if deletion_duration:
                details["deletion_duration_hours"] = (
                    deletion_duration.total_seconds() / 3600
                )

            await self.audit_logger.log_activity(
                action="RESTORE",
                entity_type=entity_type,
                entity_id=entity_id,
                reason=request.reason,
                details=details,
                user_override={"id": request.requester_id},
            )

        self.session.commit()

        return entity

    async def get_deleted_entities(
        self,
        entity_type: str,
        user_id: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Any]:
        """
        Get list of deleted entities with filtering.

        Args:
            entity_type: Type of entities to retrieve
            user_id: User requesting the data
            filters: Optional filters to apply
            limit: Maximum records to return
            offset: Offset for pagination

        Returns:
            List of deleted entities

        Raises:
            PermissionError: User lacks permission to view deleted data
        """
        # Check permission to view deleted data
        if self.permission_checker:
            if not self.permission_checker(user_id, "view_deleted", entity_type, None):
                raise PermissionError(
                    f"User {user_id} does not have permission "
                    f"to view deleted {entity_type} records"
                )

        # Get entity class
        entity_class = self._get_entity_class(entity_type)

        # Build query
        query = self.session.query(entity_class).filter(
            entity_class.is_deleted.is_(True)
        )

        # Apply filters
        if filters:
            if "deleted_after" in filters:
                query = query.filter(
                    entity_class.deleted_at >= filters["deleted_after"]
                )
            if "deleted_before" in filters:
                query = query.filter(
                    entity_class.deleted_at <= filters["deleted_before"]
                )
            if "deleted_by" in filters:
                query = query.filter(entity_class.deleted_by == filters["deleted_by"])
            if "search" in filters and filters["search"]:
                # Search in deletion reason
                query = query.filter(
                    entity_class.deletion_reason.ilike(f"%{filters['search']}%")
                )

        # Order by deletion date (newest first)
        query = query.order_by(entity_class.deleted_at.desc())

        # Apply pagination
        query = query.limit(limit).offset(offset)

        return query.all()

    async def generate_deletion_report(
        self,
        start_date: datetime,
        end_date: datetime,
        entity_types: Optional[List[str]] = None,
    ) -> DeletionReport:
        """
        Generate a compliance report for deletions in a period.

        Args:
            start_date: Report period start
            end_date: Report period end
            entity_types: Optional list of entity types to include

        Returns:
            Deletion report with statistics
        """
        report = DeletionReport(
            start_date=start_date,
            end_date=end_date,
            total_deletions=0,
            pending_approvals=0,
            restorations=0,
        )

        # Get all entity classes
        if entity_types:
            classes = [self._get_entity_class(et) for et in entity_types]
        else:
            classes = self._get_all_soft_delete_classes()

        # Collect statistics for each entity type
        for entity_class in classes:
            entity_type = entity_class.__name__

            # Count deletions in period
            deletions = (
                self.session.query(entity_class)
                .filter(
                    and_(
                        entity_class.is_deleted.is_(True),
                        entity_class.deleted_at >= start_date,
                        entity_class.deleted_at <= end_date,
                    )
                )
                .all()
            )

            # Process each deletion
            for deletion in deletions:
                reason_category = self._categorize_deletion_reason(
                    deletion.deletion_reason
                )
                report.add_deletion(
                    entity_type=entity_type,
                    user_id=deletion.deleted_by,
                    reason_category=reason_category,
                )

            # Count restorations in period
            restorations = (
                self.session.query(entity_class)
                .filter(
                    and_(
                        entity_class.is_restored.is_(True),
                        entity_class.restored_at >= start_date,
                        entity_class.restored_at <= end_date,
                    )
                )
                .count()
            )

            report.restorations += restorations

        return report

    async def evaluate_retention_compliance(self) -> Dict[str, Any]:
        """
        Evaluate all deleted records against retention policies.

        Returns:
            Compliance evaluation report
        """
        evaluation: Dict[str, Any] = {
            "evaluated": 0,
            "compliant": 0,
            "can_archive": 0,
            "can_purge": 0,
            "policy_violations": [],
            "by_entity_type": {},
        }

        # Check each entity type with a retention policy
        for entity_type, policy in self.retention_policies.items():
            try:
                entity_class = self._get_entity_class(entity_type)
            except ValueError:
                continue

            # Get all deleted records
            deleted_records = (
                self.session.query(entity_class)
                .filter(entity_class.is_deleted.is_(True))
                .all()
            )

            type_stats = {
                "total": len(deleted_records),
                "can_archive": 0,
                "can_purge": 0,
                "violations": 0,
            }

            for record in deleted_records:
                evaluation["evaluated"] += 1

                # Check if record meets retention requirements
                if policy.should_archive(record.deleted_at):
                    type_stats["can_archive"] += 1
                    evaluation["can_archive"] += 1

                if policy.can_purge(record.deleted_at):
                    type_stats["can_purge"] += 1
                    evaluation["can_purge"] += 1

                # Check for policy violations
                days_retained = (datetime.utcnow() - record.deleted_at).days
                if days_retained < policy.minimum_retention_days:
                    # Record hasn't met minimum retention yet
                    evaluation["compliant"] += 1
                else:
                    # Record has met minimum retention
                    if not policy.purge_allowed and hasattr(record, "is_purged"):
                        if getattr(record, "is_purged", False):
                            # Policy violation: purged when not allowed
                            type_stats["violations"] += 1
                            evaluation["policy_violations"].append(
                                {
                                    "entity_type": entity_type,
                                    "entity_id": str(record.id),
                                    "violation": "Purged when policy disallows purging",
                                }
                            )

            evaluation["by_entity_type"][entity_type] = type_stats

        return evaluation

    def _can_delete(self, entity: Any) -> bool:
        """Check if entity can be deleted based on business rules."""
        # Don't allow deletion of certain statuses
        if hasattr(entity, "status"):
            protected_statuses = {"approved", "released", "signed", "locked"}
            if str(entity.status).lower() in protected_statuses:
                return False

        # Don't allow deletion of locked records
        if hasattr(entity, "is_locked") and entity.is_locked:
            return False

        # Don't allow deletion of records with active references
        if hasattr(entity, "has_active_references"):
            if entity.has_active_references():
                return False

        return True

    def _get_delete_error(self, entity: Any) -> str:
        """Get specific error message for why deletion is not allowed."""
        if hasattr(entity, "status"):
            protected_statuses = {"approved", "released", "signed", "locked"}
            if str(entity.status).lower() in protected_statuses:
                return (
                    f"Cannot delete {entity.status} records. "
                    f"Status must be changed first."
                )

        if hasattr(entity, "is_locked") and entity.is_locked:
            return "Cannot delete locked records. Unlock the record first."

        if hasattr(entity, "has_active_references"):
            if entity.has_active_references():
                return (
                    "Cannot delete records with active references. "
                    "Remove references first."
                )

        return "Deletion not allowed due to business rules"

    def _can_restore(self, entity: Any) -> bool:
        """Check if entity can be restored."""
        # Check if parent still exists (for cascade deleted items)
        if (
            hasattr(entity, "cascade_deleted_from_id")
            and entity.cascade_deleted_from_id
        ):
            parent_type = entity.cascade_deleted_from_type
            parent_id = entity.cascade_deleted_from_id

            # Try to find parent
            try:
                parent_class = self._get_entity_class(parent_type)
                parent = (
                    self.session.query(parent_class)
                    .filter(parent_class.id == parent_id)
                    .first()
                )

                if not parent or parent.is_deleted:
                    return False
            except Exception:
                return False

        # Check if unique constraints would be violated
        # This is entity-specific and should be overridden

        return True

    def _get_restore_error(self, entity: Any) -> str:
        """Get specific error message for why restoration is not allowed."""
        if (
            hasattr(entity, "cascade_deleted_from_id")
            and entity.cascade_deleted_from_id
        ):
            return (
                f"Cannot restore cascade-deleted record. "
                f"Parent {entity.cascade_deleted_from_type} "
                f"{entity.cascade_deleted_from_id} must be restored first."
            )

        return "Restoration not allowed due to business rules"

    def _get_entity_summary(self, entity: Any) -> Dict[str, Any]:
        """Get summary of entity for audit trail."""
        summary = {
            "id": str(getattr(entity, "id", "unknown")),
            "type": entity.__class__.__name__,
        }

        # Add key identifying fields
        key_fields = ["name", "code", "title", "number", "reference"]
        for field in key_fields:
            if hasattr(entity, field):
                value = getattr(entity, field)
                if value:
                    summary[field] = str(value)

        # Add status if present
        if hasattr(entity, "status"):
            summary["status"] = str(entity.status)

        return summary

    def _categorize_deletion_reason(self, reason: str) -> str:
        """Categorize deletion reason for reporting."""
        reason_lower = reason.lower()

        if any(word in reason_lower for word in ["contamination", "quality", "failed"]):
            return "Quality Issue"
        elif any(
            word in reason_lower for word in ["obsolete", "superseded", "replaced"]
        ):
            return "Obsolescence"
        elif any(word in reason_lower for word in ["error", "mistake", "incorrect"]):
            return "Data Error"
        elif any(word in reason_lower for word in ["duplicate", "redundant"]):
            return "Duplicate"
        elif any(word in reason_lower for word in ["request", "change", "cr-"]):
            return "Change Request"
        else:
            return "Other"

    def _get_entity_class(self, entity_type: str) -> Type[Any]:
        """Get entity class by name."""
        # This is a simplified implementation
        # In production, maintain a registry of entity classes

        # For now, just raise an error - implement proper registry
        # TODO: Implement entity class registry

        raise ValueError(f"Entity type {entity_type} not found")

    def _get_all_soft_delete_classes(self) -> List[Type[Any]]:
        """Get all classes that use SoftDeleteMixin."""
        # This is a simplified implementation
        # In production, maintain a registry
        classes: List[Type[Any]] = []

        # Would need proper implementation to discover all models
        # For now, return empty list
        return classes

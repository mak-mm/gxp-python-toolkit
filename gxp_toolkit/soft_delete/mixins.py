"""
SQLAlchemy mixins for soft delete functionality.

These mixins provide GxP-compliant soft delete capabilities for SQLAlchemy models.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Type

from sqlalchemy import Boolean, DateTime, String, event
from sqlalchemy.orm import Mapped, Query, Session, declared_attr, mapped_column

from .exceptions import AlreadyDeletedException, NotDeletedException


class SoftDeleteMixin:
    """
    Mixin to add soft delete functionality to SQLAlchemy models.

    Provides:
    - Soft delete fields (is_deleted, deleted_at, deleted_by, deletion_reason)
    - Restore tracking fields
    - Methods for soft delete and restore operations
    - Automatic query filtering

    Usage:
        class MyModel(Base, SoftDeleteMixin):
            __tablename__ = 'my_table'
            id = Column(Integer, primary_key=True)
            name = Column(String)
    """

    # Soft delete fields
    is_deleted: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    deletion_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Restoration tracking fields
    is_restored: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    restored_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    restored_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    restoration_reason: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True
    )

    # Deletion cascade tracking
    cascade_deleted_from_type: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    cascade_deleted_from_id: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )

    @declared_attr
    def __table_args__(cls: Any) -> Any:
        """Add table-level constraints."""
        # Check for existing table args from the class definition (not the mixin)
        existing = ()
        for base in cls.__bases__:
            if hasattr(base, "__table_args__") and base is not SoftDeleteMixin:
                existing = getattr(base, "__table_args__")
                break

        if isinstance(existing, dict):
            existing = (existing,)  # type: ignore[unreachable]  # Convert dict to tuple
        elif isinstance(existing, tuple):
            if existing and isinstance(existing[-1], dict):  # type: ignore[unreachable]
                # Table args already has constraints and options
                return existing  # type: ignore[unreachable]

        # Add check constraint for deletion consistency
        from sqlalchemy import CheckConstraint

        # Get table name from the class
        table_name = getattr(cls, "__tablename__", cls.__name__.lower())

        constraint = CheckConstraint(
            "(is_deleted = false AND deleted_at IS NULL AND deleted_by IS NULL "
            "AND deletion_reason IS NULL) OR "
            "(is_deleted = true AND deleted_at IS NOT NULL AND deleted_by IS NOT NULL "
            "AND deletion_reason IS NOT NULL)",
            name=f"ck_{table_name}_deletion_consistency",
        )

        if existing:
            return existing + (constraint,)  # type: ignore[unreachable]
        return (constraint,)

    def soft_delete(
        self, user_id: str, reason: str, cascade_from: Optional[Tuple[str, str]] = None
    ) -> None:
        """
        Soft delete this record.

        Args:
            user_id: ID of user performing deletion
            reason: Justification for deletion (min 10 characters)
            cascade_from: Optional tuple of (parent_type, parent_id) if cascade deleted

        Raises:
            AlreadyDeletedException: If record is already deleted
            ValueError: If reason is too short or user_id is empty
        """
        if self.is_deleted:
            raise AlreadyDeletedException(str(getattr(self, "id", "unknown")))

        if not user_id or not user_id.strip():
            raise ValueError("User ID is required for deletion")

        if not reason or len(reason.strip()) < 10:
            raise ValueError("Deletion reason must be at least 10 characters")

        self.is_deleted = True
        self.deleted_at = datetime.utcnow()
        self.deleted_by = user_id.strip()
        self.deletion_reason = reason.strip()

        if cascade_from:
            self.cascade_deleted_from_type = cascade_from[0]
            self.cascade_deleted_from_id = cascade_from[1]

    def restore(self, user_id: str, reason: str) -> None:
        """
        Restore a soft-deleted record.

        Args:
            user_id: ID of user performing restoration
            reason: Justification for restoration (min 10 characters)

        Raises:
            NotDeletedException: If record is not deleted
            ValueError: If reason is too short or user_id is empty
        """
        if not self.is_deleted:
            raise NotDeletedException(str(getattr(self, "id", "unknown")))

        if not user_id or not user_id.strip():
            raise ValueError("User ID is required for restoration")

        if not reason or len(reason.strip()) < 10:
            raise ValueError("Restoration reason must be at least 10 characters")

        # Clear deletion fields
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.deletion_reason = None
        self.cascade_deleted_from_type = None
        self.cascade_deleted_from_id = None

        # Set restoration fields
        self.is_restored = True
        self.restored_at = datetime.utcnow()
        self.restored_by = user_id.strip()
        self.restoration_reason = reason.strip()

    @classmethod
    def query_active(cls, session: Session) -> Query[Any]:
        """
        Return query for active (non-deleted) records only.

        Args:
            session: SQLAlchemy session

        Returns:
            Query filtered to exclude deleted records
        """
        return session.query(cls).filter(cls.is_deleted.is_(False))

    @classmethod
    def query_deleted(cls, session: Session) -> Query[Any]:
        """
        Return query for deleted records only.

        Args:
            session: SQLAlchemy session

        Returns:
            Query filtered to include only deleted records
        """
        return session.query(cls).filter(cls.is_deleted.is_(True))

    @classmethod
    def query_all(cls, session: Session) -> Query[Any]:
        """
        Return query for all records including deleted.

        Args:
            session: SQLAlchemy session

        Returns:
            Query with no soft delete filter
        """
        return session.query(cls)

    def to_dict(self, include_deleted_fields: bool = True) -> Dict[str, Any]:
        """
        Convert model to dictionary representation.

        Args:
            include_deleted_fields: Whether to include soft delete fields

        Returns:
            Dictionary representation of the model
        """
        result: Dict[str, Any] = {}

        # Access __table__ attribute
        table = getattr(self, "__table__", None)
        if table is None:
            return result

        for column in table.columns:
            if hasattr(self, column.name):
                value = getattr(self, column.name)
                if isinstance(value, datetime):
                    value = value.isoformat()
                result[column.name] = value

        if not include_deleted_fields:
            # Remove soft delete fields if not wanted
            for field in [
                "is_deleted",
                "deleted_at",
                "deleted_by",
                "deletion_reason",
                "is_restored",
                "restored_at",
                "restored_by",
                "restoration_reason",
                "cascade_deleted_from_type",
                "cascade_deleted_from_id",
            ]:
                result.pop(field, None)

        return result


class CascadeSoftDeleteMixin(SoftDeleteMixin):
    """
    Extended mixin that supports cascading soft deletes.

    When a parent record is soft deleted, all related child records
    are automatically soft deleted with appropriate reason tracking.
    """

    # Allow legacy annotations without Mapped[] wrapper
    __allow_unmapped__ = True

    # Override this in child classes to define cascade relationships
    __soft_delete_cascade__: List[str] = []  # List of relationship attribute names

    def soft_delete(  # type: ignore[override]
        self,
        user_id: str,
        reason: str,
        cascade_from: Optional[Tuple[str, str]] = None,
        session: Optional[Session] = None,
    ) -> List[Any]:
        """
        Soft delete this record and cascade to related records.

        Args:
            user_id: ID of user performing deletion
            reason: Justification for deletion
            cascade_from: Optional tuple of (parent_type, parent_id)
            session: Optional session for cascade operations

        Returns:
            List of all deleted entities (including cascaded)
        """
        # First, soft delete this record
        super().soft_delete(user_id, reason, cascade_from)

        deleted_entities = [self]

        # Then cascade to related records if session provided
        if session and hasattr(self, "__soft_delete_cascade__"):
            entity_type = self.__class__.__name__
            entity_id = str(getattr(self, "id", "unknown"))

            for relationship_name in self.__soft_delete_cascade__:
                if hasattr(self, relationship_name):
                    related = getattr(self, relationship_name)

                    if related is None:
                        continue

                    # Handle both single related object and collections
                    if isinstance(related, list):
                        items = related
                    else:
                        items = [related]

                    for item in items:
                        if hasattr(item, "soft_delete") and not item.is_deleted:
                            cascade_reason = (
                                f"Cascade delete from {entity_type} {entity_id}: "  # nosec B608
                                f"{reason}"
                            )

                            # Recursively delete if it's also a cascade mixin
                            if isinstance(item, CascadeSoftDeleteMixin):
                                cascaded = item.soft_delete(
                                    user_id=user_id,
                                    reason=cascade_reason,
                                    cascade_from=(entity_type, entity_id),
                                    session=session,
                                )
                                deleted_entities.extend(cascaded)
                            else:
                                item.soft_delete(
                                    user_id=user_id,
                                    reason=cascade_reason,
                                    cascade_from=(entity_type, entity_id),
                                )
                                deleted_entities.append(item)

        return deleted_entities


# Global query modification helper
def _add_soft_delete_filter(query: Query[Any]) -> Query[Any]:
    """Add soft delete filter to query if applicable."""
    # Get the primary entity being queried
    if hasattr(query, "column_descriptions") and query.column_descriptions:
        entity = query.column_descriptions[0].get("entity")
        if entity and hasattr(entity, "is_deleted"):
            # Check if filter already applied to avoid duplicates
            if not any(
                hasattr(clause, "left")
                and hasattr(clause.left, "key")
                and clause.left.key == "is_deleted"
                for clause in query.whereclause.clauses
                if hasattr(query, "whereclause")
                and hasattr(query.whereclause, "clauses")
            ):
                query = query.filter(entity.is_deleted.is_(False))

    return query


def prevent_hard_delete(mapper: Any, connection: Any, target: Any) -> None:
    """
    Prevent hard deletes on models with SoftDeleteMixin.

    This function should be connected to SQLAlchemy's before_delete event.
    """
    if isinstance(target, SoftDeleteMixin):
        raise RuntimeError(
            f"Hard delete attempted on {target.__class__.__name__}. "
            "Use soft_delete() method instead."
        )


def register_soft_delete_listeners(base_class: Type[Any]) -> None:
    """
    Register SQLAlchemy event listeners for soft delete functionality.

    Args:
        base_class: The declarative base class
    """
    # Register hard delete prevention for all models with SoftDeleteMixin
    for mapper in base_class.registry.mappers:
        if issubclass(mapper.class_, SoftDeleteMixin):
            event.listen(mapper.class_, "before_delete", prevent_hard_delete)

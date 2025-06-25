"""
Comprehensive tests for soft delete functionality.

Tests cover mixins, services, models, and integration scenarios
to ensure GxP compliance.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from gxp_toolkit.soft_delete import (
    AlreadyDeletedException,
    CascadeSoftDeleteMixin,
    DeletionRequest,
    NotDeletedException,
    RestoreRequest,
    RetentionCategory,
    RetentionPolicy,
    SoftDeleteMixin,
    SoftDeleteService,
)

# Create test database models
Base = declarative_base()


class SampleEntity(Base, SoftDeleteMixin):
    """Sample entity with soft delete capability."""

    __tablename__ = "test_entities"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    status = Column(String(50))
    is_locked = Column(Integer, default=0)  # SQLite doesn't have Boolean


class ParentEntity(Base, CascadeSoftDeleteMixin):
    """Parent entity with cascade delete capability."""

    __tablename__ = "parent_entities"
    __allow_unmapped__ = True
    __soft_delete_cascade__ = ["children"]

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    children = relationship("ChildEntity", back_populates="parent")


class ChildEntity(Base, SoftDeleteMixin):
    """Child entity that can be cascade deleted."""

    __tablename__ = "child_entities"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    parent_id = Column(Integer, ForeignKey("parent_entities.id"))
    parent = relationship("ParentEntity", back_populates="children")


@pytest.fixture
def db_session():
    """Create an in-memory SQLite database session for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    yield session

    session.close()


@pytest.fixture
def test_entity(db_session):
    """Create a test entity."""
    entity = SampleEntity(name="Test Record", status="draft")
    db_session.add(entity)
    db_session.commit()
    return entity


@pytest.fixture
def soft_delete_service(db_session):
    """Create a soft delete service instance."""
    mock_audit_logger = AsyncMock()
    mock_permission_checker = AsyncMock(return_value=True)

    service = SoftDeleteService(
        session=db_session,
        audit_logger=mock_audit_logger,
        permission_checker=mock_permission_checker,
    )

    return service


class TestSoftDeleteMixin:
    """Test the SoftDeleteMixin functionality."""

    def test_soft_delete_basic(self, db_session, test_entity):
        """Test basic soft delete functionality."""
        # Perform soft delete
        test_entity.soft_delete(
            user_id="test_user", reason="Test deletion for unit testing purposes"
        )

        # Verify fields are set correctly
        assert test_entity.is_deleted is True
        assert test_entity.deleted_at is not None
        assert test_entity.deleted_by == "test_user"
        assert test_entity.deletion_reason == "Test deletion for unit testing purposes"
        assert test_entity.deleted_at <= datetime.utcnow()

    def test_soft_delete_already_deleted(self, db_session, test_entity):
        """Test that deleting an already deleted entity raises exception."""
        # First deletion
        test_entity.soft_delete("user1", "First deletion reason")

        # Attempt second deletion
        with pytest.raises(AlreadyDeletedException) as exc:
            test_entity.soft_delete("user2", "Second deletion reason")

        assert str(test_entity.id) in str(exc.value)

    def test_soft_delete_validation(self, db_session, test_entity):
        """Test soft delete validation rules."""
        # Test empty user ID
        with pytest.raises(ValueError) as exc:
            test_entity.soft_delete("", "Valid reason")
        assert "User ID is required" in str(exc.value)

        # Test short reason
        with pytest.raises(ValueError) as exc:
            test_entity.soft_delete("user1", "Short")
        assert "at least 10 characters" in str(exc.value)

    def test_restore_basic(self, db_session, test_entity):
        """Test basic restore functionality."""
        # Delete first
        test_entity.soft_delete("user1", "Deletion reason for testing")
        db_session.commit()

        # Restore
        test_entity.restore("user2", "Restoration reason for testing")

        # Verify deletion fields cleared
        assert test_entity.is_deleted is False
        assert test_entity.deleted_at is None
        assert test_entity.deleted_by is None
        assert test_entity.deletion_reason is None

        # Verify restoration fields set
        assert test_entity.is_restored is True
        assert test_entity.restored_at is not None
        assert test_entity.restored_by == "user2"
        assert test_entity.restoration_reason == "Restoration reason for testing"

    def test_restore_not_deleted(self, db_session, test_entity):
        """Test that restoring a non-deleted entity raises exception."""
        with pytest.raises(NotDeletedException) as exc:
            test_entity.restore("user1", "Invalid restoration")

        assert str(test_entity.id) in str(exc.value)

    def test_query_methods(self, db_session):
        """Test query helper methods."""
        # Create mix of active and deleted entities
        active1 = SampleEntity(name="Active 1", status="active")
        active2 = SampleEntity(name="Active 2", status="active")
        deleted1 = SampleEntity(name="Deleted 1", status="draft")
        deleted2 = SampleEntity(name="Deleted 2", status="draft")

        db_session.add_all([active1, active2, deleted1, deleted2])
        db_session.commit()

        # Soft delete some entities
        deleted1.soft_delete("user1", "Test deletion one")
        deleted2.soft_delete("user1", "Test deletion two")
        db_session.commit()

        # Test query_active
        active_results = SampleEntity.query_active(db_session).all()
        assert len(active_results) == 2
        assert all(not e.is_deleted for e in active_results)

        # Test query_deleted
        deleted_results = SampleEntity.query_deleted(db_session).all()
        assert len(deleted_results) == 2
        assert all(e.is_deleted for e in deleted_results)

        # Test query_all
        all_results = SampleEntity.query_all(db_session).all()
        assert len(all_results) == 4


class TestCascadeSoftDelete:
    """Test cascade soft delete functionality."""

    def test_cascade_delete(self, db_session):
        """Test that cascade delete works correctly."""
        # Create parent with children
        parent = ParentEntity(name="Parent")
        child1 = ChildEntity(name="Child 1", parent=parent)
        child2 = ChildEntity(name="Child 2", parent=parent)

        db_session.add(parent)
        db_session.commit()

        # Perform cascade delete
        deleted_entities = parent.soft_delete(
            user_id="user1", reason="Test cascade deletion", session=db_session
        )

        # Verify all entities marked as deleted
        assert parent.is_deleted is True
        assert child1.is_deleted is True
        assert child2.is_deleted is True

        # Verify cascade tracking
        assert child1.cascade_deleted_from_type == "ParentEntity"
        assert child1.cascade_deleted_from_id == str(parent.id)
        assert "Cascade delete from ParentEntity" in child1.deletion_reason

        # Verify return value
        assert len(deleted_entities) == 3
        assert parent in deleted_entities
        assert child1 in deleted_entities
        assert child2 in deleted_entities


class TestDeletionRequest:
    """Test DeletionRequest model validation."""

    def test_valid_request(self):
        """Test creating a valid deletion request."""
        request = DeletionRequest(
            entity_type="SampleEntity",
            entity_id="123",
            requester_id="user1",
            reason="Contamination detected during quality control testing",
            reference_id="QC-2024-001",
            urgency="high",
        )

        assert request.entity_type == "SampleEntity"
        assert request.urgency == "high"

    def test_generic_reason_rejection(self):
        """Test that generic reasons are rejected."""
        with pytest.raises(ValueError) as exc:
            DeletionRequest(
                entity_type="SampleEntity",
                entity_id="123",
                requester_id="user1",
                reason="not needed",
            )

        assert "specific reason" in str(exc.value)

    def test_short_reason_rejection(self):
        """Test that short reasons are rejected."""
        with pytest.raises(ValueError) as exc:
            DeletionRequest(
                entity_type="SampleEntity",
                entity_id="123",
                requester_id="user1",
                reason="Too short",
            )

        # Could be either min_length or word count validation
        error_message = str(exc.value)
        assert (
            "at least 3 words" in error_message
            or "at least 10 characters" in error_message
        )


class TestRetentionPolicy:
    """Test RetentionPolicy model."""

    def test_critical_gxp_policy(self):
        """Test critical GxP retention policy."""
        policy = RetentionPolicy(
            entity_type="Batch",
            category=RetentionCategory.CRITICAL_GXP,
            minimum_retention_days=999999,
            requires_approval_to_purge=True,
            purge_allowed=False,
        )

        # Should never allow purging
        deleted_date = datetime.utcnow() - timedelta(days=10000)
        assert policy.can_purge(deleted_date) is False

    def test_standard_gxp_policy(self):
        """Test standard GxP retention policy."""
        policy = RetentionPolicy(
            entity_type="TestResult",
            category=RetentionCategory.STANDARD_GXP,
            minimum_retention_days=2555,  # 7 years
            requires_approval_to_purge=True,
            archive_after_days=365,
        )

        # Test archiving
        recent_date = datetime.utcnow() - timedelta(days=180)
        old_date = datetime.utcnow() - timedelta(days=400)

        assert policy.should_archive(recent_date) is False
        assert policy.should_archive(old_date) is True

        # Test purging
        very_old_date = datetime.utcnow() - timedelta(days=3000)
        assert policy.can_purge(very_old_date) is True

    def test_retention_validation(self):
        """Test retention period validation."""
        # Standard GxP must be at least 7 years
        with pytest.raises(ValueError) as exc:
            RetentionPolicy(
                entity_type="TestResult",
                category=RetentionCategory.STANDARD_GXP,
                minimum_retention_days=1000,  # Less than 7 years
            )

        assert "7 years" in str(exc.value)


class TestSoftDeleteService:
    """Test SoftDeleteService functionality."""

    @pytest.mark.asyncio
    async def test_delete_entity_success(self, soft_delete_service, test_entity):
        """Test successful entity deletion through service."""
        request = DeletionRequest(
            entity_type="SampleEntity",
            entity_id=str(test_entity.id),
            requester_id="user1",
            reason="Quality control failure - contamination detected",
            reference_id="QC-2024-001",
        )

        result = await soft_delete_service.delete_entity(
            entity=test_entity, request=request, require_signature=False
        )

        assert result["success"] is True
        assert result["entity_id"] == str(test_entity.id)
        assert test_entity.is_deleted is True
        assert test_entity.deleted_by == "user1"

        # Verify audit log was called
        soft_delete_service.audit_logger.log_activity.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_entity_permission_denied(self, db_session, test_entity):
        """Test deletion with permission denied."""
        # Create service with permission checker that denies
        service = SoftDeleteService(
            session=db_session, permission_checker=Mock(return_value=False)
        )

        request = DeletionRequest(
            entity_type="SampleEntity",
            entity_id=str(test_entity.id),
            requester_id="user1",
            reason="Attempting deletion without permission",
        )

        with pytest.raises(PermissionError):
            await service.delete_entity(test_entity, request)

    @pytest.mark.asyncio
    async def test_delete_protected_entity(self, soft_delete_service, test_entity):
        """Test that protected entities cannot be deleted."""
        # Set entity to protected status
        test_entity.status = "approved"

        request = DeletionRequest(
            entity_type="SampleEntity",
            entity_id=str(test_entity.id),
            requester_id="user1",
            reason="Attempting to delete approved record",
        )

        with pytest.raises(Exception) as exc:
            await soft_delete_service.delete_entity(test_entity, request)

        assert "Cannot delete approved records" in str(exc.value)

    @pytest.mark.asyncio
    async def test_restore_entity_success(self, soft_delete_service, test_entity):
        """Test successful entity restoration."""
        # First delete the entity
        test_entity.soft_delete("user1", "Initial deletion for testing")
        soft_delete_service.session.commit()

        # Create restore request
        request = RestoreRequest(
            entity_type="SampleEntity",
            entity_id=str(test_entity.id),
            requester_id="user2",
            reason="Deletion was made in error - record needed for audit",
            reference_id="AUDIT-2024-001",
        )

        # Mock the entity class lookup
        soft_delete_service._get_entity_class = Mock(return_value=SampleEntity)

        restored = await soft_delete_service.restore_entity(
            entity_type="SampleEntity",
            entity_id=str(test_entity.id),
            request=request,
            require_approval=False,
        )

        assert restored.is_deleted is False
        assert restored.is_restored is True
        assert restored.restored_by == "user2"

    @pytest.mark.asyncio
    async def test_generate_deletion_report(self, soft_delete_service, db_session):
        """Test deletion report generation."""
        # Create and delete some entities
        entity1 = SampleEntity(name="Entity 1", status="draft")
        entity2 = SampleEntity(name="Entity 2", status="draft")
        entity3 = SampleEntity(name="Entity 3", status="draft")

        db_session.add_all([entity1, entity2, entity3])
        db_session.commit()

        # Delete entities with different users and reasons
        entity1.soft_delete("user1", "Quality issue - contamination found")
        entity2.soft_delete("user1", "Duplicate entry discovered")
        entity3.soft_delete("user2", "Obsolete - replaced by new version")
        db_session.commit()

        # Mock the entity class discovery
        soft_delete_service._get_all_soft_delete_classes = Mock(
            return_value=[SampleEntity]
        )

        # Generate report
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow() + timedelta(days=1)

        report = await soft_delete_service.generate_deletion_report(
            start_date=start_date, end_date=end_date
        )

        assert report.total_deletions == 3
        assert report.by_type["SampleEntity"] == 3
        assert report.by_user["user1"] == 2
        assert report.by_user["user2"] == 1
        assert "Quality Issue" in report.by_reason_category
        assert "Duplicate" in report.by_reason_category
        assert "Obsolescence" in report.by_reason_category


class TestIntegration:
    """Integration tests for complete workflows."""

    @pytest.mark.asyncio
    async def test_complete_deletion_restoration_cycle(
        self, soft_delete_service, db_session
    ):
        """Test complete cycle of deletion and restoration."""
        # Create entity
        entity = SampleEntity(name="Integration Test", status="draft")
        db_session.add(entity)
        db_session.commit()

        original_id = entity.id

        # Delete entity
        delete_request = DeletionRequest(
            entity_type="SampleEntity",
            entity_id=str(entity.id),
            requester_id="user1",
            reason="Integration test - temporary deletion for testing",
        )

        delete_result = await soft_delete_service.delete_entity(
            entity=entity, request=delete_request
        )

        assert delete_result["success"] is True

        # Verify entity is deleted
        active_entities = SampleEntity.query_active(db_session).all()
        assert len(active_entities) == 0

        deleted_entities = SampleEntity.query_deleted(db_session).all()
        assert len(deleted_entities) == 1

        # Restore entity
        restore_request = RestoreRequest(
            entity_type="SampleEntity",
            entity_id=str(original_id),
            requester_id="user2",
            reason="Integration test - restoring after test deletion",
        )

        soft_delete_service._get_entity_class = Mock(return_value=SampleEntity)

        restored_entity = await soft_delete_service.restore_entity(
            entity_type="SampleEntity",
            entity_id=str(original_id),
            request=restore_request,
            require_approval=False,
        )

        # Verify entity is restored
        assert restored_entity.is_deleted is False
        assert restored_entity.is_restored is True

        active_entities = SampleEntity.query_active(db_session).all()
        assert len(active_entities) == 1
        assert active_entities[0].id == original_id

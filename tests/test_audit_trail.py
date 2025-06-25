"""
Comprehensive tests for audit trail functionality.

Tests cover models, storage backends, logger, and decorators
to ensure 21 CFR Part 11 compliance.
"""

import asyncio
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from gxp_toolkit.audit_trail import (
    AuditAction,
    AuditEntry,
    AuditLogger,
    AuditQuery,
    AuditReport,
    audit_activity,
    audit_create,
    audit_delete,
    audit_log,
    audit_update,
)
from gxp_toolkit.audit_trail.logger import (
    current_session,
    current_user,
    set_audit_logger,
)
from gxp_toolkit.audit_trail.storage import (
    FileAuditStorage,
    SQLAuditStorage,
    get_audit_storage,
)


@pytest.fixture
def mock_user():
    """Create a mock user for testing."""
    return {
        "id": "test_user_123",
        "name": "Test User",
        "roles": ["operator", "viewer"],
    }


@pytest.fixture
def mock_request():
    """Create a mock request context."""
    return {
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 Test Browser",
    }


@pytest.fixture
def file_storage():
    """Create a temporary file storage for testing."""
    import asyncio

    tmpdir = tempfile.mkdtemp()
    storage = FileAuditStorage(tmpdir)

    # Initialize storage synchronously for test fixture
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(storage.initialize())
        yield storage
    finally:
        loop.close()
        import shutil

        shutil.rmtree(tmpdir)


@pytest.fixture
def sql_storage():
    """Create an in-memory SQL storage for testing."""
    import asyncio

    storage = SQLAuditStorage("sqlite:///:memory:")

    # Initialize storage synchronously for test fixture
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(storage.initialize())
        yield storage
    finally:
        loop.close()


@pytest.fixture
def audit_logger(file_storage):
    """Create an audit logger with file storage."""
    logger = AuditLogger(
        storage=file_storage,
        application_name="TestApp",
        batch_mode=False,  # Disable batching for tests
    )
    return logger


class TestAuditEntry:
    """Test AuditEntry model functionality."""

    def test_audit_entry_creation(self):
        """Test creating an audit entry."""
        entry = AuditEntry(
            id="test_123",
            user_id="user_123",
            action=AuditAction.CREATE,
            entity_type="TestEntity",
            entity_id="entity_456",
            application="TestApp",
        )

        assert entry.id == "test_123"
        assert entry.user_id == "user_123"
        assert entry.action == AuditAction.CREATE
        assert entry.timestamp <= datetime.utcnow()

    def test_checksum_calculation(self):
        """Test checksum calculation and verification."""
        entry = AuditEntry(
            id="test_123",
            user_id="user_123",
            action=AuditAction.UPDATE,
            entity_type="TestEntity",
            entity_id="entity_456",
            old_values={"status": "draft"},
            new_values={"status": "approved"},
            application="TestApp",
        )

        # Calculate checksum
        checksum = entry.calculate_checksum()
        assert checksum is not None
        assert len(checksum) == 64  # SHA256 produces 64 char hex

        # Verify checksum
        assert entry.verify_checksum(checksum) is True
        assert entry.verify_checksum("invalid_checksum") is False

    def test_critical_action_validation(self):
        """Test that critical actions require reasons."""
        # Should fail without reason
        with pytest.raises(ValueError) as exc:
            AuditEntry(
                id="test_123",
                user_id="user_123",
                action=AuditAction.DELETE,
                application="TestApp",
            )
        assert "Reason is required" in str(exc.value)

        # Should succeed with reason
        entry = AuditEntry(
            id="test_123",
            user_id="user_123",
            action=AuditAction.DELETE,
            reason="Test deletion for unit testing",
            application="TestApp",
        )
        assert entry.reason == "Test deletion for unit testing"

    def test_log_format(self):
        """Test conversion to log format."""
        entry = AuditEntry(
            id="test_123",
            user_id="user_123",
            action=AuditAction.UPDATE,
            entity_type="TestEntity",
            entity_id="entity_456",
            reason="Test update",
            application="TestApp",
        )

        log_str = entry.to_log_format()
        assert "USER=user_123" in log_str
        assert "ACTION=UPDATE" in log_str
        assert "ENTITY=TestEntity:entity_456" in log_str
        assert "REASON='Test update'" in log_str


class TestAuditLogger:
    """Test AuditLogger functionality."""

    @pytest.mark.asyncio
    async def test_log_activity(self, audit_logger, mock_user):
        """Test basic activity logging."""
        # Set context
        audit_logger.set_context(user=mock_user, session_id="session_123")

        # Log activity
        entry_id = await audit_logger.log_activity(
            action=AuditAction.CREATE,
            entity_type="Document",
            entity_id="doc_123",
            details={"title": "Test Document"},
        )

        assert entry_id is not None

        # Verify entry was stored
        entry = await audit_logger.storage.get_by_id(entry_id)
        assert entry is not None
        assert entry.user_id == "test_user_123"
        assert entry.action == AuditAction.CREATE
        assert entry.entity_type == "Document"
        assert entry.entity_id == "doc_123"

    @pytest.mark.asyncio
    async def test_batch_mode(self, file_storage):
        """Test batch mode operation."""
        logger = AuditLogger(
            storage=file_storage,
            application_name="TestApp",
            batch_mode=True,
            batch_size=3,
            flush_interval=10.0,  # Long interval to prevent auto-flush
        )

        logger.set_context(user={"id": "batch_user"})

        # Log fewer activities to avoid hitting batch_size
        ids = []
        for i in range(2):  # Less than batch_size
            entry_id = await logger.log_activity(
                action=AuditAction.CREATE,
                entity_type="BatchTest",
                entity_id=f"batch_{i}",
            )
            ids.append(entry_id)

        # Entries shouldn't be immediately available (still in batch)
        entry = await file_storage.get_by_id(ids[0])
        assert entry is None

        # Force flush
        await logger.flush()

        # Now entries should be available
        for entry_id in ids:
            entry = await file_storage.get_by_id(entry_id)
            assert entry is not None

        # Clean up the logger
        await logger.close()

    @pytest.mark.asyncio
    async def test_query_activities(self, audit_logger, mock_user):
        """Test querying audit entries."""
        audit_logger.set_context(user=mock_user)

        # Create test entries
        for i in range(5):
            await audit_logger.log_activity(
                action=AuditAction.CREATE if i % 2 == 0 else AuditAction.UPDATE,
                entity_type="QueryTest",
                entity_id=f"query_{i}",
            )

        # Query all entries
        query = AuditQuery(limit=10)
        entries = await audit_logger.query(query)
        assert len(entries) == 5

        # Query by action
        query = AuditQuery(actions=[AuditAction.CREATE])
        entries = await audit_logger.query(query)
        assert len(entries) == 3
        assert all(e.action == AuditAction.CREATE for e in entries)

    @pytest.mark.asyncio
    async def test_user_activities(self, audit_logger):
        """Test getting user-specific activities."""
        # Log activities for different users
        for user_id in ["user1", "user2", "user1", "user3", "user1"]:
            audit_logger.set_context(user={"id": user_id})
            await audit_logger.log_activity(
                action=AuditAction.CREATE,
                entity_type="UserTest",
            )

        # Get activities for user1
        entries = await audit_logger.get_user_activities("user1")
        assert len(entries) == 3
        assert all(e.user_id == "user1" for e in entries)

    @pytest.mark.asyncio
    async def test_entity_history(self, audit_logger, mock_user):
        """Test getting entity history."""
        audit_logger.set_context(user=mock_user)

        # Create entity lifecycle
        entity_id = "entity_lifecycle_123"

        # Create
        await audit_logger.log_activity(
            action=AuditAction.CREATE,
            entity_type="LifecycleTest",
            entity_id=entity_id,
            new_values={"status": "draft"},
        )

        # Update
        await audit_logger.log_activity(
            action=AuditAction.UPDATE,
            entity_type="LifecycleTest",
            entity_id=entity_id,
            old_values={"status": "draft"},
            new_values={"status": "reviewed"},
        )

        # Approve
        await audit_logger.log_activity(
            action=AuditAction.APPROVE,
            entity_type="LifecycleTest",
            entity_id=entity_id,
            reason="Meets all requirements",
        )

        # Get history
        history = await audit_logger.get_entity_history("LifecycleTest", entity_id)

        assert len(history) == 3
        assert history[0].action == AuditAction.CREATE
        assert history[1].action == AuditAction.UPDATE
        assert history[2].action == AuditAction.APPROVE

    @pytest.mark.asyncio
    async def test_failed_actions(self, audit_logger, mock_user):
        """Test tracking failed actions."""
        audit_logger.set_context(user=mock_user)

        # Log some successful and failed actions
        await audit_logger.log_activity(
            action=AuditAction.CREATE,
            entity_type="FailTest",
            success=True,
        )

        await audit_logger.log_activity(
            action=AuditAction.UPDATE,
            entity_type="FailTest",
            success=False,
            error_message="Validation failed",
        )

        await audit_logger.log_activity(
            action=AuditAction.DELETE,
            entity_type="FailTest",
            success=False,
            error_message="Permission denied",
            reason="Attempted unauthorized deletion",
        )

        # Get failed actions - filter by entity type to isolate test data
        from gxp_toolkit.audit_trail.models import AuditQuery

        query = AuditQuery(entity_types=["FailTest"], failures_only=True)
        failed = await audit_logger.query(query)

        assert len(failed) == 2
        assert all(not e.success for e in failed)
        assert failed[0].error_message == "Permission denied"  # Most recent first


class TestAuditDecorators:
    """Test audit decorator functionality."""

    @pytest.mark.asyncio
    async def test_audit_log_decorator(self, audit_logger):
        """Test basic audit_log decorator."""
        # Set the global audit logger for decorators
        set_audit_logger(audit_logger)

        # Set up context
        current_user.set({"id": "decorator_user"})

        @audit_log(action=AuditAction.CREATE, entity_type_param="entity_type")
        async def create_entity(entity_type: str, data: dict):
            return {"id": "created_123", "type": entity_type, **data}

        # Call decorated function
        result = await create_entity("TestEntity", {"name": "Test"})

        # Verify result
        assert result["id"] == "created_123"

        # Verify audit entry was created
        await asyncio.sleep(0.1)  # Give time for async logging

        query = AuditQuery(actions=[AuditAction.CREATE], limit=1)
        entries = await audit_logger.query(query)

        assert len(entries) > 0
        assert entries[0].action == AuditAction.CREATE
        assert entries[0].entity_type == "TestEntity"

    @pytest.mark.asyncio
    async def test_audit_log_with_error(self, audit_logger):
        """Test audit logging when function fails."""
        # Set the global audit logger for decorators
        set_audit_logger(audit_logger)

        current_user.set({"id": "error_user"})

        @audit_log(capture_errors=True)
        async def failing_function():
            raise ValueError("Test error")

        # Function should still raise the error
        with pytest.raises(ValueError):
            await failing_function()

        # But audit entry should be created
        await asyncio.sleep(0.1)

        query = AuditQuery(failures_only=True, limit=1)
        entries = await audit_logger.query(query)

        assert len(entries) > 0
        assert not entries[0].success
        assert "Test error" in entries[0].error_message

    def test_audit_log_sync_function(self, audit_logger):
        """Test decorator on synchronous function."""
        # Set the global audit logger for decorators
        set_audit_logger(audit_logger)

        current_user.set({"id": "sync_user"})

        @audit_log(action=AuditAction.UPDATE)
        def sync_update(entity_id: str, data: dict):
            return {"id": entity_id, "updated": True}

        # Call sync function
        result = sync_update("sync_123", {"field": "value"})
        assert result["updated"] is True

    @pytest.mark.asyncio
    async def test_audit_activity_decorator(self, audit_logger):
        """Test simplified audit_activity decorator."""
        # Set the global audit logger for decorators
        set_audit_logger(audit_logger)

        current_user.set({"id": "activity_user"})

        @audit_activity(AuditAction.APPROVE)
        async def approve_document(doc_id: str, reason: str):
            return {"approved": True, "doc_id": doc_id}

        # Should require reason for approval
        result = await approve_document("doc_456", "Meets all criteria")
        assert result["approved"] is True

        # Verify audit
        query = AuditQuery(actions=[AuditAction.APPROVE], limit=1)
        entries = await audit_logger.query(query)

        assert len(entries) > 0
        assert entries[0].reason == "Meets all criteria"

    @pytest.mark.asyncio
    async def test_convenience_decorators(self, audit_logger):
        """Test convenience decorators like audit_create, audit_update."""
        # Set the global audit logger for decorators
        set_audit_logger(audit_logger)

        current_user.set({"id": "convenience_user"})

        @audit_create()
        async def create_item(name: str):
            return {"id": "item_123", "name": name}

        @audit_update()
        async def update_item(item_id: str, old_values: dict, new_values: dict):
            return new_values

        @audit_delete()
        async def delete_item(item_id: str, reason: str):
            return {"deleted": True}

        # Test create
        await create_item("Test Item")

        # Test update
        await update_item("item_123", {"status": "active"}, {"status": "inactive"})

        # Test delete
        await delete_item("item_123", "No longer needed for testing")

        # Verify all three audit entries
        await asyncio.sleep(0.1)
        query = AuditQuery(limit=10)
        entries = await audit_logger.query(query)

        actions = [e.action for e in entries]
        assert AuditAction.CREATE in actions
        assert AuditAction.UPDATE in actions
        assert AuditAction.DELETE in actions


class TestAuditReport:
    """Test audit report generation."""

    @pytest.mark.asyncio
    async def test_report_generation(self, audit_logger, mock_user):
        """Test generating audit reports."""
        audit_logger.set_context(user=mock_user)

        # Create various activities
        for i in range(10):
            action = AuditAction.CREATE if i < 6 else AuditAction.UPDATE
            success = i != 3  # One failure

            await audit_logger.log_activity(
                action=action,
                entity_type="ReportTest",
                entity_id=f"report_{i}",
                success=success,
                error_message="Test failure" if not success else None,
            )

        # Generate report
        start_date = datetime.utcnow() - timedelta(hours=1)
        end_date = datetime.utcnow() + timedelta(hours=1)

        report = await audit_logger.generate_report(
            start_date=start_date,
            end_date=end_date,
            generated_by="test_user_123",
        )

        assert report.total_entries == 10
        assert report.by_action[AuditAction.CREATE] == 6
        assert report.by_action[AuditAction.UPDATE] == 4
        assert report.total_failures == 1
        assert report.failure_rate == 10.0

    @pytest.mark.asyncio
    async def test_report_anomaly_detection(self, audit_logger):
        """Test anomaly detection in reports."""
        # Create unusual activity pattern
        audit_logger.set_context(user={"id": "hyperactive_user"})

        # Create many normal users with low activity first
        for user_num in range(10):
            audit_logger.set_context(user={"id": f"normal_user_{user_num}"})
            for i in range(2):
                await audit_logger.log_activity(
                    action=AuditAction.CREATE,
                    entity_type="AnomalyTest",
                )

        # Then one user with excessive activity
        audit_logger.set_context(user={"id": "hyperactive_user"})
        for i in range(200):
            await audit_logger.log_activity(
                action=AuditAction.CREATE,
                entity_type="AnomalyTest",
            )

        # Generate report
        report = await audit_logger.generate_report(
            start_date=datetime.utcnow() - timedelta(hours=1),
            end_date=datetime.utcnow() + timedelta(hours=1),
        )

        # Should detect unusual activity
        assert len(report.anomalies) > 0
        anomaly = report.anomalies[0]
        assert anomaly["type"] == "UNUSUAL_USER_ACTIVITY"
        assert "hyperactive_user" in anomaly["user_id"]


class TestAuditIntegrity:
    """Test audit integrity verification."""

    @pytest.mark.asyncio
    async def test_integrity_verification(self, audit_logger, mock_user):
        """Test verifying audit entry integrity."""
        audit_logger.set_context(user=mock_user)

        # Create some entries
        for i in range(5):
            await audit_logger.log_activity(
                action=AuditAction.CREATE,
                entity_type="IntegrityTest",
                entity_id=f"integrity_{i}",
            )

        # Verify integrity
        results = await audit_logger.verify_integrity()

        assert results["total_checked"] == 5
        assert results["valid"] == 5
        assert results["invalid"] == 0

    @pytest.mark.asyncio
    async def test_detect_tampering(self, sql_storage):
        """Test detection of tampered audit entries."""
        logger = AuditLogger(storage=sql_storage)
        logger.set_context(user={"id": "tamper_test"})

        # Create an entry
        entry_id = await logger.log_activity(
            action=AuditAction.CREATE,
            entity_type="TamperTest",
        )

        # Ensure entry is flushed to database
        await logger.flush()

        # Tamper with the entry directly in storage
        from gxp_toolkit.audit_trail.storage import AuditEntryDB

        with sql_storage.SessionLocal() as session:
            db_entry = (
                session.query(AuditEntryDB).filter(AuditEntryDB.id == entry_id).first()
            )

            # Change the action and add reason to avoid validation errors
            db_entry.action = AuditAction.DELETE
            db_entry.reason = "Tampered reason"
            session.commit()

        # Verify integrity should detect tampering
        results = await logger.verify_integrity()

        assert results["invalid"] == 1
        assert len(results["invalid_entries"]) == 1


class TestAuditArchival:
    """Test audit log archival functionality."""

    @pytest.mark.asyncio
    async def test_archive_old_entries(self, audit_logger, mock_user):
        """Test archiving old audit entries."""
        audit_logger.set_context(user=mock_user)

        # Note: In a real test, we'd modify entry timestamps
        # For now, just test the archival mechanism
        with tempfile.TemporaryDirectory() as archive_dir:
            # Create some entries
            for i in range(5):
                await audit_logger.log_activity(
                    action=AuditAction.CREATE,
                    entity_type="ArchiveTest",
                )

            # Archive entries older than 1 day ago (should archive nothing since entries are recent)
            cutoff = datetime.utcnow() - timedelta(days=1)
            archived = await audit_logger.archive_old_entries(
                cutoff_date=cutoff,
                archive_location=archive_dir,
            )

            # Since all entries are recent (created now), nothing should be archived
            assert archived == 0

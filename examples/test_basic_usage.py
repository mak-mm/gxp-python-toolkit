#!/usr/bin/env python3
"""
Basic usage test for the GxP Python Toolkit.

This script demonstrates basic functionality of both the soft delete
and audit trail modules.
"""

import asyncio
from datetime import datetime

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from gxp_toolkit.audit_trail import AuditAction, AuditLogger, audit_create
from gxp_toolkit.soft_delete import SoftDeleteMixin

# Create test database model
Base = declarative_base()


class TestRecord(Base, SoftDeleteMixin):
    """Test record with soft delete capability."""

    __tablename__ = "test_records"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    status = Column(String(50))


async def test_basic_functionality():
    """Test basic soft delete and audit functionality."""
    print("🧪 GxP Python Toolkit - Basic Functionality Test")
    print("=" * 50)

    # Setup in-memory database
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create test record
    record = TestRecord(name="Test Document", status="draft")
    session.add(record)
    session.commit()
    print(f"✅ Created record: {record.name} (ID: {record.id})")

    # Test soft delete
    record.soft_delete(
        user_id="test_user_123",
        reason="Testing soft delete functionality for GxP compliance",
    )
    session.commit()
    print(f"✅ Soft deleted record: {record.name}")
    print(f"   - Deleted at: {record.deleted_at}")
    print(f"   - Deleted by: {record.deleted_by}")
    print(f"   - Is deleted: {record.is_deleted}")

    # Test restore
    record.restore(
        user_id="test_supervisor_456",
        reason="Restoration approved after review - record needed for audit trail",
    )
    session.commit()
    print(f"✅ Restored record: {record.name}")
    print(f"   - Restored at: {record.restored_at}")
    print(f"   - Restored by: {record.restored_by}")
    print(f"   - Is deleted: {record.is_deleted}")
    print(f"   - Is restored: {record.is_restored}")

    # Test audit logging
    print("\n📋 Testing Audit Trail:")
    import os
    import tempfile

    from gxp_toolkit.audit_trail.storage import FileAuditStorage

    # Create temporary storage for demo
    temp_dir = tempfile.mkdtemp()
    storage = FileAuditStorage(temp_dir)
    await storage.initialize()

    logger = AuditLogger(storage=storage, application_name="GxP-Test-App")

    # Set audit context
    logger.set_context(
        user={"id": "test_user_123", "name": "Test User", "roles": ["operator"]},
        session_id="test_session_789",
    )

    # Log an activity
    audit_id = await logger.log_activity(
        action=AuditAction.UPDATE,
        entity_type="TestRecord",
        entity_id=str(record.id),
        old_values={"status": "draft"},
        new_values={"status": "approved"},
        reason="Approved after quality review",
    )
    print(f"✅ Created audit entry: {audit_id}")

    # Test decorator
    @audit_create()
    async def create_document(name: str, doc_type: str):
        """Example function with audit decorator."""
        return {"id": "doc_123", "name": name, "type": doc_type}

    result = await create_document("Test Protocol", "SOP")
    print(f"✅ Decorated function result: {result}")

    session.close()

    # Cleanup temp directory
    import shutil

    shutil.rmtree(temp_dir)

    print("\n🎉 All basic functionality tests passed!")
    print("\nNext steps:")
    print(
        "- Review the comprehensive documentation in GXP_SOFTWARE_DEVELOPMENT_GUIDE.md"
    )
    print("- Run the full test suite: pytest tests/ -v")
    print("- Explore advanced features like electronic signatures and access control")


if __name__ == "__main__":
    asyncio.run(test_basic_functionality())

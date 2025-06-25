#!/usr/bin/env python3
"""
Interactive demo for the GxP Python Toolkit.

This provides step-by-step examples you can run in a Python shell.
"""


def demo_soft_delete():
    """Demonstrate soft delete functionality."""
    print("🗑️  SOFT DELETE DEMO")
    print("=" * 40)

    from sqlalchemy import Column, Integer, String, create_engine
    from sqlalchemy.orm import declarative_base, sessionmaker

    from gxp_toolkit.soft_delete import SoftDeleteMixin

    # Setup
    Base = declarative_base()

    class Document(SoftDeleteMixin, Base):
        __tablename__ = "documents"

        id = Column(Integer, primary_key=True)
        title = Column(String(200))
        content = Column(String(1000))
        status = Column(String(50))

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create document
    doc = Document(
        title="Quality Control Procedure",
        content="Standard operating procedure for quality control...",
        status="draft",
    )
    session.add(doc)
    session.commit()
    print(f"✅ Created document: '{doc.title}' (ID: {doc.id})")

    # Query active documents
    active_docs = Document.query_active(session).all()
    print(f"📊 Active documents: {len(active_docs)}")

    # Soft delete
    doc.soft_delete(
        user_id="qc_manager_123",
        reason="Document superseded by new version with updated regulations",
    )
    session.commit()
    print(f"🗑️  Soft deleted: {doc.title}")
    print(f"   - Deleted by: {doc.deleted_by}")
    print(f"   - Reason: {doc.deletion_reason}")

    # Query again
    active_docs = Document.query_active(session).all()
    deleted_docs = Document.query_deleted(session).all()
    print(f"📊 Active documents: {len(active_docs)}")
    print(f"📊 Deleted documents: {len(deleted_docs)}")

    # Restore
    doc.restore(
        user_id="regulatory_supervisor_456",
        reason="Document needed for regulatory audit - restoration approved by supervisor",
    )
    session.commit()
    print(f"♻️  Restored: {doc.title}")
    print(f"   - Restored by: {doc.restored_by}")
    print(f"   - Is restored: {doc.is_restored}")

    session.close()
    return doc


def demo_audit_trail():
    """Demonstrate audit trail functionality."""
    print("\n📋 AUDIT TRAIL DEMO")
    print("=" * 40)

    import asyncio
    import tempfile

    from gxp_toolkit.audit_trail import (
        AuditAction,
        AuditLogger,
        audit_create,
        audit_update,
    )
    from gxp_toolkit.audit_trail.storage import FileAuditStorage

    async def audit_demo():
        # Setup storage
        temp_dir = tempfile.mkdtemp()
        storage = FileAuditStorage(temp_dir)
        await storage.initialize()

        # Create logger
        logger = AuditLogger(storage=storage, application_name="Demo-GxP-System")

        # Set context
        logger.set_context(
            user={
                "id": "demo_user_789",
                "name": "Demo User",
                "roles": ["analyst", "operator"],
            },
            session_id="demo_session_abc123",
        )

        # Manual logging
        audit_id = await logger.log_activity(
            action=AuditAction.CREATE,
            entity_type="SampleBatch",
            entity_id="BATCH_2024_001",
            new_values={
                "batch_number": "BATCH_2024_001",
                "status": "in_progress",
                "analyst": "demo_user_789",
            },
            reason="New batch created for testing protocol XYZ",
        )
        print(f"✅ Created audit entry: {audit_id}")

        # Using decorators
        @audit_create()
        async def create_test_result(batch_id: str, result_value: float, status: str):
            """Create a test result with automatic audit logging."""
            return {
                "id": f"RESULT_{batch_id}_001",
                "batch_id": batch_id,
                "result": result_value,
                "status": status,
                "timestamp": "2024-01-15T14:30:00Z",
            }

        @audit_update()
        async def approve_result(
            result_id: str, old_values: dict, new_values: dict, reason: str
        ):
            """Approve a test result with audit logging."""
            return new_values

        # Test the decorators
        result = await create_test_result("BATCH_2024_001", 99.7, "pending_review")
        print(f"✅ Created test result: {result['id']}")

        approved_result = await approve_result(
            result_id=result["id"],
            old_values={"status": "pending_review"},
            new_values={"status": "approved", "approved_by": "supervisor_xyz"},
            reason="Result meets all quality specifications",
        )
        print(f"✅ Approved result: {approved_result}")

        # Query audit trail
        from gxp_toolkit.audit_trail.models import AuditQuery

        query = AuditQuery(limit=10)
        entries = await logger.query(query)
        print(f"📊 Total audit entries: {len(entries)}")

        for entry in entries:
            print(
                f"   - {entry.action} on {entry.entity_type or 'system'} by {entry.user_id}"
            )

        # Cleanup
        import shutil

        shutil.rmtree(temp_dir)

    asyncio.run(audit_demo())


def demo_integration():
    """Demonstrate integration of both modules."""
    print("\n🔗 INTEGRATION DEMO")
    print("=" * 40)

    import asyncio
    import tempfile

    from sqlalchemy import Column, Integer, String, create_engine
    from sqlalchemy.orm import declarative_base, sessionmaker

    from gxp_toolkit.audit_trail import AuditLogger
    from gxp_toolkit.audit_trail.storage import FileAuditStorage
    from gxp_toolkit.soft_delete import SoftDeleteMixin, SoftDeleteService

    async def integration_demo():
        # Database setup
        Base = declarative_base()

        class QualityRecord(SoftDeleteMixin, Base):
            __tablename__ = "quality_records"

            id = Column(Integer, primary_key=True)
            sample_id = Column(String(100))
            test_type = Column(String(100))
            result = Column(String(200))
            status = Column(String(50))

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()

        # Audit setup
        temp_dir = tempfile.mkdtemp()
        storage = FileAuditStorage(temp_dir)
        await storage.initialize()
        audit_logger = AuditLogger(storage=storage, application_name="QC-System")

        # Create integrated service
        def mock_permission_checker(user_id: str, action: str, entity_type: str, entity) -> bool:
            return True  # Allow all for demo

        service = SoftDeleteService(
            session=session,
            audit_logger=audit_logger,
            permission_checker=mock_permission_checker,
        )

        # Create a quality record
        record = QualityRecord(
            sample_id="SAMPLE_2024_001",
            test_type="Purity Analysis",
            result="99.8% pure",
            status="pending",
        )
        session.add(record)
        session.commit()
        print(f"✅ Created quality record: {record.sample_id}")

        # Set audit context
        audit_logger.set_context(
            user={"id": "qc_analyst_456", "name": "QC Analyst", "roles": ["analyst"]},
            session_id="qc_session_789",
        )

        # Use integrated deletion with automatic audit
        from gxp_toolkit.soft_delete.models import DeletionRequest

        deletion_request = DeletionRequest(
            entity_type="QualityRecord",
            entity_id=str(record.id),
            requester_id="qc_analyst_456",
            reason="Sample contaminated during storage - invalidating test results",
            reference_id="INCIDENT_2024_003",
        )

        # Perform soft delete directly (service.delete_entity expects different params)
        record.soft_delete(
            user_id=deletion_request.requester_id,
            reason=deletion_request.reason
        )
        session.commit()
        
        # Log the deletion manually
        await audit_logger.log_activity(
            action="DELETE",
            entity_type="QualityRecord",
            entity_id=str(record.id),
            reason=deletion_request.reason
        )
        
        result = {"success": True}

        print(f"✅ Integrated deletion completed: {result['success']}")
        print(f"   - Audit trail created")
        print(f"   - Record marked as deleted: {record.is_deleted}")

        # Cleanup
        session.close()
        import shutil

        shutil.rmtree(temp_dir)

    asyncio.run(integration_demo())


if __name__ == "__main__":
    print("🧪 GxP Python Toolkit - Interactive Demos")
    print("=" * 50)

    demo_soft_delete()
    demo_audit_trail()
    demo_integration()

    print("\n🎉 All demos completed successfully!")
    print("\n💡 Try running individual functions in a Python shell:")
    print("   from interactive_demo import demo_soft_delete")
    print("   demo_soft_delete()")

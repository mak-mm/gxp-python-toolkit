#!/usr/bin/env python3
"""Quick functionality test script"""


def test_imports():
    """Test that all imports work"""
    try:
        from gxp_toolkit.audit_trail import AuditAction, AuditLogger, audit_create
        from gxp_toolkit.config import GxPConfig
        from gxp_toolkit.soft_delete import SoftDeleteMixin, SoftDeleteService

        print("✅ All imports successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False


def test_basic_soft_delete():
    """Test basic soft delete functionality"""
    try:
        from sqlalchemy import Column, Integer, String, create_engine
        from sqlalchemy.orm import declarative_base, sessionmaker

        from gxp_toolkit.soft_delete import SoftDeleteMixin

        Base = declarative_base()

        class TestModel(Base, SoftDeleteMixin):
            __tablename__ = "test"
            __allow_unmapped__ = True
            id = Column(Integer, primary_key=True)
            name = Column(String(100))

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()

        # Create and delete
        model = TestModel(name="Test")
        session.add(model)
        session.commit()

        model.soft_delete("user123", "Test deletion reason")
        assert model.is_deleted == True
        assert model.deleted_by == "user123"

        # Query
        active = TestModel.query_active(session).count()
        deleted = TestModel.query_deleted(session).count()
        assert active == 0
        assert deleted == 1

        print("✅ Soft delete functionality working")
        return True

    except Exception as e:
        print(f"❌ Soft delete test failed: {e}")
        return False


def test_basic_audit():
    """Test basic audit functionality"""
    try:
        import asyncio
        import tempfile

        from gxp_toolkit.audit_trail import AuditAction, AuditLogger
        from gxp_toolkit.audit_trail.storage import FileAuditStorage

        async def audit_test():
            temp_dir = tempfile.mkdtemp()
            storage = FileAuditStorage(temp_dir)
            await storage.initialize()

            logger = AuditLogger(storage=storage)
            logger.set_context(user={"id": "test_user"})

            audit_id = await logger.log_activity(
                action=AuditAction.CREATE,
                entity_type="Test",
                entity_id="123",
                reason="Test audit",
            )

            assert audit_id is not None
            return True

        result = asyncio.run(audit_test())
        print("✅ Audit trail functionality working")
        return result

    except Exception as e:
        print(f"❌ Audit test failed: {e}")
        return False


if __name__ == "__main__":
    print("🧪 Quick Functionality Tests")
    print("=" * 30)

    results = []
    results.append(test_imports())
    results.append(test_basic_soft_delete())
    results.append(test_basic_audit())

    passed = sum(results)
    total = len(results)

    print(f"\n📊 Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All core functionality working!")
    else:
        print("⚠️  Some functionality issues detected")

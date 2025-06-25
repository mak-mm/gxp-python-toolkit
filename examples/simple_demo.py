#!/usr/bin/env python3
"""
Simple demo to test if the GxP Python Toolkit is working correctly.
"""

def test_imports():
    """Test if all modules can be imported."""
    print("🧪 Testing imports...")
    
    try:
        from gxp_toolkit import __version__
        print(f"✅ GxP Toolkit version: {__version__}")
        
        from gxp_toolkit.audit_trail import AuditLogger, AuditAction
        print("✅ Audit trail module imported")
        
        from gxp_toolkit.soft_delete import SoftDeleteMixin
        print("✅ Soft delete module imported")
        
        from gxp_toolkit.access_control import AccessControlManager
        print("✅ Access control module imported")
        
        from gxp_toolkit.data_integrity import DataIntegrityChecker
        print("✅ Data integrity module imported")
        
        from gxp_toolkit.electronic_signatures import ElectronicSignatureManager
        print("✅ Electronic signatures module imported")
        
        from gxp_toolkit.validation import ValidationFramework
        print("✅ Validation module imported")
        
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False


def test_basic_functionality():
    """Test basic functionality without database dependencies."""
    print("\n🧪 Testing basic functionality...")
    
    try:
        # Test data integrity
        from gxp_toolkit.data_integrity import DataIntegrityService, ChecksumAlgorithm
        
        checker = DataIntegrityService(algorithm=ChecksumAlgorithm.SHA256)
        data = b"Test data for integrity check"
        checksum = checker.calculate_checksum(data)
        print(f"✅ Data integrity checksum: {checksum[:16]}...")
        
        # Test validation
        from gxp_toolkit.validation import ValidationFramework, ValidationSeverity
        from gxp_toolkit.validation.rules import ValidationRule
        
        framework = ValidationFramework(name="Demo Validation")
        
        # Add a simple rule
        rule = ValidationRule(
            id="TEST001",
            name="Test Rule",
            description="Simple test rule",
            severity=ValidationSeverity.ERROR,
            validation_function=lambda data: data.get("value", 0) > 0,
            error_message="Value must be positive"
        )
        framework.add_rule(rule)
        
        # Test validation
        result = framework.validate({"value": 10})
        print(f"✅ Validation passed: {result.is_valid}")
        
        # Test access control
        from gxp_toolkit.access_control import AccessControlManager, Permission
        
        rbac = AccessControlManager()
        rbac.add_role("operator", "Basic operator role")
        rbac.add_role("admin", "Administrator role")
        rbac.add_permission("operator", Permission.READ)
        rbac.add_permission("admin", Permission.READ)
        rbac.add_permission("admin", Permission.WRITE)
        rbac.add_permission("admin", Permission.DELETE)
        
        rbac.assign_role("user123", "operator")
        can_read = rbac.check_permission("user123", Permission.READ)
        can_delete = rbac.check_permission("user123", Permission.DELETE)
        
        print(f"✅ Access control - User can read: {can_read}, can delete: {can_delete}")
        
        return True
        
    except Exception as e:
        print(f"❌ Functionality error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_async_functionality():
    """Test async functionality."""
    print("\n🧪 Testing async functionality...")
    
    try:
        import asyncio
        import tempfile
        import shutil
        
        async def async_test():
            # Create temporary directory for audit logs
            temp_dir = tempfile.mkdtemp()
            
            try:
                from gxp_toolkit.audit_trail import AuditLogger, AuditAction
                from gxp_toolkit.audit_trail.storage import FileAuditStorage
                
                # Initialize storage
                storage = FileAuditStorage(temp_dir)
                await storage.initialize()
                
                # Create logger
                logger = AuditLogger(
                    storage=storage,
                    application_name="Demo-App"
                )
                
                # Set context
                logger.set_context(
                    user={"id": "demo_user", "name": "Demo User"},
                    session_id="demo_session"
                )
                
                # Log an activity
                audit_id = await logger.log_activity(
                    action=AuditAction.CREATE,
                    entity_type="TestRecord",
                    entity_id="TEST001",
                    new_values={"status": "created"},
                    reason="Demo test for toolkit verification"
                )
                
                print(f"✅ Audit log created with ID: {audit_id}")
                
                # Query logs
                from gxp_toolkit.audit_trail.models import AuditQuery
                query = AuditQuery(limit=1)
                entries = await logger.query(query)
                
                if entries:
                    print(f"✅ Retrieved {len(entries)} audit entries")
                
                return True
                
            finally:
                # Cleanup
                shutil.rmtree(temp_dir)
        
        # Run async test
        result = asyncio.run(async_test())
        return result
        
    except Exception as e:
        print(f"❌ Async functionality error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("🧪 GxP Python Toolkit - Simple Demo")
    print("=" * 50)
    
    all_passed = True
    
    # Run tests
    if not test_imports():
        all_passed = False
    
    if not test_basic_functionality():
        all_passed = False
    
    if not test_async_functionality():
        all_passed = False
    
    # Summary
    print("\n" + "=" * 50)
    if all_passed:
        print("✅ All tests passed! The toolkit is working correctly.")
    else:
        print("❌ Some tests failed. Please check the errors above.")
    
    print("\n💡 For database-related features (soft delete, etc.), you'll need")
    print("   to set up SQLAlchemy models with proper configuration.")
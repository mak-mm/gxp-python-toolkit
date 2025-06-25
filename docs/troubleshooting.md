# Troubleshooting Guide

This guide helps you resolve common issues when using the GxP Python Toolkit.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Problems](#configuration-problems)
- [Audit Trail Issues](#audit-trail-issues)
- [Electronic Signature Errors](#electronic-signature-errors)
- [Database and Storage Issues](#database-and-storage-issues)
- [Performance Problems](#performance-problems)
- [Integration Issues](#integration-issues)
- [Common Error Messages](#common-error-messages)

## Installation Issues

### Problem: Import errors after installation

**Symptom:**
```python
ImportError: cannot import name 'AuditLogger' from 'gxp_toolkit'
```

**Solutions:**

1. Verify installation:
```bash
pip show gxp-python-toolkit
```

2. Reinstall with dependencies:
```bash
pip install --force-reinstall gxp-python-toolkit[all]
```

3. Check Python version compatibility:
```bash
python --version  # Should be 3.8+
```

### Problem: Missing dependencies

**Symptom:**
```
ModuleNotFoundError: No module named 'cryptography'
```

**Solution:**
```bash
# Install all optional dependencies
pip install gxp-python-toolkit[crypto,async,dev]
```

## Configuration Problems

### Problem: Configuration not loading

**Symptom:**
```python
AttributeError: 'NoneType' object has no attribute 'audit_retention_days'
```

**Solutions:**

1. Check configuration file location:
```python
import os
print(os.path.exists('gxp_config.py'))
```

2. Verify configuration syntax:
```python
from gxp_toolkit import GxPConfig

# Minimal valid configuration
config = GxPConfig(
    audit_retention_days=2555
)
```

3. Use environment variables:
```bash
export GXP_AUDIT_RETENTION_DAYS=2555
export GXP_AUDIT_STORAGE_BACKEND=sqlite
```

### Problem: Invalid configuration values

**Symptom:**
```
ValidationError: audit_retention_days must be between 1 and 36500
```

**Solution:**
Check configuration constraints:
```python
# Valid ranges
config = GxPConfig(
    audit_retention_days=2555,        # 1-36500 days
    signature_timeout_minutes=15,      # 1-60 minutes
    max_login_attempts=3,              # 1-10 attempts
    session_timeout_minutes=30,        # 5-480 minutes
)
```

## Audit Trail Issues

### Problem: Audit events not being recorded

**Symptom:**
Functions execute but no audit trail entries appear.

**Solutions:**

1. Verify audit logger initialization:
```python
from gxp_toolkit import AuditLogger

# Correct initialization
audit = AuditLogger()  # Uses default config

# With custom config
audit = AuditLogger(config=my_config)
```

2. Check decorator usage:
```python
# Correct
@audit.log_activity("USER_ACTION")
def my_function():
    pass

# Incorrect - missing parentheses
@audit.log_activity  # This won't work!
def my_function():
    pass
```

3. Verify storage connection:
```python
# Test storage connection
storage = audit.get_storage()
health = storage.get_health()
print(f"Storage status: {health}")
```

### Problem: Audit query performance

**Symptom:**
Audit queries take too long or timeout.

**Solutions:**

1. Add indexes to audit table:
```sql
CREATE INDEX idx_audit_user ON audit_trail(user);
CREATE INDEX idx_audit_timestamp ON audit_trail(timestamp);
CREATE INDEX idx_audit_action ON audit_trail(action);
```

2. Use date ranges in queries:
```python
# Good - limited date range
events = storage.query_events(
    start_date=datetime.now() - timedelta(days=7),
    limit=1000
)

# Bad - no constraints
events = storage.query_events()  # Queries all events!
```

3. Enable query caching:
```python
config = GxPConfig(
    audit_query_cache_ttl=300,  # 5 minutes
    audit_query_cache_size=100
)
```

## Electronic Signature Errors

### Problem: "Multi-factor authentication required"

**Symptom:**
```
PermissionError: Multi-factor authentication required for signing
```

**Solutions:**

1. Ensure user has MFA enabled:
```python
user = User(
    username="john.doe",
    email="john@example.com",
    metadata={"authentication_factors": ["password", "mfa"]}
)
```

2. Disable MFA requirement (development only):
```python
@require_signature("Approve action", require_mfa=False)
def my_function():
    pass
```

### Problem: Signature verification fails

**Symptom:**
```
SignatureError: Invalid signature - tampering detected
```

**Solutions:**

1. Check signature data integrity:
```python
# Verify signature immediately after creation
signature = create_signature(...)
is_valid = verify_signature(signature)
```

2. Ensure consistent serialization:
```python
# Use toolkit's serialization
from gxp_toolkit.electronic_signatures import serialize_for_signature

data = serialize_for_signature({"key": "value"})
```

## Database and Storage Issues

### Problem: Database connection errors

**Symptom:**
```
sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) could not connect to server
```

**Solutions:**

1. Verify connection string:
```python
# PostgreSQL
config = GxPConfig(
    audit_connection_string="postgresql://user:pass@localhost:5432/dbname"
)

# SQLite (for testing)
config = GxPConfig(
    audit_connection_string="sqlite:///local_audit.db"
)
```

2. Test database connectivity:
```bash
# PostgreSQL
psql -h localhost -U user -d dbname -c "SELECT 1;"

# Check if service is running
sudo systemctl status postgresql
```

3. Use connection pooling:
```python
config = GxPConfig(
    db_pool_size=10,
    db_pool_timeout=30,
    db_pool_recycle=3600
)
```

### Problem: Soft delete not working

**Symptom:**
Records are permanently deleted instead of soft deleted.

**Solutions:**

1. Ensure model inherits from SoftDeleteMixin:
```python
from gxp_toolkit.soft_delete import SoftDeleteMixin

class MyModel(Base, SoftDeleteMixin):  # Correct
    __tablename__ = 'my_table'
```

2. Use soft delete methods:
```python
# Correct - soft delete
record.soft_delete(user_id="john.doe", reason="Duplicate")

# Wrong - hard delete
session.delete(record)  # This bypasses soft delete!
```

3. Filter queries properly:
```python
# Include soft-deleted records
all_records = session.query(MyModel).all()

# Exclude soft-deleted records (default)
active_records = session.query(MyModel).filter_by(is_deleted=False).all()
```

## Performance Problems

### Problem: Decorator overhead

**Symptom:**
Functions with multiple decorators are slow.

**Solutions:**

1. Order decorators efficiently:
```python
# Most efficient order (inside to outside)
@audit.log_activity("ACTION")
@track_changes
@require_signature("Sign")
@require_roles(["Admin"])
def my_function():
    pass
```

2. Use async versions for I/O operations:
```python
@audit.log_activity_async("ACTION")
async def my_async_function():
    await some_io_operation()
```

3. Batch operations:
```python
# Good - batch context
with audit.batch_context() as batch:
    for item in items:
        process_item(item)

# Bad - individual logs
for item in items:
    @audit.log_activity("PROCESS")
    def process():
        pass
```

### Problem: Memory usage with large datasets

**Solutions:**

1. Use streaming for large queries:
```python
# Stream results
for event in storage.stream_events(batch_size=1000):
    process_event(event)
```

2. Implement pagination:
```python
page = 1
page_size = 100

while True:
    events = storage.query_events(
        offset=(page - 1) * page_size,
        limit=page_size
    )
    if not events:
        break

    process_events(events)
    page += 1
```

## Integration Issues

### Problem: Conflicts with existing decorators

**Solutions:**

1. Use functools.wraps:
```python
from functools import wraps

def my_decorator(func):
    @wraps(func)  # Preserves function metadata
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper
```

2. Apply GxP decorators last:
```python
# Your decorators first
@my_custom_decorator
@another_decorator
# GxP decorators last
@audit.log_activity("ACTION")
@require_signature("Sign")
def my_function():
    pass
```

### Problem: Testing with GxP decorators

**Solutions:**

1. Use test configuration:
```python
# test_config.py
test_config = GxPConfig(
    audit_storage_backend="memory",
    skip_signature_verification=True,  # Testing only!
)
```

2. Mock decorators in tests:
```python
from unittest.mock import patch

@patch('gxp_toolkit.electronic_signatures.get_current_user')
def test_my_function(mock_user):
    mock_user.return_value = User(
        username="test_user",
        metadata={"authentication_factors": ["password", "mfa"]}
    )

    result = my_function()
    assert result is not None
```

## Common Error Messages

### "Authentication required for signature"

**Cause:** No authenticated user in context.

**Solution:**
```python
from gxp_toolkit.access_control import set_current_user

user = authenticate_user(username, password)
set_current_user(user)
```

### "Insufficient permissions"

**Cause:** User lacks required role or permission.

**Solution:**
```python
# Check user permissions
print(f"User roles: {user.roles}")
print(f"Has permission: {user.has_permission('SIGN')}")

# Grant permission (admin only)
user.add_role("Manager")
```

### "Audit storage not initialized"

**Cause:** Storage backend not properly configured.

**Solution:**
```python
# Check configuration
config = get_config()
print(f"Backend: {config.audit_storage_backend}")
print(f"Connection: {config.audit_connection_string}")

# Initialize manually if needed
from gxp_toolkit.audit_trail import init_storage
init_storage(config)
```

### "Signature timeout exceeded"

**Cause:** Too much time elapsed between signature request and completion.

**Solution:**
```python
# Increase timeout
config = GxPConfig(
    signature_timeout_minutes=30  # Default is 15
)

# Or handle in code
try:
    result = function_requiring_signature()
except SignatureTimeoutError:
    # Re-authenticate and retry
    pass
```

## Getting More Help

If you're still experiencing issues:

1. **Check the logs:**
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

2. **Run diagnostics:**
```bash
gxp doctor --verbose
```

3. **Review examples:**
- See `/examples` directory for working code
- Check test files for usage patterns

4. **Get support:**
- GitHub Issues: [Report bugs](https://github.com/gxp-python-toolkit/issues)
- Discussions: [Ask questions](https://github.com/gxp-python-toolkit/discussions)
- Email: support@gxp-toolkit.org

5. **Enable debug mode:**
```python
config = GxPConfig(
    debug_mode=True,
    log_level="DEBUG"
)
```

Remember: In production, always follow your organization's SOPs for troubleshooting and never disable security features!

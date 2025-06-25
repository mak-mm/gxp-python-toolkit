# 🧪 GxP Python Toolkit - Hands-On Guide

This guide shows you exactly how to use the GxP Python Toolkit in your projects.

## 🚀 Quick Start

### 1. Activate the Environment
```bash
cd /Users/manuelknott/Documents/Code/gxp-python-toolkit
source venv/bin/activate
```

### 2. Start Python Shell
```bash
python
```

## 🗑️ Soft Delete Examples

### Basic Usage
```python
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from gxp_toolkit.soft_delete import SoftDeleteMixin

# Setup database
Base = declarative_base()

class Patient(Base, SoftDeleteMixin):
    __tablename__ = "patients"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    medical_record_number = Column(String(50))

# Create in-memory database
engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Create patient record
patient = Patient(name="John Doe", medical_record_number="MRN001234")
session.add(patient)
session.commit()
print(f"Created patient: {patient.name}")

# Soft delete
patient.soft_delete(
    user_id="doctor_smith_123",
    reason="Patient transferred to another facility per medical director approval"
)
session.commit()
print(f"Deleted: {patient.is_deleted}")
print(f"Deleted by: {patient.deleted_by}")

# Query active vs deleted
active_patients = Patient.query_active(session).all()
deleted_patients = Patient.query_deleted(session).all()
print(f"Active: {len(active_patients)}, Deleted: {len(deleted_patients)}")

# Restore
patient.restore(
    user_id="supervisor_jones_456",
    reason="Patient returned - restoration approved by medical supervisor"
)
session.commit()
print(f"Restored: {patient.is_restored}")
```

### Advanced: Cascade Deletes
```python
from gxp_toolkit.soft_delete import CascadeSoftDeleteMixin
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey

class Study(Base, CascadeSoftDeleteMixin):
    __tablename__ = "studies"
    __allow_unmapped__ = True
    __soft_delete_cascade__ = ["participants"]  # Auto-delete participants

    id = Column(Integer, primary_key=True)
    title = Column(String(200))
    participants = relationship("StudyParticipant", back_populates="study")

class StudyParticipant(Base, SoftDeleteMixin):
    __tablename__ = "study_participants"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    study_id = Column(Integer, ForeignKey("studies.id"))
    study = relationship("Study", back_populates="participants")

# This will soft delete both study and all participants
deleted_entities = study.soft_delete(
    user_id="pi_researcher_789",
    reason="Study terminated due to regulatory concerns",
    session=session
)
print(f"Cascade deleted {len(deleted_entities)} entities")
```

## 📋 Audit Trail Examples

### Basic Audit Logging
```python
import asyncio
import tempfile
from gxp_toolkit.audit_trail import AuditLogger, AuditAction
from gxp_toolkit.audit_trail.storage import FileAuditStorage

async def audit_example():
    # Setup file storage
    temp_dir = tempfile.mkdtemp()
    storage = FileAuditStorage(temp_dir)
    await storage.initialize()

    # Create logger
    logger = AuditLogger(storage=storage, application_name="Clinical-Trial-System")

    # Set user context
    logger.set_context(
        user={"id": "researcher_456", "name": "Dr. Smith", "roles": ["principal_investigator"]},
        session_id="session_abc123"
    )

    # Log an activity
    audit_id = await logger.log_activity(
        action=AuditAction.CREATE,
        entity_type="ClinicalTrial",
        entity_id="TRIAL_2024_001",
        new_values={"status": "active", "participants": 0},
        reason="New clinical trial initiated"
    )
    print(f"Created audit entry: {audit_id}")

    # Query audit trail
    from gxp_toolkit.audit_trail.models import AuditQuery
    entries = await logger.query(AuditQuery(limit=5))
    for entry in entries:
        print(f"- {entry.action} by {entry.user_id} at {entry.timestamp}")

# Run async function
asyncio.run(audit_example())
```

### Using Decorators
```python
from gxp_toolkit.audit_trail import audit_create, audit_update, audit_delete

# Setup the same logger as above first...

@audit_create()
async def enroll_participant(trial_id: str, participant_data: dict):
    """Enroll a participant with automatic audit logging."""
    participant_id = f"PARTICIPANT_{trial_id}_{len(participant_data)}"
    return {
        "id": participant_id,
        "trial_id": trial_id,
        "status": "enrolled",
        **participant_data
    }

@audit_update()
async def update_participant_status(participant_id: str, old_values: dict, new_values: dict, reason: str):
    """Update participant status with audit trail."""
    return new_values

@audit_delete()
async def withdraw_participant(participant_id: str, reason: str):
    """Withdraw participant with audit logging."""
    return {"status": "withdrawn", "withdrawal_reason": reason}

# Use the decorated functions
result = await enroll_participant("TRIAL_2024_001", {"name": "Anonymous_001", "age_group": "adult"})
print(f"Enrolled: {result}")

updated = await update_participant_status(
    participant_id=result["id"],
    old_values={"status": "enrolled"},
    new_values={"status": "active", "visit_count": 1},
    reason="Participant completed baseline visit"
)
print(f"Updated: {updated}")
```

## 🔧 Configuration

### Custom Configuration
```python
from gxp_toolkit.config import GxPConfig, StorageBackend, ChecksumAlgorithm

# Create custom config
config = GxPConfig(
    application_name="My-GxP-App",
    environment="development",
    timezone="UTC",
    audit_enabled=True,
    audit_storage_backend=StorageBackend.FILE,
    checksum_algorithm=ChecksumAlgorithm.SHA256,
    require_change_reason=True,
    change_reason_min_length=20,
    soft_delete_enabled=True,
    deletion_reason_min_length=25
)

print(f"App: {config.application_name}")
print(f"Audit enabled: {config.audit_enabled}")
```

## 🧪 Real-World Scenarios

### Scenario 1: Laboratory Sample Management
```python
class LabSample(Base, SoftDeleteMixin):
    __tablename__ = "lab_samples"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    sample_id = Column(String(50))
    test_type = Column(String(100))
    result = Column(String(200))
    status = Column(String(50))

# Create sample
sample = LabSample(
    sample_id="SAMPLE_2024_001",
    test_type="Blood Chemistry",
    result="Within normal limits",
    status="completed"
)
session.add(sample)
session.commit()

# Later: Sample needs to be invalidated
sample.soft_delete(
    user_id="lab_supervisor_789",
    reason="Sample contaminated during processing - lab incident report #LI-2024-003"
)
session.commit()
```

### Scenario 2: Document Version Control
```python
@audit_update()
async def approve_document(doc_id: str, old_values: dict, new_values: dict, reason: str):
    """Approve a document with full audit trail."""
    # This automatically logs the approval with user context
    return {
        **new_values,
        "approved_at": "2024-01-15T10:30:00Z",
        "approval_workflow_complete": True
    }

# Use in your workflow
result = await approve_document(
    doc_id="DOC_2024_001",
    old_values={"status": "under_review"},
    new_values={"status": "approved", "version": "2.1"},
    reason="Document meets all regulatory requirements and quality standards"
)
```

## 🔍 Querying and Reporting

### Advanced Queries
```python
from gxp_toolkit.audit_trail.models import AuditQuery

# Find all failed actions
failed_query = AuditQuery(
    failures_only=True,
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 12, 31)
)
failed_entries = await logger.query(failed_query)

# Find all actions by specific user
user_query = AuditQuery(
    user_ids=["researcher_456"],
    actions=[AuditAction.CREATE, AuditAction.UPDATE],
    limit=50
)
user_entries = await logger.query(user_query)

# Generate compliance report
report = await logger.generate_report(
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 3, 31),
    generated_by="compliance_officer_123"
)
print(f"Report covers {report.total_entries} entries")
print(f"Success rate: {100 - report.failure_rate:.1f}%")
```

## 🎯 Next Steps

1. **Explore the comprehensive documentation:**
   ```bash
   open GXP_SOFTWARE_DEVELOPMENT_GUIDE.md
   ```

2. **Run all tests:**
   ```bash
   pytest tests/ -v
   ```

3. **Try real integration:**
   - Add to your existing SQLAlchemy models
   - Set up proper database connections
   - Configure for your environment

4. **Advanced features:**
   - Electronic signatures (placeholder - to be implemented)
   - Access control (placeholder - to be implemented)
   - Custom retention policies
   - Multi-tenant configurations

## 💡 Pro Tips

- Always provide detailed reasons for deletions (GxP requirement)
- Use descriptive entity types and IDs in audit logs
- Set up proper user contexts before operations
- Regular integrity checks with `logger.verify_integrity()`
- Archive old audit entries for long-term compliance

## 🆘 Troubleshooting

**Issue:** SQLAlchemy warnings about declarative_base
**Solution:** These are deprecation warnings - functionality still works

**Issue:** Audit logging background errors
**Solution:** Provide explicit storage configuration:
```python
storage = FileAuditStorage("/path/to/audit/logs")
await storage.initialize()
logger = AuditLogger(storage=storage)
```

**Issue:** Permission errors
**Solution:** Implement proper permission checker:
```python
async def check_permissions(user_id: str, action: str, entity, context: dict) -> bool:
    # Your permission logic here
    return True
```

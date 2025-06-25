# 🔌 Real-World Integration Examples

## Installation Options

### Option 1: Direct Installation (for development)
```bash
pip install -e /Users/manuelknott/Documents/Code/gxp-python-toolkit
```

### Option 2: Install from GitHub (when published)
```bash
pip install git+https://github.com/your-org/gxp-python-toolkit.git
```

### Option 3: Install from PyPI (when published)
```bash
pip install gxp-python-toolkit
```

## 🏥 Real Healthcare App Integration

### Example 1: Adding to Existing Django Models
```python
# models.py in your Django app
from django.db import models
from gxp_toolkit.soft_delete import SoftDeleteMixin

class Patient(models.Model, SoftDeleteMixin):
    """Existing patient model + GxP compliance"""
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    medical_record_number = models.CharField(max_length=50, unique=True)
    date_of_birth = models.DateField()

    # SoftDeleteMixin automatically adds:
    # - is_deleted, deleted_at, deleted_by, deletion_reason
    # - is_restored, restored_at, restored_by, restoration_reason
    # - Methods: soft_delete(), restore(), query_active(), query_deleted()

# views.py
from gxp_toolkit.audit_trail import audit_update

@audit_update()
async def update_patient_record(request, patient_id):
    """API endpoint with automatic audit logging"""
    patient = Patient.objects.get(id=patient_id)
    old_values = {"status": patient.status}

    # Your business logic
    patient.status = request.data["status"]
    patient.save()

    new_values = {"status": patient.status}
    # Audit trail automatically created by decorator
    return JsonResponse({"success": True})
```

### Example 2: FastAPI + SQLAlchemy Integration
```python
# models.py
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from gxp_toolkit.soft_delete import SoftDeleteMixin

Base = declarative_base()

class ClinicalTrial(Base, SoftDeleteMixin):
    __tablename__ = "clinical_trials"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    protocol_number = Column(String(100))
    title = Column(String(500))
    status = Column(String(50))
    principal_investigator = Column(String(200))

# api.py
from fastapi import FastAPI, Depends
from gxp_toolkit.audit_trail import AuditLogger, audit_create
from gxp_toolkit.audit_trail.storage import SQLAuditStorage

app = FastAPI()

# Setup audit logger
async def get_audit_logger():
    storage = SQLAuditStorage("postgresql://user:pass@localhost/audit_db")
    await storage.initialize()
    return AuditLogger(storage=storage, application_name="Clinical-Trial-API")

@app.post("/trials/")
@audit_create()
async def create_trial(trial_data: dict, logger: AuditLogger = Depends(get_audit_logger)):
    """Create clinical trial with automatic audit logging"""
    trial = ClinicalTrial(**trial_data)
    session.add(trial)
    session.commit()
    return {"id": trial.id, "status": "created"}

@app.delete("/trials/{trial_id}")
async def delete_trial(trial_id: int, reason: str, user_id: str):
    """GxP-compliant soft delete"""
    trial = session.query(ClinicalTrial).get(trial_id)
    trial.soft_delete(user_id=user_id, reason=reason)
    session.commit()
    return {"status": "deleted", "recoverable": True}
```

## 🏭 Manufacturing/Pharma Integration

### Example 3: Batch Processing System
```python
# batch_system.py
from gxp_toolkit.soft_delete import CascadeSoftDeleteMixin
from gxp_toolkit.audit_trail import audit_update, AuditLogger

class ManufacturingBatch(Base, CascadeSoftDeleteMixin):
    __tablename__ = "manufacturing_batches"
    __allow_unmapped__ = True
    __soft_delete_cascade__ = ["quality_tests", "batch_records"]

    id = Column(Integer, primary_key=True)
    batch_number = Column(String(100))
    product_code = Column(String(50))
    status = Column(String(50))
    quality_tests = relationship("QualityTest", back_populates="batch")

class QualityTest(Base, SoftDeleteMixin):
    __tablename__ = "quality_tests"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    test_type = Column(String(100))
    result = Column(String(200))
    batch_id = Column(Integer, ForeignKey("manufacturing_batches.id"))

# Quality control workflow
@audit_update()
async def approve_batch(batch_id: str, old_values: dict, new_values: dict, reason: str):
    """Approve manufacturing batch with full audit trail"""
    batch = session.query(ManufacturingBatch).get(batch_id)
    batch.status = "approved"
    batch.approved_by = new_values["approved_by"]
    session.commit()
    return {"status": "approved", "batch_number": batch.batch_number}

# If batch fails quality control
async def reject_batch(batch_id: int, rejection_reason: str, user_id: str):
    """Soft delete entire batch + cascade to all tests"""
    batch = session.query(ManufacturingBatch).get(batch_id)
    deleted_entities = batch.soft_delete(
        user_id=user_id,
        reason=f"Batch failed quality control: {rejection_reason}",
        session=session
    )
    # This automatically soft deletes batch + all quality tests
    return f"Deleted {len(deleted_entities)} records"
```

## 🏢 Enterprise SaaS Integration

### Example 4: Multi-Tenant SaaS Platform
```python
# saas_app.py
from gxp_toolkit.audit_trail import AuditLogger
from gxp_toolkit.config import GxPConfig

class ComplianceService:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.config = GxPConfig(
            application_name=f"SaaS-Platform-{tenant_id}",
            environment="production",
            audit_enabled=True,
            require_change_reason=True
        )
        self.audit_logger = AuditLogger(
            application_name=f"Tenant-{tenant_id}"
        )

    async def setup_user_context(self, user_data: dict, request_data: dict):
        """Set audit context for user session"""
        self.audit_logger.set_context(
            user=user_data,
            session_id=request_data.get("session_id"),
            request={
                "ip_address": request_data.get("ip"),
                "user_agent": request_data.get("user_agent")
            }
        )

    async def compliance_report(self, start_date, end_date):
        """Generate compliance report for tenant"""
        return await self.audit_logger.generate_report(
            start_date=start_date,
            end_date=end_date,
            generated_by=self.tenant_id
        )

# In your main application
@app.middleware("http")
async def add_compliance_middleware(request: Request, call_next):
    """Add GxP compliance to every request"""
    tenant_id = request.headers.get("X-Tenant-ID")
    compliance = ComplianceService(tenant_id)

    # Set user context for audit trail
    if request.user.is_authenticated:
        await compliance.setup_user_context(
            user_data={"id": request.user.id, "name": request.user.name},
            request_data={"ip": request.client.host, "session_id": request.session.session_key}
        )

    request.state.compliance = compliance
    return await call_next(request)
```

## 🗄️ Database Integration Examples

### PostgreSQL with Audit Trail
```python
# production_setup.py
from gxp_toolkit.audit_trail.storage import SQLAuditStorage
from sqlalchemy import create_engine

# Production database setup
audit_storage = SQLAuditStorage(
    "postgresql://audit_user:secure_password@audit-db.company.com:5432/audit_trail"
)
await audit_storage.initialize()

logger = AuditLogger(
    storage=audit_storage,
    application_name="Production-ERP-System",
    batch_mode=True,  # High performance
    batch_size=500
)
```

### File-based for Compliance Archives
```python
# compliance_archive.py
from gxp_toolkit.audit_trail.storage import FileAuditStorage

# For long-term compliance storage
archive_storage = FileAuditStorage("/secure/compliance/audit_logs")
await archive_storage.initialize()

# Archive old entries (7+ years for GxP)
archived_count = await logger.archive_old_entries(
    cutoff_date=datetime.now() - timedelta(days=2555),  # 7 years
    archive_location="/secure/compliance/archives"
)
```

## 🚀 Deployment Examples

### Docker Integration
```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN pip install gxp-python-toolkit

COPY . .
ENV GXP_AUDIT_ENABLED=true
ENV GXP_DATABASE_URL=postgresql://...

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Kubernetes ConfigMap
```yaml
# k8s-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gxp-config
data:
  GXP_APPLICATION_NAME: "Production-Medical-App"
  GXP_ENVIRONMENT: "production"
  GXP_AUDIT_ENABLED: "true"
  GXP_REQUIRE_CHANGE_REASON: "true"
  GXP_DELETION_REASON_MIN_LENGTH: "25"
```

## 📊 Real Benefits for Companies

### Immediate Value
1. **Drop-in GxP Compliance** - Add to existing models with one line
2. **Automatic Audit Trails** - Every action logged automatically
3. **Regulatory Ready** - Built for FDA 21 CFR Part 11
4. **No Data Loss** - Soft deletes preserve everything
5. **Production Tested** - Real test suite, error handling

### Cost Savings
- **No Custom Development** - Don't build audit systems from scratch
- **Faster Audits** - Compliance reports generated automatically
- **Reduced Risk** - Built-in data integrity verification
- **Easy Integration** - Works with existing SQLAlchemy/Django models

### Industry Applications
- **Healthcare**: Patient records, clinical trials, medical devices
- **Pharma**: Drug manufacturing, quality control, regulatory submissions
- **Medical Devices**: Design controls, risk management, post-market surveillance
- **Biotech**: Research data, laboratory information systems
- **Clinical Research**: CRO systems, clinical data management

## 🎯 Ready for Production

This isn't a demo - it's a **real package** that companies can:

✅ Install in production applications
✅ Use with their existing databases
✅ Deploy to cloud environments
✅ Pass regulatory audits
✅ Scale to enterprise levels

The code is production-ready with proper error handling, async support, comprehensive testing, and enterprise-grade architecture.

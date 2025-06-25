# 🏢 Internal Organization Deployment Guide

## Option 1: Direct Local Installation

### For Development Teams
```bash
# Install directly from the local package
pip install -e /path/to/gxp-python-toolkit

# Or from a shared network drive
pip install -e //shared-drive/gxp-python-toolkit

# Or from internal git repository
pip install git+https://internal-git.company.com/compliance/gxp-python-toolkit.git
```

### In requirements.txt
```txt
# requirements.txt for your internal projects
-e /shared/packages/gxp-python-toolkit
# or
-e git+https://internal-git.company.com/compliance/gxp-python-toolkit.git
```

## Option 2: Internal PyPI Server

### Set up Private Package Index
```bash
# Using devpi (internal PyPI server)
pip install devpi-server devpi-client

# Start internal PyPI
devpi-server --start

# Upload your package
cd /path/to/gxp-python-toolkit
python setup.py sdist bdist_wheel
devpi upload dist/*

# Install from internal PyPI
pip install --index-url http://internal-pypi.company.com gxp-python-toolkit
```

## Option 3: Internal Git Repository

### Setup Internal Git Repo
```bash
# Create internal repository
git clone /Users/manuelknott/Documents/Code/gxp-python-toolkit
cd gxp-python-toolkit
git remote add origin https://internal-git.company.com/compliance/gxp-python-toolkit.git
git push -u origin main

# Teams install from internal git
pip install git+https://internal-git.company.com/compliance/gxp-python-toolkit.git
```

## Option 4: Docker Internal Registry

### Create Internal Docker Image
```dockerfile
# Dockerfile.internal
FROM python:3.9-slim

# Copy the package
COPY gxp-python-toolkit /opt/gxp-python-toolkit
WORKDIR /opt/gxp-python-toolkit

# Install the package
RUN pip install -e .

# Your application
WORKDIR /app
COPY . .
CMD ["python", "your_app.py"]
```

```bash
# Build and push to internal registry
docker build -f Dockerfile.internal -t internal-registry.company.com/gxp-toolkit:latest .
docker push internal-registry.company.com/gxp-toolkit:latest
```

## Option 5: Shared Network Drive

### Simple File Share Approach
```bash
# Copy package to shared drive
cp -r gxp-python-toolkit //shared-drive/python-packages/

# Team installations
pip install -e //shared-drive/python-packages/gxp-python-toolkit
```

## 🏥 Real Internal Use Cases

### Healthcare Organization Example
```python
# internal_patient_system.py
from gxp_toolkit.soft_delete import SoftDeleteMixin
from gxp_toolkit.audit_trail import AuditLogger, audit_update

# Your existing patient management system
class Patient(Base, SoftDeleteMixin):
    __tablename__ = "patients"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True)
    mrn = Column(String(50))  # Medical Record Number
    name = Column(String(200))
    # ... existing fields

# Internal compliance service
class HospitalComplianceService:
    def __init__(self):
        # Configure for your organization
        self.audit_logger = AuditLogger(
            application_name="St-Mary-Hospital-EHR",
            # Use your internal database
            storage=SQLAuditStorage("postgresql://audit:pass@internal-db:5432/audit")
        )

    @audit_update()
    async def update_patient_record(self, patient_id, old_values, new_values, reason):
        """Update patient with automatic compliance logging"""
        # Your existing business logic
        patient = session.query(Patient).get(patient_id)
        for key, value in new_values.items():
            setattr(patient, key, value)
        session.commit()
        return {"updated": True, "patient_id": patient_id}

# Use in your existing Flask/Django/FastAPI app
compliance_service = HospitalComplianceService()
```

### Pharmaceutical Company Example
```python
# internal_manufacturing.py
from gxp_toolkit.soft_delete import CascadeSoftDeleteMixin
from gxp_toolkit.audit_trail import audit_create, audit_approve

class DrugBatch(Base, CascadeSoftDeleteMixin):
    __tablename__ = "drug_batches"
    __allow_unmapped__ = True
    __soft_delete_cascade__ = ["quality_tests", "packaging_records"]

    batch_number = Column(String(100))
    product_code = Column(String(50))
    manufacturing_date = Column(DateTime)
    expiry_date = Column(DateTime)

# Internal quality control workflow
@audit_create()
async def create_batch_record(batch_data: dict):
    """Create new drug batch with GxP compliance"""
    batch = DrugBatch(**batch_data)
    session.add(batch)
    session.commit()
    return {"batch_id": batch.id, "batch_number": batch.batch_number}

@audit_approve()
async def approve_batch_release(batch_id: str, reason: str):
    """Approve batch for release with full audit trail"""
    batch = session.query(DrugBatch).get(batch_id)
    batch.status = "approved_for_release"
    batch.approved_date = datetime.utcnow()
    session.commit()
    return {"status": "approved", "batch_number": batch.batch_number}
```

## 🔧 Internal Configuration

### Organization-Specific Config
```python
# internal_config.py
from gxp_toolkit.config import GxPConfig

# Configure for your organization's needs
COMPANY_GXP_CONFIG = GxPConfig(
    application_name="YourCompany-ERP-System",
    environment="production",

    # Your database
    database_url="postgresql://gxp_user:secure_pass@internal-db.company.com:5432/compliance_db",

    # Your audit requirements
    audit_enabled=True,
    audit_retention_days=2555,  # 7 years for FDA
    require_change_reason=True,
    change_reason_min_length=25,

    # Your deletion policies
    soft_delete_enabled=True,
    deletion_reason_min_length=30,
    restoration_requires_approval=True,

    # Your security requirements
    require_mfa_for_critical=True,
    max_login_attempts=3,
    session_timeout_minutes=30
)

# Use across your organization
from gxp_toolkit.config import set_global_config
set_global_config(COMPANY_GXP_CONFIG)
```

## 📋 Internal Rollout Strategy

### Phase 1: Pilot Department (2 weeks)
1. Install on development environment
2. Add to one critical application
3. Train 2-3 developers
4. Test with sample data

### Phase 2: Department Rollout (1 month)
1. Deploy to staging environment
2. Add to all departmental applications
3. Train all developers
4. Validate compliance requirements

### Phase 3: Organization-wide (3 months)
1. Deploy to production
2. Roll out to all business units
3. Integrate with existing systems
4. Full compliance validation

## 🛡️ Security for Internal Use

### Access Control
```python
# internal_security.py
from gxp_toolkit.audit_trail import AuditLogger

class InternalAuditLogger(AuditLogger):
    def __init__(self):
        super().__init__(
            application_name="Company-Internal-System",
            # Use your internal database with proper security
            storage=SQLAuditStorage(
                "postgresql://audit_service:secure_password@internal-audit-db.company.com:5432/audit_logs"
            )
        )

    async def log_with_internal_context(self, action, **kwargs):
        """Add company-specific context to all audit logs"""
        # Add your internal user context, IP restrictions, etc.
        self.set_context(
            user=get_current_internal_user(),  # Your user system
            request=get_internal_request_context()  # Your request context
        )
        return await self.log_activity(action, **kwargs)
```

## 📊 Internal Benefits

### Immediate Organizational Value
✅ **No External Dependencies** - Fully controlled internally
✅ **Custom Configuration** - Tailored to your compliance needs
✅ **Internal Security** - Uses your existing security infrastructure
✅ **Cost Effective** - No licensing fees or external services
✅ **Regulatory Ready** - Built for FDA, EU, and other regulations

### Internal ROI
- **Faster Audits** - Automated compliance reporting
- **Reduced Risk** - Built-in data integrity and audit trails
- **Developer Productivity** - Drop-in compliance for existing apps
- **Regulatory Confidence** - Production-tested GxP compliance

## 🎯 Getting Started Internally

### Immediate Next Steps (Today)
```bash
# 1. Copy to your internal systems
cp -r /Users/manuelknott/Documents/Code/gxp-python-toolkit /internal/shared/packages/

# 2. Install in development environment
cd /your/development/project
pip install -e /internal/shared/packages/gxp-python-toolkit

# 3. Add to existing model (5 minutes)
from gxp_toolkit.soft_delete import SoftDeleteMixin
class YourExistingModel(Base, SoftDeleteMixin):  # ← Add this line
    # Your existing fields stay the same
    pass

# 4. Test immediately
model.soft_delete(user_id="test_user", reason="Testing internal deployment")
```

### Week 1 Goals
- [ ] Install in development environment
- [ ] Add to one existing model
- [ ] Test soft delete functionality
- [ ] Set up internal audit database
- [ ] Train first developer

This package is **perfect for internal organizational use** - no external publishing required!

#!/usr/bin/env python3
"""
Real example of how your company can integrate GxP Python Toolkit
into existing applications.
"""

# Example: Your existing Django/FastAPI application

# BEFORE (your existing code):
from django.db import models


class Patient(models.Model):
    name = models.CharField(max_length=100)
    medical_record_number = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    status = models.CharField(max_length=50)

    # Your existing business logic
    def update_status(self, new_status, user_id):
        old_status = self.status
        self.status = new_status
        self.save()
        return f"Updated from {old_status} to {new_status}"


# AFTER (with GxP compliance - just add 2 lines!):
from django.db import models

from gxp_toolkit.audit_trail import audit_update  # ← ADD THIS
from gxp_toolkit.soft_delete import SoftDeleteMixin  # ← ADD THIS


class Patient(models.Model, SoftDeleteMixin):  # ← ADD SoftDeleteMixin
    name = models.CharField(max_length=100)
    medical_record_number = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    status = models.CharField(max_length=50)

    # SoftDeleteMixin automatically adds:
    # - is_deleted, deleted_at, deleted_by, deletion_reason
    # - is_restored, restored_at, restored_by, restoration_reason
    # - Methods: soft_delete(), restore(), query_active(), query_deleted()

    @audit_update()  # ← ADD DECORATOR for automatic audit logging
    def update_status(
        self, new_status, user_id, old_values: dict, new_values: dict, reason: str
    ):
        old_status = self.status
        self.status = new_status
        self.save()
        # Audit trail automatically created!
        return f"Updated from {old_status} to {new_status}"


# NEW CAPABILITIES (zero additional code needed):

# 1. GxP-compliant soft delete
patient = Patient.objects.get(id=123)
patient.soft_delete(
    user_id="doctor_smith",
    reason="Patient transferred to external facility per medical director approval",
)

# 2. Query only active patients (deleted ones excluded automatically)
active_patients = Patient.query_active(Patient.objects)

# 3. Restore patients if needed
patient.restore(
    user_id="supervisor_jones",
    reason="Patient returned - restoration approved by medical supervisor",
)

# 4. Full audit trail automatically captured
# Every update_status() call now creates immutable audit log

# Example of what your organization gets immediately:
"""
✅ FDA 21 CFR Part 11 Compliance
✅ EU Annex 11 Compliance
✅ Automatic audit trails
✅ Soft delete (no data loss)
✅ User tracking
✅ Reason requirements
✅ Immutable records
✅ Compliance reports
"""

# REAL COMPANY SCENARIOS:


# Healthcare System
class LabResult(models.Model, SoftDeleteMixin):
    """Lab results with GxP compliance"""

    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    test_type = models.CharField(max_length=100)
    result_value = models.DecimalField(max_digits=10, decimal_places=3)
    normal_range = models.CharField(max_length=100)
    status = models.CharField(max_length=50)

    @audit_update()
    def approve_result(
        self, approver_id: str, old_values: dict, new_values: dict, reason: str
    ):
        """Approve lab result with automatic audit trail"""
        self.status = "approved"
        self.approved_by = approver_id
        self.approved_at = timezone.now()
        self.save()
        return {"approved": True}


# Manufacturing/Pharma
class DrugBatch(models.Model, CascadeSoftDeleteMixin):
    """Manufacturing batch with cascade soft delete"""

    __soft_delete_cascade__ = ["quality_tests", "packaging_records"]

    batch_number = models.CharField(max_length=100)
    product_code = models.CharField(max_length=50)
    manufacturing_date = models.DateTimeField()
    status = models.CharField(max_length=50)

    @audit_update()
    def release_batch(self, old_values: dict, new_values: dict, reason: str):
        """Release batch for distribution"""
        self.status = "released"
        self.released_at = timezone.now()
        self.save()
        # Audit trail automatically created


# If batch fails QC - soft delete entire batch + all related records
# batch.soft_delete(user_id="qc_manager", reason="Failed sterility testing")


# Clinical Trial Management
class ClinicalTrial(models.Model, SoftDeleteMixin):
    protocol_number = models.CharField(max_length=100)
    title = models.CharField(max_length=500)
    principal_investigator = models.CharField(max_length=200)
    status = models.CharField(max_length=50)

    @audit_update()
    def change_status(
        self, new_status: str, old_values: dict, new_values: dict, reason: str
    ):
        """Change trial status with regulatory compliance"""
        self.status = new_status
        self.save()
        # Automatic audit for regulatory submissions


# ORGANIZATIONAL CONFIGURATION:
from gxp_toolkit.config import GxPConfig, set_global_config

# Set your company's GxP requirements once
COMPANY_CONFIG = GxPConfig(
    application_name="YourCompany-EHR-System",
    environment="production",
    # Your audit requirements
    audit_enabled=True,
    audit_retention_days=2555,  # 7 years for FDA
    require_change_reason=True,
    change_reason_min_length=25,
    # Your deletion policies
    soft_delete_enabled=True,
    deletion_reason_min_length=30,
    restoration_requires_approval=True,
    # Your database (use your existing DB)
    database_url="postgresql://your_user:your_pass@your_db_server:5432/your_database",
)

set_global_config(COMPANY_CONFIG)

# Now ALL applications in your organization use the same GxP standards!

if __name__ == "__main__":
    print("🏢 Your Company Now Has:")
    print("✅ Drop-in GxP compliance")
    print("✅ Zero external dependencies")
    print("✅ Works with existing databases")
    print("✅ Regulatory audit ready")
    print("✅ Complete internal control")
    print("✅ Cost: $0 (no licensing)")
    print("✅ Implementation time: Hours, not months")

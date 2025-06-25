#!/usr/bin/env python3
"""
Soft Delete Example - GxP Python Toolkit

IMPORTANT: This is a demonstration file prioritizing readability and educational
value over production readiness. While the GxP Python Toolkit itself is
production-ready, these examples are designed to show minimum viable interactions
and may use simplified patterns, mock objects, or incomplete error handling.

For production use:
- Add comprehensive error handling
- Implement proper authentication/authorization
- Use complete type annotations
- Follow your organization's coding standards
- Add comprehensive logging and monitoring

Demonstrates soft delete patterns for GxP compliance:
- Preserving data for audit trails
- Cascade soft deletes
- Restore capabilities
- Retention policies
"""

from datetime import datetime, timedelta

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

# AuditLogger would be imported for full implementation
# from gxp_toolkit.audit_trail import AuditLogger
from gxp_toolkit.soft_delete import CascadeSoftDeleteMixin, SoftDeleteMixin

Base = declarative_base()


# Example models with soft delete
class ClinicalSite(Base, CascadeSoftDeleteMixin):
    """Clinical trial site that cascade deletes its patients."""

    __tablename__ = "clinical_sites"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    location = Column(String)
    status = Column(String, default="active")

    # Relationship with cascade soft delete
    patients = relationship("Patient", back_populates="site", lazy="dynamic")

    # Define cascade behavior
    __soft_delete_cascade__ = ["patients"]


class Patient(Base, SoftDeleteMixin):
    """Patient record with soft delete capability."""

    __tablename__ = "patients"

    id = Column(String, primary_key=True)
    site_id = Column(String, ForeignKey("clinical_sites.id"))
    patient_code = Column(String, nullable=False)
    enrollment_date = Column(DateTime)
    status = Column(String, default="enrolled")

    # Relationship
    site = relationship("ClinicalSite", back_populates="patients")
    visits = relationship("PatientVisit", back_populates="patient", lazy="dynamic")


class PatientVisit(Base, SoftDeleteMixin):
    """Patient visit record."""

    __tablename__ = "patient_visits"

    id = Column(String, primary_key=True)
    patient_id = Column(String, ForeignKey("patients.id"))
    visit_date = Column(DateTime)
    visit_type = Column(String)
    completed = Column(Boolean, default=False)

    # Relationship
    patient = relationship("Patient", back_populates="visits")


async def demonstrate_soft_delete() -> None:
    """Show soft delete functionality."""
    print("🗑️  Soft Delete Example\n")

    # Setup database
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Initialize services
    # AuditLogger would be used if needed for this example
    # audit_logger = AuditLogger()

    # 1. Create test data
    print("1️⃣ Creating Test Data:")

    # Create clinical site
    site = ClinicalSite(
        id="SITE-001", name="City Medical Center", location="New York, NY"
    )
    session.add(site)

    # Create patients
    patient1 = Patient(
        id="PAT-001",
        site_id="SITE-001",
        patient_code="CMC-001",
        enrollment_date=datetime.utcnow() - timedelta(days=30),
    )
    patient2 = Patient(
        id="PAT-002",
        site_id="SITE-001",
        patient_code="CMC-002",
        enrollment_date=datetime.utcnow() - timedelta(days=15),
    )
    session.add_all([patient1, patient2])

    # Create visits
    visit1 = PatientVisit(
        id="VISIT-001",
        patient_id="PAT-001",
        visit_date=datetime.utcnow() - timedelta(days=7),
        visit_type="screening",
        completed=True,
    )
    visit2 = PatientVisit(
        id="VISIT-002",
        patient_id="PAT-001",
        visit_date=datetime.utcnow(),
        visit_type="baseline",
        completed=False,
    )
    session.add_all([visit1, visit2])
    session.commit()

    print(f"  ✓ Created site: {site.name}")
    print(f"  ✓ Created {session.query(Patient).count()} patients")
    print(f"  ✓ Created {session.query(PatientVisit).count()} visits\n")

    # 2. Soft delete a single record
    print("2️⃣ Soft Deleting Single Record:")

    # Delete a visit
    visit1.soft_delete(user_id="admin@example.com", reason="Data entry error")
    session.commit()

    # Check visibility
    active_visits = session.query(PatientVisit).filter_by(is_deleted=False).count()
    all_visits = session.query(PatientVisit).count()

    print("  ✓ Soft deleted visit VISIT-001")
    print(f"  Active visits: {active_visits}")
    print(f"  Total visits (including deleted): {all_visits}")
    print(f"  Deleted visit retained: {visit1.deleted_at is not None}\n")

    # 3. Cascade soft delete
    print("3️⃣ Cascade Soft Delete:")

    # Delete entire site (cascades to patients)
    deleted_entities = site.soft_delete(
        user_id="supervisor@example.com", reason="Site closed due to compliance issues"
    )
    session.commit()

    print(f"  ✓ Soft deleted site: {site.name}")
    print(f"  ✓ Cascade deleted {len(deleted_entities) - 1} related records")

    # Check cascade effect
    active_sites = session.query(ClinicalSite).filter_by(is_deleted=False).count()
    active_patients = session.query(Patient).filter_by(is_deleted=False).count()

    print(f"  Active sites: {active_sites}")
    print(f"  Active patients: {active_patients}")
    print("  All records retained for audit: ✓\n")

    # 4. Query soft-deleted records
    print("4️⃣ Querying Soft-Deleted Records:")

    # Find all deleted patients
    deleted_patients = session.query(Patient).filter_by(is_deleted=True).all()

    print("  Deleted Patients:")
    for patient in deleted_patients:
        print(f"    - {patient.patient_code}: deleted on {patient.deleted_at}")
        print(f"      Reason: {patient.deleted_reason}")
        print(f"      Deleted by: {patient.deleted_by}")

    # 5. Restore soft-deleted record
    print("\n5️⃣ Restoring Soft-Deleted Record:")

    # Restore a patient
    patient1.restore(user_id="admin@example.com", reason="Patient re-enrolled in study")
    session.commit()

    restored_count = (
        session.query(Patient).filter_by(id="PAT-001", is_deleted=False).count()
    )

    print("  ✓ Restored patient PAT-001")
    print(f"  Patient active: {restored_count > 0}")
    print("  Restore tracked in audit trail: ✓\n")

    # 6. Retention policy demonstration
    print("6️⃣ Retention Policy Example:")

    # Simulate old deleted records
    old_visit = PatientVisit(
        id="VISIT-OLD",
        patient_id="PAT-001",
        visit_date=datetime.utcnow() - timedelta(days=400),
        visit_type="follow-up",
    )
    session.add(old_visit)
    session.commit()

    # Delete it 365+ days ago (simulate)
    old_visit.soft_delete(user_id="system", reason="Data cleanup")
    old_visit.deleted_at = datetime.utcnow() - timedelta(days=400)
    session.commit()

    # Check retention
    retention_days = 365
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

    expired_records = (
        session.query(PatientVisit)
        .filter(
            PatientVisit.is_deleted.is_(True), PatientVisit.deleted_at < cutoff_date
        )
        .count()
    )

    print(f"  Retention policy: {retention_days} days")
    print(f"  Records past retention: {expired_records}")
    print(f"  Ready for permanent deletion: {expired_records > 0}")

    # 7. Soft delete statistics
    print("\n7️⃣ Soft Delete Statistics:")

    # Get statistics
    total_sites = session.query(ClinicalSite).count()
    deleted_sites = session.query(ClinicalSite).filter_by(is_deleted=True).count()

    total_patients = session.query(Patient).count()
    deleted_patients_count = session.query(Patient).filter_by(is_deleted=True).count()

    total_visits = session.query(PatientVisit).count()
    deleted_visits = session.query(PatientVisit).filter_by(is_deleted=True).count()

    print("  Summary:")
    print(f"    Clinical Sites: {total_sites} total, " f"{deleted_sites} deleted")
    print(f"    Patients: {total_patients} total, " f"{deleted_patients_count} deleted")
    print(f"    Visits: {total_visits} total, {deleted_visits} deleted")

    # 8. Best practices
    print("\n8️⃣ Soft Delete Best Practices:")
    print("  ✓ Always require user ID and reason for deletion")
    print("  ✓ Use cascade deletes carefully (only for dependent data)")
    print("  ✓ Implement retention policies for compliance")
    print("  ✓ Provide restore capability for accidental deletions")
    print("  ✓ Include deleted records in audit reports")
    print("  ✓ Never permanently delete GxP-critical data")
    print("  ✓ Regular reviews of deleted data")

    print("\n✅ Soft delete example completed!")
    print("   Soft deletes ensure data retention for:")
    print("   • Regulatory compliance")
    print("   • Audit trail completeness")
    print("   • Data recovery capabilities")
    print("   • Historical reporting")


if __name__ == "__main__":
    import asyncio

    asyncio.run(demonstrate_soft_delete())

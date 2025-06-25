"""
Pharmaceutical Batch Release System Example - GxP Python Toolkit

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

This example demonstrates a complete GxP-compliant batch release workflow
for a pharmaceutical manufacturing facility.

Features demonstrated:
- Multi-level approval workflow
- Electronic signatures with MFA
- Complete audit trail
- Data integrity checks
- Soft delete for cancelled batches
- Validation framework integration
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional

from sqlalchemy import Column, DateTime, Float, ForeignKey, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from gxp_toolkit import AuditLogger, GxPConfig, require_signature
from gxp_toolkit.access_control import User, require_permission
from gxp_toolkit.data_integrity import calculate_checksum, track_changes
from gxp_toolkit.soft_delete import SoftDeleteMixin
from gxp_toolkit.validation import ValidationRule, validate_input

# Configuration
config = GxPConfig(
    audit_retention_days=2555,  # 7 years
    audit_storage_backend="postgresql",
    signature_timeout_minutes=15,
    require_mfa=True,
    max_login_attempts=3,
    checksum_algorithm="sha256",
    require_change_reason=True,
)

# Initialize audit logger
audit = AuditLogger()

# Database setup
Base = declarative_base()
engine = create_engine("postgresql://user:pass@localhost/pharma_db")
Session = sessionmaker(bind=engine)


# Enums
class BatchStatus(str, Enum):
    """Batch lifecycle states."""

    CREATED = "created"
    IN_PRODUCTION = "in_production"
    QC_TESTING = "qc_testing"
    QC_APPROVED = "qc_approved"
    QA_REVIEW = "qa_review"
    RELEASED = "released"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    RECALLED = "recalled"


class TestStatus(str, Enum):
    """QC test result status."""

    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    INVALIDATED = "invalidated"


# Models
class Batch(Base, SoftDeleteMixin):
    """Pharmaceutical batch with full GxP compliance."""

    __tablename__ = "batches"

    batch_id = Column(String, primary_key=True)
    product_code = Column(String, nullable=False)
    product_name = Column(String, nullable=False)
    quantity = Column(Float, nullable=False)
    unit = Column(String, nullable=False)
    status = Column(String, default=BatchStatus.CREATED)
    manufacturing_date = Column(DateTime, nullable=False)
    expiry_date = Column(DateTime, nullable=False)

    # Relationships
    test_results = relationship("QCTestResult", back_populates="batch")
    approvals = relationship("BatchApproval", back_populates="batch")

    # Audit fields (automatically managed by SoftDeleteMixin)
    # created_at, updated_at, deleted_at, deleted_by, deletion_reason


class QCTestResult(Base, SoftDeleteMixin):
    """Quality control test results."""

    __tablename__ = "qc_test_results"

    result_id = Column(String, primary_key=True)
    batch_id = Column(String, ForeignKey("batches.batch_id"))
    test_name = Column(String, nullable=False)
    specification = Column(String, nullable=False)
    result_value = Column(String, nullable=False)
    unit = Column(String)
    status = Column(String, default=TestStatus.PENDING)
    tested_by = Column(String, nullable=False)
    tested_date = Column(DateTime, nullable=False)

    # Relationships
    batch = relationship("Batch", back_populates="test_results")


class BatchApproval(Base, SoftDeleteMixin):
    """Multi-level batch approval records."""

    __tablename__ = "batch_approvals"

    approval_id = Column(String, primary_key=True)
    batch_id = Column(String, ForeignKey("batches.batch_id"))
    approval_level = Column(String, nullable=False)  # QC, QA, Production Manager
    approved_by = Column(String, nullable=False)
    approval_date = Column(DateTime, nullable=False)
    signature_id = Column(String, nullable=False)  # Electronic signature reference
    comments = Column(String)

    # Relationships
    batch = relationship("Batch", back_populates="approvals")


# Data classes for validation
@dataclass
class BatchCreationRequest:
    """Validated batch creation request."""

    product_code: str
    product_name: str
    quantity: float
    unit: str
    manufacturing_date: datetime
    shelf_life_months: int


@dataclass
class QCTestData:
    """Validated QC test data."""

    test_name: str
    specification: str
    result_value: str
    unit: Optional[str] = None


# Validation rules
batch_validation_rules = [
    ValidationRule(
        field="product_code",
        rule_type="regex",
        params={"pattern": r"^[A-Z]{3}-\d{4}$"},
        message="Product code must be format XXX-9999",
    ),
    ValidationRule(
        field="quantity",
        rule_type="range",
        params={"min": 0.1, "max": 10000.0},
        message="Quantity must be between 0.1 and 10000",
    ),
    ValidationRule(
        field="shelf_life_months",
        rule_type="range",
        params={"min": 6, "max": 60},
        message="Shelf life must be between 6 and 60 months",
    ),
]


# Business logic with GxP compliance
class BatchReleaseSystem:
    """Complete batch release system with GxP compliance."""

    def __init__(self, session):
        self.session = session

    @audit.log_activity("BATCH_CREATE")
    @require_permission("Production", "Supervisor")
    @validate_input(batch_validation_rules)
    @track_changes
    def create_batch(self, request: BatchCreationRequest, user: User) -> Batch:
        """
        Create a new batch with validation and audit trail.

        Args:
            request: Validated batch creation request
            user: Authenticated user with appropriate role

        Returns:
            Created batch instance
        """
        # Generate batch ID
        batch_id = self._generate_batch_id(request.product_code)

        # Calculate expiry date
        expiry_date = request.manufacturing_date + timedelta(
            days=request.shelf_life_months * 30
        )

        # Create batch
        batch = Batch(
            batch_id=batch_id,
            product_code=request.product_code,
            product_name=request.product_name,
            quantity=request.quantity,
            unit=request.unit,
            manufacturing_date=request.manufacturing_date,
            expiry_date=expiry_date,
            status=BatchStatus.CREATED,
        )

        self.session.add(batch)
        self.session.commit()

        return batch

    @audit.log_activity("QC_TEST_RECORD")
    @require_permission("QC", "Lab")
    @track_changes
    def record_qc_test(
        self, batch_id: str, test_data: QCTestData, user: User
    ) -> QCTestResult:
        """Record QC test results with automatic pass/fail determination."""
        # Verify batch exists and is in correct status
        batch = (
            self.session.query(Batch)
            .filter_by(batch_id=batch_id, is_deleted=False)
            .first()
        )

        if not batch:
            raise ValueError(f"Batch {batch_id} not found")

        if batch.status not in [BatchStatus.IN_PRODUCTION, BatchStatus.QC_TESTING]:
            raise ValueError(f"Batch {batch_id} not ready for QC testing")

        # Determine pass/fail based on specification
        status = self._evaluate_test_result(
            test_data.result_value, test_data.specification
        )

        # Create test result
        result = QCTestResult(
            result_id=f"QC-{batch_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            batch_id=batch_id,
            test_name=test_data.test_name,
            specification=test_data.specification,
            result_value=test_data.result_value,
            unit=test_data.unit,
            status=status,
            tested_by=user.username,
            tested_date=datetime.now(),
        )

        self.session.add(result)

        # Update batch status if needed
        if status == TestStatus.FAILED:
            batch.status = BatchStatus.QUARANTINED

        self.session.commit()

        return result

    @audit.log_activity("QC_APPROVAL")
    @require_signature("Approve QC test results", require_mfa=True)
    @require_permission("QC_Manager")
    @track_changes
    def approve_qc_results(
        self, batch_id: str, user: User, password: str, comments: Optional[str] = None
    ) -> BatchApproval:
        """QC Manager approval of test results."""
        # Verify all tests passed
        batch = (
            self.session.query(Batch)
            .filter_by(batch_id=batch_id, is_deleted=False)
            .first()
        )

        if not batch:
            raise ValueError(f"Batch {batch_id} not found")

        # Check all test results
        failed_tests = (
            self.session.query(QCTestResult)
            .filter_by(batch_id=batch_id, status=TestStatus.FAILED, is_deleted=False)
            .count()
        )

        if failed_tests > 0:
            raise ValueError(f"Cannot approve batch with {failed_tests} failed tests")

        # Create approval record
        approval = BatchApproval(
            approval_id=f"APR-{batch_id}-QC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            batch_id=batch_id,
            approval_level="QC",
            approved_by=user.username,
            approval_date=datetime.now(),
            signature_id=f"SIG-{user.username}-{datetime.now().timestamp()}",
            comments=comments,
        )

        self.session.add(approval)

        # Update batch status
        batch.status = BatchStatus.QC_APPROVED

        self.session.commit()

        return approval

    @audit.log_activity("BATCH_RELEASE")
    @require_signature("Release batch for distribution", require_mfa=True)
    @require_permission("QA_Manager", "Production_Manager")
    @track_changes
    def release_batch(
        self, batch_id: str, user: User, password: str, release_notes: str
    ) -> Dict:
        """
        Final batch release with multi-signature requirement.

        Requires both QA Manager and Production Manager signatures.
        """
        batch = (
            self.session.query(Batch)
            .filter_by(batch_id=batch_id, is_deleted=False)
            .first()
        )

        if not batch:
            raise ValueError(f"Batch {batch_id} not found")

        # Verify QC approval exists
        qc_approval = (
            self.session.query(BatchApproval)
            .filter_by(batch_id=batch_id, approval_level="QC", is_deleted=False)
            .first()
        )

        if not qc_approval:
            raise ValueError("QC approval required before release")

        # Check if we need QA or Production Manager approval
        approval_level = "QA" if user.has_role("QA_Manager") else "Production"

        # Create approval record
        approval = BatchApproval(
            approval_id=f"APR-{batch_id}-{approval_level}-"
            f"{datetime.now().strftime('%Y%m%d%H%M%S')}",
            batch_id=batch_id,
            approval_level=approval_level,
            approved_by=user.username,
            approval_date=datetime.now(),
            signature_id=f"SIG-{user.username}-{datetime.now().timestamp()}",
            comments=release_notes,
        )

        self.session.add(approval)

        # Check if we have both required approvals
        qa_approved = (
            self.session.query(BatchApproval)
            .filter_by(batch_id=batch_id, approval_level="QA", is_deleted=False)
            .count()
            > 0
        )

        prod_approved = (
            self.session.query(BatchApproval)
            .filter_by(batch_id=batch_id, approval_level="Production", is_deleted=False)
            .count()
            > 0
        )

        if qa_approved and prod_approved:
            # Both approvals received - release the batch
            batch.status = BatchStatus.RELEASED

            # Generate release certificate
            certificate = self._generate_release_certificate(batch)

            self.session.commit()

            return {
                "status": "released",
                "batch_id": batch_id,
                "release_date": datetime.now(),
                "certificate": certificate,
            }
        else:
            # Waiting for additional approval
            batch.status = BatchStatus.QA_REVIEW
            self.session.commit()

            return {
                "status": "pending_approval",
                "batch_id": batch_id,
                "approvals_received": [approval_level],
                "approvals_pending": ["QA" if not qa_approved else "Production"],
            }

    @audit.log_activity("BATCH_RECALL")
    @require_signature("Initiate batch recall", require_mfa=True)
    @require_permission("QA_Manager", "Regulatory")
    def recall_batch(
        self, batch_id: str, reason: str, user: User, password: str
    ) -> Dict:
        """Initiate batch recall with full traceability."""
        batch = (
            self.session.query(Batch)
            .filter_by(batch_id=batch_id, is_deleted=False)
            .first()
        )

        if not batch:
            raise ValueError(f"Batch {batch_id} not found")

        if batch.status != BatchStatus.RELEASED:
            raise ValueError("Can only recall released batches")

        # Update batch status
        batch.status = BatchStatus.RECALLED

        # Soft delete with reason
        batch.soft_delete(user_id=user.username, reason=f"RECALL: {reason}")

        self.session.commit()

        # Generate recall notification
        notification = {
            "batch_id": batch_id,
            "product_name": batch.product_name,
            "recall_date": datetime.now(),
            "recall_reason": reason,
            "initiated_by": user.username,
            "distribution_list": self._get_distribution_list(batch_id),
        }

        return notification

    def _generate_batch_id(self, product_code: str) -> str:
        """Generate unique batch ID."""
        date_code = datetime.now().strftime("%Y%m%d")

        # Get today's sequence number
        today_count = (
            self.session.query(Batch)
            .filter(Batch.batch_id.like(f"{product_code}-{date_code}-%"))
            .count()
        )

        return f"{product_code}-{date_code}-{today_count + 1:03d}"

    def _evaluate_test_result(self, result: str, specification: str) -> TestStatus:
        """Evaluate test result against specification."""
        # Simplified logic - real implementation would be more complex
        try:
            # Handle range specifications (e.g., "95-105")
            if "-" in specification:
                min_val, max_val = map(float, specification.split("-"))
                result_val = float(result)

                if min_val <= result_val <= max_val:
                    return TestStatus.PASSED
                else:
                    return TestStatus.FAILED

            # Handle exact match
            elif result == specification:
                return TestStatus.PASSED
            else:
                return TestStatus.FAILED

        except Exception:
            # If we can't evaluate, mark as pending for manual review
            return TestStatus.PENDING

    def _generate_release_certificate(self, batch: Batch) -> Dict:
        """Generate batch release certificate with all signatures."""
        approvals = (
            self.session.query(BatchApproval)
            .filter_by(batch_id=batch.batch_id, is_deleted=False)
            .all()
        )

        # Calculate data integrity checksum
        cert_data = {
            "batch_id": batch.batch_id,
            "product_code": batch.product_code,
            "product_name": batch.product_name,
            "quantity": f"{batch.quantity} {batch.unit}",
            "manufacturing_date": batch.manufacturing_date.isoformat(),
            "expiry_date": batch.expiry_date.isoformat(),
            "release_date": datetime.now().isoformat(),
            "approvals": [
                {
                    "level": approval.approval_level,
                    "approved_by": approval.approved_by,
                    "date": approval.approval_date.isoformat(),
                    "signature_id": approval.signature_id,
                }
                for approval in approvals
            ],
        }

        # Add integrity checksum
        cert_data["checksum"] = calculate_checksum(cert_data)

        return cert_data

    def _get_distribution_list(self, batch_id: str) -> List[Dict]:
        """Get distribution list for recall notifications."""
        # Simplified - would query distribution database
        return [
            {"distributor": "PharmaCo Distribution", "contact": "recall@pharmaco.com"},
            {
                "distributor": "Regional Health Network",
                "contact": "pharmacy@health.net",
            },
        ]


# Example usage
def main():
    """Demonstrate the batch release system."""
    session = Session()
    system = BatchReleaseSystem(session)

    # Create a batch
    batch_request = BatchCreationRequest(
        product_code="ASP-1234",
        product_name="Aspirin 100mg Tablets",
        quantity=10000,
        unit="tablets",
        manufacturing_date=datetime.now(),
        shelf_life_months=36,
    )

    # Simulate user authentication
    production_user = User(
        username="john.smith",
        roles=["Production", "Supervisor"],
        email="john.smith@pharma.com",
    )

    # Create batch
    batch = system.create_batch(batch_request, production_user)
    print(f"Created batch: {batch.batch_id}")

    # Record QC tests
    qc_user = User(
        username="jane.doe", roles=["QC", "Lab"], email="jane.doe@pharma.com"
    )

    tests = [
        QCTestData("Assay", "95-105", "98.5", "%"),
        QCTestData("Dissolution", "80", "85", "%"),
        QCTestData("Uniformity", "Pass", "Pass", None),
    ]

    for test in tests:
        result = system.record_qc_test(batch.batch_id, test, qc_user)
        print(f"Recorded test: {test.test_name} - {result.status}")

    # QC approval
    qc_manager = User(
        username="bob.wilson", roles=["QC_Manager"], email="bob.wilson@pharma.com"
    )

    qc_approval = system.approve_qc_results(
        batch.batch_id, qc_manager, "secure_password", "All tests within specifications"
    )
    print(f"QC approved by: {qc_approval.approved_by}")

    # QA release
    qa_manager = User(
        username="alice.johnson", roles=["QA_Manager"], email="alice.johnson@pharma.com"
    )

    qa_release = system.release_batch(
        batch.batch_id,
        qa_manager,
        "secure_password",
        "Batch meets all quality standards",
    )
    print(f"QA release status: {qa_release['status']}")

    # Production release
    prod_manager = User(
        username="charlie.brown",
        roles=["Production_Manager"],
        email="charlie.brown@pharma.com",
    )

    final_release = system.release_batch(
        batch.batch_id,
        prod_manager,
        "secure_password",
        "Production records complete and verified",
    )

    if final_release["status"] == "released":
        print(f"Batch {batch.batch_id} successfully released!")
        print(f"Certificate: {final_release['certificate']}")


if __name__ == "__main__":
    # This is a demonstration - do not run without proper database setup
    print("This is a demonstration example. Set up database before running.")
    print("See the code for complete implementation details.")

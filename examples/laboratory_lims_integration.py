"""
Laboratory Information Management System (LIMS) Integration Example - GxP Python Toolkit

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

This example demonstrates integration of the GxP toolkit with a LIMS
for a clinical laboratory performing FDA-regulated testing.

Features demonstrated:
- Sample chain of custody
- Instrument integration with audit trail
- Result validation and approval workflow
- CLIA/CAP compliance features
- HL7 message generation
- Automated report generation with signatures
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Tuple

from gxp_toolkit import AuditLogger, GxPConfig, require_signature
from gxp_toolkit.access_control import User, require_permission
from gxp_toolkit.data_integrity import ValidationRule, calculate_checksum, track_changes

# Configuration for laboratory environment
config = GxPConfig(
    audit_retention_days=2555,  # 7 years per CLIA
    signature_timeout_minutes=10,
    require_mfa=True,
    checksum_algorithm="sha256",
    require_change_reason=True,
    validation_strict_mode=True,
)

audit = AuditLogger()


# Enums for laboratory workflows
class SampleType(str, Enum):
    BLOOD = "blood"
    URINE = "urine"
    TISSUE = "tissue"
    SWAB = "swab"
    CSF = "csf"
    OTHER = "other"


class TestStatus(str, Enum):
    ORDERED = "ordered"
    COLLECTED = "collected"
    RECEIVED = "received"
    IN_PROGRESS = "in_progress"
    PRELIMINARY = "preliminary"
    FINAL = "final"
    CORRECTED = "corrected"
    CANCELLED = "cancelled"


class Priority(str, Enum):
    ROUTINE = "routine"
    URGENT = "urgent"
    STAT = "stat"


class QCStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    REPEAT = "repeat"


# Data models
@dataclass
class Patient:
    """Patient information with PHI protection."""

    patient_id: str
    medical_record_number: str
    date_of_birth: datetime
    gender: str
    # PHI fields are not logged in audit trail
    _first_name: str = field(repr=False)
    _last_name: str = field(repr=False)

    @property
    def full_name(self) -> str:
        """Get full name (PHI protected)."""
        return f"{self._first_name} {self._last_name}"

    def get_demographics_hash(self) -> str:
        """Get hash of demographics for matching without exposing PHI."""
        data = f"{self.date_of_birth}{self.gender}{self._last_name[:3]}"
        return calculate_checksum(data)


@dataclass
class Sample:
    """Laboratory sample with chain of custody."""

    sample_id: str
    patient_id: str
    sample_type: SampleType
    collection_datetime: datetime
    collected_by: str
    collection_site: str
    priority: Priority = Priority.ROUTINE

    # Chain of custody
    custody_log: List[Dict] = field(default_factory=list)

    def transfer_custody(self, from_user: str, to_user: str, location: str):
        """Record custody transfer."""
        self.custody_log.append(
            {
                "timestamp": datetime.now().isoformat(),
                "from": from_user,
                "to": to_user,
                "location": location,
                "checksum": calculate_checksum(f"{from_user}{to_user}{location}"),
            }
        )


@dataclass
class TestOrder:
    """Laboratory test order."""

    order_id: str
    sample_id: str
    test_code: str
    test_name: str
    ordered_by: str
    order_datetime: datetime
    clinical_info: Optional[str] = None
    icd10_codes: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Laboratory test result with validation."""

    result_id: str
    order_id: str
    test_code: str
    value: str
    unit: Optional[str]
    reference_range: Optional[str]
    flag: Optional[str]  # H, L, C (critical)
    status: TestStatus
    performed_by: str
    performed_datetime: datetime
    instrument_id: Optional[str] = None
    lot_number: Optional[str] = None
    qc_status: Optional[QCStatus] = None

    def is_critical(self) -> bool:
        """Check if result is critical value."""
        return self.flag == "C"

    def is_abnormal(self) -> bool:
        """Check if result is abnormal."""
        return self.flag in ["H", "L", "C"]


@dataclass
class QCResult:
    """Quality control result."""

    qc_id: str
    control_name: str
    control_lot: str
    test_code: str
    value: Decimal
    expected_mean: Decimal
    expected_sd: Decimal
    status: QCStatus
    performed_by: str
    performed_datetime: datetime
    instrument_id: str

    def calculate_z_score(self) -> Decimal:
        """Calculate Z-score for Westgard rules."""
        return (self.value - self.expected_mean) / self.expected_sd


# Validation rules
sample_validation_rules = [
    ValidationRule(
        field="sample_type",
        rule_type="enum",
        params={"allowed_values": [t.value for t in SampleType]},
        message="Invalid sample type",
    ),
    ValidationRule(
        field="collection_datetime",
        rule_type="datetime_range",
        params={"max_hours_ago": 72},
        message="Sample collection time too old",
    ),
]

result_validation_rules = [
    ValidationRule(
        field="value",
        rule_type="required",
        params={},
        message="Result value is required",
    ),
    ValidationRule(
        field="status",
        rule_type="enum",
        params={"allowed_values": [s.value for s in TestStatus]},
        message="Invalid result status",
    ),
]


# LIMS Core System
class LaboratorySystem:
    """Core LIMS functionality with GxP compliance."""

    def __init__(self):
        self.samples: Dict[str, Sample] = {}
        self.orders: Dict[str, TestOrder] = {}
        self.results: Dict[str, TestResult] = {}
        self.qc_results: List[QCResult] = []

    @audit.log_activity("SAMPLE_COLLECTION")
    @require_permission("Phlebotomist", "Nurse", "Physician")
    # @validate_input(sample_validation_rules)  # Validation rules would be applied
    @track_changes
    def collect_sample(
        self,
        patient: Patient,
        sample_type: SampleType,
        collection_site: str,
        user: User,
    ) -> Sample:
        """
        Collect patient sample with full chain of custody.

        Args:
            patient: Patient information
            sample_type: Type of sample
            collection_site: Location of collection
            user: Collecting user

        Returns:
            Sample object with unique ID
        """
        # Generate unique sample ID with checksum
        sample_id = self._generate_sample_id(patient.patient_id, sample_type)

        sample = Sample(
            sample_id=sample_id,
            patient_id=patient.patient_id,
            sample_type=sample_type,
            collection_datetime=datetime.now(),
            collected_by=user.username,
            collection_site=collection_site,
        )

        # Initialize chain of custody
        sample.transfer_custody(
            from_user="SYSTEM", to_user=user.username, location=collection_site
        )

        self.samples[sample_id] = sample

        # Generate collection label
        self._print_sample_label(sample, patient)

        return sample

    @audit.log_activity("SAMPLE_RECEIVE")
    @require_permission("Lab_Tech", "Lab_Supervisor")
    def receive_sample(
        self,
        sample_id: str,
        user: User,
        temperature_ok: bool = True,
        integrity_ok: bool = True,
    ) -> Dict:
        """Receive sample in laboratory with quality checks."""
        sample = self.samples.get(sample_id)
        if not sample:
            raise ValueError(f"Sample {sample_id} not found")

        # Quality checks
        if not temperature_ok:
            audit.log_event(
                action="SAMPLE_REJECTION",
                user=user.username,
                details={"sample_id": sample_id, "reason": "Temperature out of range"},
                severity="WARNING",
            )
            return {"status": "rejected", "reason": "temperature"}

        if not integrity_ok:
            audit.log_event(
                action="SAMPLE_REJECTION",
                user=user.username,
                details={
                    "sample_id": sample_id,
                    "reason": "Sample integrity compromised",
                },
                severity="WARNING",
            )
            return {"status": "rejected", "reason": "integrity"}

        # Transfer custody to lab
        sample.transfer_custody(
            from_user=sample.custody_log[-1]["to"],
            to_user=user.username,
            location="Laboratory Receiving",
        )

        return {
            "status": "accepted",
            "received_by": user.username,
            "timestamp": datetime.now(),
        }

    @audit.log_activity("TEST_ORDER")
    @require_permission("Physician", "Nurse_Practitioner")
    def order_test(
        self,
        sample_id: str,
        test_code: str,
        test_name: str,
        user: User,
        clinical_info: Optional[str] = None,
        icd10_codes: Optional[List[str]] = None,
    ) -> TestOrder:
        """Order laboratory test with clinical information."""
        sample = self.samples.get(sample_id)
        if not sample:
            raise ValueError(f"Sample {sample_id} not found")

        order_id = f"ORD-{uuid.uuid4().hex[:8].upper()}"

        order = TestOrder(
            order_id=order_id,
            sample_id=sample_id,
            test_code=test_code,
            test_name=test_name,
            ordered_by=user.username,
            order_datetime=datetime.now(),
            clinical_info=clinical_info,
            icd10_codes=icd10_codes or [],
        )

        self.orders[order_id] = order

        # Check if test is STAT priority
        if sample.priority == Priority.STAT:
            self._alert_stat_order(order)

        return order

    @audit.log_activity("INSTRUMENT_RESULT")
    @require_permission("RESULT_ENTRY")
    # @validate_input(result_validation_rules)  # Validation rules would be applied
    def record_instrument_result(
        self,
        order_id: str,
        value: str,
        unit: Optional[str],
        instrument_id: str,
        operator: User,
        lot_number: Optional[str] = None,
    ) -> TestResult:
        """
        Record result from automated instrument.

        Includes automatic QC verification and critical value checking.
        """
        order = self.orders.get(order_id)
        if not order:
            raise ValueError(f"Order {order_id} not found")

        # Verify QC is current
        if not self._verify_qc_status(order.test_code, instrument_id):
            raise ValueError("QC not current for this test/instrument")

        # Determine reference range and flags
        ref_range, flag = self._evaluate_result(order.test_code, value, unit)

        result = TestResult(
            result_id=f"RES-{uuid.uuid4().hex[:8].upper()}",
            order_id=order_id,
            test_code=order.test_code,
            value=value,
            unit=unit,
            reference_range=ref_range,
            flag=flag,
            status=TestStatus.PRELIMINARY,
            performed_by=operator.username,
            performed_datetime=datetime.now(),
            instrument_id=instrument_id,
            lot_number=lot_number,
            qc_status=QCStatus.PASS,
        )

        self.results[result.result_id] = result

        # Check for critical values
        if result.is_critical():
            self._handle_critical_value(result, order)

        return result

    @audit.log_activity("RESULT_REVIEW")
    @require_signature("Review and release test results")
    @require_permission("Technologist", "Pathologist")
    def review_result(
        self,
        result_id: str,
        user: User,
        password: str,
        action: str = "release",  # release, hold, repeat
        comment: Optional[str] = None,
    ) -> Dict:
        """Review and release test results with electronic signature."""
        result = self.results.get(result_id)
        if not result:
            raise ValueError(f"Result {result_id} not found")

        if action == "release":
            # Delta check - compare with previous results
            delta_check = self._perform_delta_check(result)
            if delta_check["significant_change"]:
                if not comment:
                    raise ValueError("Comment required for significant change")

            result.status = TestStatus.FINAL

            # Generate HL7 message for EMR
            hl7_message = self._generate_hl7_result(result)

            return {
                "status": "released",
                "released_by": user.username,
                "timestamp": datetime.now(),
                "hl7_message": hl7_message,
            }

        elif action == "hold":
            result.status = TestStatus.IN_PROGRESS
            return {"status": "held", "held_by": user.username, "reason": comment}

        elif action == "repeat":
            # Create repeat order
            order = self.orders[result.order_id]
            repeat_order = self.order_test(
                sample_id=order.sample_id,
                test_code=order.test_code,
                test_name=f"{order.test_name} (REPEAT)",
                user=user,
                clinical_info=f"Repeat requested by {user.username}: {comment}",
            )

            return {
                "status": "repeat_ordered",
                "repeat_order_id": repeat_order.order_id,
            }

    @audit.log_activity("QC_PERFORM")
    @require_permission("Lab_Tech", "Technologist")
    def perform_qc(
        self,
        control_name: str,
        control_lot: str,
        test_code: str,
        value: Decimal,
        instrument_id: str,
        user: User,
    ) -> QCResult:
        """Perform quality control with Westgard rules evaluation."""
        # Get expected values for control
        expected_mean, expected_sd = self._get_control_values(
            control_name, control_lot, test_code
        )

        qc_result = QCResult(
            qc_id=f"QC-{uuid.uuid4().hex[:8].upper()}",
            control_name=control_name,
            control_lot=control_lot,
            test_code=test_code,
            value=value,
            expected_mean=expected_mean,
            expected_sd=expected_sd,
            status=QCStatus.PASS,  # Will be updated by rules
            performed_by=user.username,
            performed_datetime=datetime.now(),
            instrument_id=instrument_id,
        )

        # Apply Westgard rules
        qc_result.status = self._apply_westgard_rules(qc_result)

        self.qc_results.append(qc_result)

        if qc_result.status == QCStatus.FAIL:
            # Lock instrument for this test
            self._lock_instrument_test(instrument_id, test_code)

            # Alert supervisor
            audit.log_event(
                action="QC_FAILURE",
                user=user.username,
                details={
                    "test_code": test_code,
                    "instrument_id": instrument_id,
                    "control": control_name,
                    "z_score": float(qc_result.calculate_z_score()),
                },
                severity="ERROR",
            )

        return qc_result

    @audit.log_activity("REPORT_GENERATE")
    @require_signature("Approve final report", require_mfa=True)
    @require_permission("Pathologist", "Lab_Director")
    def generate_final_report(
        self, patient_id: str, order_ids: List[str], user: User, password: str
    ) -> Dict:
        """Generate signed final report for patient."""
        # Collect all results
        report_data = {
            "patient_id": patient_id,
            "report_date": datetime.now(),
            "results": [],
            "generated_by": user.username,
            "facility": "GxP Clinical Laboratory",
            "clia_number": "11D1234567",
        }

        for order_id in order_ids:
            order = self.orders.get(order_id)
            if not order:
                continue

            # Find final results for order
            final_results = [
                r
                for r in self.results.values()
                if r.order_id == order_id and r.status == TestStatus.FINAL
            ]

            for result in final_results:
                report_data["results"].append(
                    {
                        "test_name": order.test_name,
                        "test_code": result.test_code,
                        "value": result.value,
                        "unit": result.unit,
                        "reference_range": result.reference_range,
                        "flag": result.flag,
                        "performed_date": result.performed_datetime,
                    }
                )

        # Add data integrity checksum
        report_data["checksum"] = calculate_checksum(report_data)

        # Generate PDF (simulated)
        pdf_path = self._generate_pdf_report(report_data)

        return {
            "report_id": f"RPT-{uuid.uuid4().hex[:8].upper()}",
            "pdf_path": pdf_path,
            "checksum": report_data["checksum"],
            "signed_by": user.username,
            "signature_timestamp": datetime.now(),
        }

    def _generate_sample_id(self, patient_id: str, sample_type: SampleType) -> str:
        """Generate unique sample ID with embedded checksum."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        base_id = f"{timestamp}-{sample_type.value[:3].upper()}"
        checksum = calculate_checksum(f"{patient_id}{base_id}")[:4]
        return f"{base_id}-{checksum}"

    def _verify_qc_status(self, test_code: str, instrument_id: str) -> bool:
        """Verify QC is current for test/instrument combination."""
        # Get QC results for last 24 hours
        cutoff_time = datetime.now() - timedelta(hours=24)

        recent_qc = [
            qc
            for qc in self.qc_results
            if qc.test_code == test_code
            and qc.instrument_id == instrument_id
            and qc.performed_datetime > cutoff_time
        ]

        if not recent_qc:
            return False

        # Check if any QC failed
        return all(qc.status != QCStatus.FAIL for qc in recent_qc)

    def _evaluate_result(
        self, test_code: str, value: str, unit: Optional[str]
    ) -> Tuple[str, Optional[str]]:
        """Evaluate result against reference ranges."""
        # Simplified - real system would query reference range database
        ranges = {
            "GLUC": (
                "70-110",
                "mg/dL",
                50,
                150,
            ),  # (range, unit, low_critical, high_critical)
            "HGB": ("12.0-16.0", "g/dL", 7.0, 20.0),
            "WBC": ("4.5-11.0", "K/uL", 2.0, 30.0),
        }

        if test_code not in ranges:
            return ("See Report", None)

        ref_range, ref_unit, low_crit, high_crit = ranges[test_code]

        try:
            numeric_value = float(value)
            range_parts = ref_range.split("-")
            low_normal = float(range_parts[0])
            high_normal = float(range_parts[1])

            if numeric_value < low_crit or numeric_value > high_crit:
                flag = "C"  # Critical
            elif numeric_value < low_normal:
                flag = "L"  # Low
            elif numeric_value > high_normal:
                flag = "H"  # High
            else:
                flag = None  # Normal

            return (f"{ref_range} {ref_unit}", flag)

        except (ValueError, IndexError):
            return (ref_range, None)

    def _handle_critical_value(self, result: TestResult, order: TestOrder):
        """Handle critical value notification."""
        # Log critical value
        audit.log_event(
            action="CRITICAL_VALUE",
            user="SYSTEM",
            details={
                "result_id": result.result_id,
                "test_code": result.test_code,
                "value": f"{result.value} {result.unit}",
                "ordered_by": order.ordered_by,
            },
            severity="CRITICAL",
            category="PATIENT_SAFETY",
        )

        # In real system, would page physician
        print(f"CRITICAL VALUE ALERT: {result.test_code} = {result.value}")

    def _perform_delta_check(self, result: TestResult) -> Dict:
        """Compare with previous results for significant changes."""
        # Simplified - real system would have configurable delta check rules
        return {
            "significant_change": False,
            "previous_value": None,
            "percent_change": None,
        }

    def _apply_westgard_rules(self, qc: QCResult) -> QCStatus:
        """Apply Westgard multi-rules for QC evaluation."""
        z_score = qc.calculate_z_score()

        # 1-3s rule: Reject if |z| > 3
        if abs(z_score) > 3:
            return QCStatus.FAIL

        # 1-2s rule: Warning if |z| > 2
        if abs(z_score) > 2:
            return QCStatus.WARNING

        # Additional rules would check patterns across multiple QC results
        # 2-2s, R-4s, 4-1s, 10-x, etc.

        return QCStatus.PASS

    def _generate_hl7_result(self, result: TestResult) -> str:
        """Generate HL7 ORU message for result."""
        # Simplified HL7 v2.5 message
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

        hl7_message = (
            f"MSH|^~\\&|LIMS|LAB|EMR|HOSP|{timestamp}||ORU^R01|"
            f"{result.result_id}|P|2.5\n"
            f"PID|1||{result.order_id}||DOE^JOHN||19700101|M\n"
            f"OBR|1|{result.order_id}||{result.test_code}^{result.test_code}|||"
            f"{timestamp}\n"
            f"OBX|1|NM|{result.test_code}||{result.value}|{result.unit}|"
            f"{result.reference_range}|{result.flag}|||F|||{timestamp}\n"
        )
        return hl7_message

    def _get_control_values(
        self, control_name: str, control_lot: str, test_code: str
    ) -> Tuple[Decimal, Decimal]:
        """Get expected mean and SD for control."""
        # Simplified - real system would query control database
        control_values = {
            ("NORMAL", "LOT123", "GLUC"): (Decimal("95"), Decimal("3.2")),
            ("HIGH", "LOT123", "GLUC"): (Decimal("250"), Decimal("8.5")),
            ("NORMAL", "LOT456", "HGB"): (Decimal("14.0"), Decimal("0.4")),
        }

        key = (control_name, control_lot, test_code)
        return control_values.get(key, (Decimal("0"), Decimal("1")))

    def _lock_instrument_test(self, instrument_id: str, test_code: str):
        """Lock instrument for specific test due to QC failure."""
        audit.log_event(
            action="INSTRUMENT_LOCK",
            user="SYSTEM",
            details={
                "instrument_id": instrument_id,
                "test_code": test_code,
                "reason": "QC failure",
            },
            severity="WARNING",
        )

    def _print_sample_label(self, sample: Sample, patient: Patient):
        """Generate sample label with barcode."""
        label_data = {
            "sample_id": sample.sample_id,
            "patient_name": patient.full_name[:20],  # Truncated for privacy
            "dob": patient.date_of_birth.strftime("%Y-%m-%d"),
            "collected": sample.collection_datetime.strftime("%Y-%m-%d %H:%M"),
            "type": sample.sample_type.value,
        }

        # In real system, would send to label printer
        print(f"Sample Label: {label_data}")

    def _generate_pdf_report(self, report_data: Dict) -> str:
        """Generate PDF report (simulated)."""
        # In real system, would use reportlab or similar
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"/reports/{report_data['patient_id']}_{timestamp}.pdf"
        return filename

    def _alert_stat_order(self, order: TestOrder):
        """Alert staff to STAT order."""
        audit.log_event(
            action="STAT_ORDER_ALERT",
            user="SYSTEM",
            details={"order_id": order.order_id, "test_code": order.test_code},
            severity="INFO",
            category="URGENT",
        )


# Example usage
def demonstrate_laboratory_workflow():
    """Demonstrate complete laboratory workflow."""
    lims = LaboratorySystem()

    # Create patient
    patient = Patient(
        patient_id="PAT001",
        medical_record_number="MRN123456",
        date_of_birth=datetime(1970, 1, 1),
        gender="M",
        _first_name="John",
        _last_name="Doe",
    )

    # Simulate users
    phlebotomist = User(
        username="sarah.jones", roles=["Phlebotomist"], email="sarah.jones@lab.com"
    )

    tech = User(
        username="mike.wilson",
        roles=["Lab_Tech", "Technologist"],
        email="mike.wilson@lab.com",
    )

    pathologist = User(
        username="dr.smith",
        roles=["Pathologist", "Lab_Director"],
        email="dr.smith@lab.com",
    )

    # 1. Collect sample
    sample = lims.collect_sample(
        patient=patient,
        sample_type=SampleType.BLOOD,
        collection_site="Outpatient Lab",
        user=phlebotomist,
    )
    print(f"Sample collected: {sample.sample_id}")

    # 2. Receive sample in lab
    receipt = lims.receive_sample(
        sample_id=sample.sample_id, user=tech, temperature_ok=True, integrity_ok=True
    )
    print(f"Sample received: {receipt['status']}")

    # 3. Order tests
    physician = User(
        username="dr.johnson", roles=["Physician"], email="dr.johnson@clinic.com"
    )

    glucose_order = lims.order_test(
        sample_id=sample.sample_id,
        test_code="GLUC",
        test_name="Glucose",
        user=physician,
        clinical_info="Diabetes monitoring",
        icd10_codes=["E11.9"],
    )

    # 4. Perform QC
    qc_result = lims.perform_qc(
        control_name="NORMAL",
        control_lot="LOT123",
        test_code="GLUC",
        value=Decimal("95.2"),
        instrument_id="INST-001",
        user=tech,
    )
    print(f"QC Status: {qc_result.status}")

    # 5. Record instrument result
    result = lims.record_instrument_result(
        order_id=glucose_order.order_id,
        value="105",
        unit="mg/dL",
        instrument_id="INST-001",
        operator=tech,
        lot_number="REA-123",
    )
    print(f"Result recorded: {result.value} {result.unit} ({result.flag or 'Normal'})")

    # 6. Review and release result
    review = lims.review_result(
        result_id=result.result_id,
        user=tech,
        password="secure_password",
        action="release",
    )
    print(f"Result status: {review['status']}")

    # 7. Generate final report
    report = lims.generate_final_report(
        patient_id=patient.patient_id,
        order_ids=[glucose_order.order_id],
        user=pathologist,
        password="secure_password",
    )
    print(f"Report generated: {report['report_id']}")

    # Show audit trail
    print("\n--- Audit Trail Sample ---")
    # In real system, would query audit storage
    print("All laboratory actions have been logged with full compliance")


if __name__ == "__main__":
    print("Laboratory LIMS Integration Example")
    print("=" * 50)
    demonstrate_laboratory_workflow()

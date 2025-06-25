"""
Computer system validation for GxP compliance.

Implements validation for computerized systems according to
GAMP 5 guidelines and 21 CFR Part 11 requirements.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from ..access_control import Permission, require_permission
from ..audit_trail import audit_event
from ..electronic_signatures import SignaturePurpose, require_signature


class ValidationLevel(str, Enum):
    """GAMP 5 software categories."""

    CATEGORY_1 = "infrastructure"  # Operating systems
    CATEGORY_2 = "standard"  # Standard software (unchanged)
    CATEGORY_3 = "configurable"  # Configurable software
    CATEGORY_4 = "configured"  # Configured software
    CATEGORY_5 = "custom"  # Custom software


class TestType(str, Enum):  # noqa: N801
    """Types of validation tests."""

    UNIT = "unit"
    INTEGRATION = "integration"
    SYSTEM = "system"
    ACCEPTANCE = "acceptance"
    PERFORMANCE = "performance"
    SECURITY = "security"
    REGRESSION = "regression"


class TestStatus(str, Enum):  # noqa: N801
    """Test execution status."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


@dataclass
class TestCase:  # noqa: N801
    """Individual test case definition."""

    test_id: str
    name: str
    description: str
    test_type: TestType

    # Test details
    preconditions: List[str]
    test_steps: List[Dict[str, str]]  # step_number, description, expected_result
    postconditions: List[str]

    # Requirements traceability
    requirements: List[str]
    risk_level: str = "medium"  # low, medium, high

    # Metadata
    created_by: str = ""
    created_date: datetime = field(default_factory=datetime.utcnow)
    version: str = "1.0"


@dataclass
class TestResult:  # noqa: N801
    """Test execution result."""

    result_id: str
    test_id: str
    execution_date: datetime
    executed_by: str

    # Results
    status: TestStatus
    actual_results: List[Dict[str, str]]  # step_number, actual_result, pass/fail

    # Issues
    defects: List[Dict[str, Any]] = field(default_factory=list)
    deviations: List[str] = field(default_factory=list)

    # Evidence
    screenshots: List[str] = field(default_factory=list)
    log_files: List[str] = field(default_factory=list)

    # Comments
    comments: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "result_id": self.result_id,
            "test_id": self.test_id,
            "execution_date": self.execution_date.isoformat(),
            "executed_by": self.executed_by,
            "status": self.status.value,
            "actual_results": self.actual_results,
            "defects": self.defects,
            "deviations": self.deviations,
            "screenshots": self.screenshots,
            "log_files": self.log_files,
            "comments": self.comments,
        }


@dataclass
class SystemValidationPlan:
    """Computer system validation plan."""

    plan_id: str
    system_name: str
    system_description: str
    validation_level: ValidationLevel

    # Scope
    in_scope: List[str]
    out_of_scope: List[str]

    # Test strategy
    test_cases: List[TestCase]
    test_environments: List[Dict[str, str]]

    # Schedule
    start_date: datetime
    end_date: datetime

    # Acceptance criteria
    minimum_pass_rate: float = 0.95
    critical_tests: List[str] = field(default_factory=list)

    # Risk assessment
    risk_assessment: Dict[str, Any] = field(default_factory=dict)

    # Status
    status: str = "draft"
    approved_by: Optional[str] = None
    approved_date: Optional[datetime] = None


@dataclass
class ValidationSummaryReport:
    """System validation summary report."""

    report_id: str
    plan_id: str

    # Summary
    total_tests: int
    tests_passed: int
    tests_failed: int
    tests_skipped: int
    pass_rate: float

    # Details
    test_results: List[TestResult]
    defect_summary: List[Dict[str, Any]]

    # Traceability
    requirements_coverage: Dict[str, List[str]]  # requirement -> test cases

    # Conclusions
    validation_status: str  # validated, conditionally_validated, not_validated

    # Approval
    prepared_by: str
    prepared_date: datetime

    # Optional fields with defaults
    restrictions: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    reviewed_by: Optional[str] = None
    reviewed_date: Optional[datetime] = None
    approved_by: Optional[str] = None
    approved_date: Optional[datetime] = None


class SystemValidator:
    """Computer system validator for GxP compliance."""

    def __init__(self) -> None:
        """Initialize system validator."""
        self.validation_plans: Dict[str, SystemValidationPlan] = {}
        self.test_cases: Dict[str, TestCase] = {}
        self.test_results: Dict[str, List[TestResult]] = {}

    def create_validation_plan(
        self,
        system_name: str,
        system_description: str,
        validation_level: ValidationLevel,
        test_cases: List[TestCase],
        start_date: datetime,
        end_date: datetime,
    ) -> SystemValidationPlan:
        """
        Create system validation plan.

        Args:
            system_name: Name of system
            system_description: System description
            validation_level: GAMP 5 category
            test_cases: List of test cases
            start_date: Planned start
            end_date: Planned end

        Returns:
            Validation plan
        """
        import uuid

        plan_id = str(uuid.uuid4())

        # Determine risk level based on validation level
        risk_assessment = self._assess_risk(validation_level)

        plan = SystemValidationPlan(
            plan_id=plan_id,
            system_name=system_name,
            system_description=system_description,
            validation_level=validation_level,
            in_scope=[],
            out_of_scope=[],
            test_cases=test_cases,
            test_environments=[],
            start_date=start_date,
            end_date=end_date,
            risk_assessment=risk_assessment,
        )

        self.validation_plans[plan_id] = plan

        # Store test cases
        for test_case in test_cases:
            self.test_cases[test_case.test_id] = test_case

        # Audit
        audit_event(
            action="system.validation.plan.created",
            resource_type="validation_plan",
            resource_id=plan_id,
            details={
                "system_name": system_name,
                "validation_level": validation_level.value,
                "test_cases": len(test_cases),
            },
        )

        return plan

    def _assess_risk(self, validation_level: ValidationLevel) -> Dict[str, Any]:
        """Assess risk based on validation level."""
        risk_levels = {
            ValidationLevel.CATEGORY_1: "low",
            ValidationLevel.CATEGORY_2: "low",
            ValidationLevel.CATEGORY_3: "medium",
            ValidationLevel.CATEGORY_4: "high",
            ValidationLevel.CATEGORY_5: "critical",
        }

        return {
            "overall_risk": risk_levels.get(validation_level, "medium"),
            "patient_safety_impact": (
                "high"
                if validation_level
                in [ValidationLevel.CATEGORY_4, ValidationLevel.CATEGORY_5]
                else "medium"
            ),
            "data_integrity_impact": "high",
            "regulatory_impact": "high",
        }

    @require_permission(Permission.WRITE)
    def execute_test(
        self,
        test_id: str,
        executed_by: str,
        actual_results: List[Dict[str, str]],
        status: TestStatus,
        defects: Optional[List[Dict[str, Any]]] = None,
        screenshots: Optional[List[str]] = None,
        comments: str = "",
    ) -> TestResult:
        """
        Execute a test case.

        Args:
            test_id: Test case ID
            executed_by: Tester name
            actual_results: Actual results per step
            status: Test status
            defects: Any defects found
            screenshots: Evidence screenshots
            comments: Additional comments

        Returns:
            Test result
        """
        import uuid

        test_case = self.test_cases.get(test_id)
        if not test_case:
            raise ValueError(f"Unknown test case: {test_id}")

        result = TestResult(
            result_id=str(uuid.uuid4()),
            test_id=test_id,
            execution_date=datetime.utcnow(),
            executed_by=executed_by,
            status=status,
            actual_results=actual_results,
            defects=defects or [],
            screenshots=screenshots or [],
            comments=comments,
        )

        # Store result
        if test_id not in self.test_results:
            self.test_results[test_id] = []
        self.test_results[test_id].append(result)

        # Audit
        audit_event(
            action="system.test.executed",
            resource_type="test_result",
            resource_id=result.result_id,
            details={
                "test_id": test_id,
                "status": status.value,
                "defects": len(defects) if defects else 0,
            },
        )

        return result

    @require_permission(Permission.APPROVE)
    @require_signature(purpose=SignaturePurpose.APPROVAL)
    def complete_validation(
        self, plan_id: str, recommendations: List[str]
    ) -> ValidationSummaryReport:
        """
        Complete validation and generate report.

        Args:
            plan_id: Validation plan ID
            recommendations: List of recommendations

        Returns:
            Validation summary report
        """
        import uuid

        plan = self.validation_plans.get(plan_id)
        if not plan:
            raise ValueError(f"Unknown validation plan: {plan_id}")

        # Collect all test results
        all_results = []
        test_summary = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}

        defect_summary = []
        requirements_coverage: Dict[str, Any] = {}

        for test_case in plan.test_cases:
            results = self.test_results.get(test_case.test_id, [])
            if results:
                # Take latest result
                latest_result = results[-1]
                all_results.append(latest_result)

                test_summary["total"] += 1
                if latest_result.status == TestStatus.PASSED:
                    test_summary["passed"] += 1
                elif latest_result.status == TestStatus.FAILED:
                    test_summary["failed"] += 1
                elif latest_result.status == TestStatus.SKIPPED:
                    test_summary["skipped"] += 1

                # Collect defects
                defect_summary.extend(latest_result.defects)

                # Track requirements coverage
                for req in test_case.requirements:
                    if req not in requirements_coverage:
                        requirements_coverage[req] = []
                    requirements_coverage[req].append(test_case.test_id)

        # Calculate pass rate
        pass_rate = (
            (test_summary["passed"] / test_summary["total"])
            if test_summary["total"] > 0
            else 0
        )

        # Determine validation status
        if pass_rate >= plan.minimum_pass_rate and test_summary["failed"] == 0:
            validation_status = "validated"
        elif pass_rate >= 0.8:  # 80% pass rate
            validation_status = "conditionally_validated"
        else:
            validation_status = "not_validated"

        # Check critical tests
        restrictions = []
        for critical_test_id in plan.critical_tests:
            results = self.test_results.get(critical_test_id, [])
            if not results or results[-1].status != TestStatus.PASSED:
                restrictions.append(f"Critical test {critical_test_id} not passed")
                validation_status = "not_validated"

        # Create report
        report = ValidationSummaryReport(
            report_id=str(uuid.uuid4()),
            plan_id=plan_id,
            total_tests=test_summary["total"],
            tests_passed=test_summary["passed"],
            tests_failed=test_summary["failed"],
            tests_skipped=test_summary["skipped"],
            pass_rate=pass_rate,
            test_results=all_results,
            defect_summary=defect_summary,
            requirements_coverage=requirements_coverage,
            validation_status=validation_status,
            restrictions=restrictions,
            recommendations=recommendations,
            prepared_by="system",  # Would get from current user
            prepared_date=datetime.utcnow(),
        )

        # Update plan status
        plan.status = "completed"

        # Audit
        audit_event(
            action="system.validation.completed",
            resource_type="validation_report",
            resource_id=report.report_id,
            details={
                "plan_id": plan_id,
                "validation_status": validation_status,
                "pass_rate": pass_rate,
                "defects": len(defect_summary),
            },
        )

        return report


# Global system validator instance
_system_validator: Optional[SystemValidator] = None


def get_system_validator() -> SystemValidator:
    """Get global system validator instance."""
    global _system_validator
    if _system_validator is None:
        _system_validator = SystemValidator()
    return _system_validator


def validate_system(
    system_name: str,
    validation_level: ValidationLevel,
    test_cases: List[TestCase],
    start_date: datetime,
    end_date: datetime,
) -> SystemValidationPlan:
    """
    Create system validation plan.

    Args:
        system_name: System to validate
        validation_level: GAMP 5 category
        test_cases: Test cases
        start_date: Start date
        end_date: End date

    Returns:
        Validation plan
    """
    validator = get_system_validator()
    return validator.create_validation_plan(
        system_name=system_name,
        system_description="",
        validation_level=validation_level,
        test_cases=test_cases,
        start_date=start_date,
        end_date=end_date,
    )

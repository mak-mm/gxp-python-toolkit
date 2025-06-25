"""
Tests for computer system validation module.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from gxp_toolkit.validation.system import (
    SystemValidationPlan,
    SystemValidator,
    TestCase,
    TestResult,
    TestStatus,
    TestType,
    ValidationLevel,
    ValidationSummaryReport,
    get_system_validator,
    validate_system,
)


class TestTestCase:
    """Test TestCase functionality."""

    def test_test_case_creation(self):
        """Test creating a test case."""
        test_case = TestCase(
            test_id="TC-001",
            name="Login Test",
            description="Test user login functionality",
            test_type=TestType.ACCEPTANCE,
            preconditions=["User account exists", "System is accessible"],
            test_steps=[
                {
                    "step_number": "1",
                    "description": "Navigate to login page",
                    "expected_result": "Login page displayed",
                },
                {
                    "step_number": "2",
                    "description": "Enter credentials",
                    "expected_result": "Credentials accepted",
                },
            ],
            postconditions=["User is logged in"],
            requirements=["REQ-001", "REQ-002"],
            risk_level="high",
            created_by="test_author",
        )

        assert test_case.test_id == "TC-001"
        assert test_case.test_type == TestType.ACCEPTANCE
        assert len(test_case.test_steps) == 2
        assert test_case.risk_level == "high"
        assert test_case.version == "1.0"


class TestTestResult:
    """Test TestResult functionality."""

    def test_test_result_creation(self):
        """Test creating a test result."""
        result = TestResult(
            result_id="TR-001",
            test_id="TC-001",
            execution_date=datetime.utcnow(),
            executed_by="test_tester",
            status=TestStatus.PASSED,
            actual_results=[
                {
                    "step_number": "1",
                    "actual_result": "Page loaded",
                    "pass/fail": "pass",
                },
                {
                    "step_number": "2",
                    "actual_result": "Login successful",
                    "pass/fail": "pass",
                },
            ],
            defects=[],
            deviations=[],
            screenshots=["login_page.png", "dashboard.png"],
            log_files=["test_log.txt"],
            comments="Test completed successfully",
        )

        assert result.result_id == "TR-001"
        assert result.status == TestStatus.PASSED
        assert len(result.actual_results) == 2
        assert len(result.screenshots) == 2
        assert result.comments != ""

    def test_test_result_to_dict(self):
        """Test converting test result to dictionary."""
        result = TestResult(
            result_id="TR-002",
            test_id="TC-002",
            execution_date=datetime.utcnow(),
            executed_by="tester",
            status=TestStatus.FAILED,
            actual_results=[],
            defects=[{"id": "BUG-001", "severity": "high"}],
        )

        data = result.to_dict()
        assert data["result_id"] == "TR-002"
        assert data["status"] == "failed"
        assert len(data["defects"]) == 1
        assert "execution_date" in data


class TestSystemValidator:
    """Test system validator functionality."""

    @pytest.fixture
    def validator(self):
        """Create a validator instance."""
        return SystemValidator()

    @pytest.fixture
    def sample_test_case(self):
        """Create a sample test case."""
        return TestCase(
            test_id="TC-TEST",
            name="Sample Test",
            description="Sample test case",
            test_type=TestType.SYSTEM,
            preconditions=["System is running"],
            test_steps=[
                {
                    "step_number": "1",
                    "description": "Perform action",
                    "expected_result": "Success",
                }
            ],
            postconditions=["Action completed"],
            requirements=["REQ-001"],
            risk_level="medium",
        )

    def test_create_validation_plan(self, validator, sample_test_case):
        """Test creating a validation plan."""
        with patch("gxp_toolkit.validation.system.audit_event"):
            plan = validator.create_validation_plan(
                system_name="Test System",
                system_description="Test system description",
                validation_level=ValidationLevel.CATEGORY_4,
                test_cases=[sample_test_case],
                start_date=datetime.utcnow(),
                end_date=datetime.utcnow() + timedelta(days=30),
            )

            assert plan.system_name == "Test System"
            assert plan.validation_level == ValidationLevel.CATEGORY_4
            assert len(plan.test_cases) == 1
            assert plan.status == "draft"
            assert plan.plan_id in validator.validation_plans
            assert sample_test_case.test_id in validator.test_cases
            assert "overall_risk" in plan.risk_assessment

    def test_assess_risk_levels(self, validator):
        """Test risk assessment for different validation levels."""
        # Test each validation level
        risk_cat1 = validator._assess_risk(ValidationLevel.CATEGORY_1)
        assert risk_cat1["overall_risk"] == "low"
        assert risk_cat1["patient_safety_impact"] == "medium"

        risk_cat5 = validator._assess_risk(ValidationLevel.CATEGORY_5)
        assert risk_cat5["overall_risk"] == "critical"
        assert risk_cat5["patient_safety_impact"] == "high"

        # All should have high data integrity and regulatory impact
        for level in ValidationLevel:
            risk = validator._assess_risk(level)
            assert risk["data_integrity_impact"] == "high"
            assert risk["regulatory_impact"] == "high"

    @patch("gxp_toolkit.validation.system.audit_event")
    def test_execute_test_success(self, mock_audit, validator, sample_test_case):
        """Test executing a successful test."""
        # Setup
        validator.test_cases[sample_test_case.test_id] = sample_test_case

        result = validator.execute_test(
            test_id=sample_test_case.test_id,
            executed_by="tester",
            actual_results=[
                {"step_number": "1", "actual_result": "Success", "pass/fail": "pass"}
            ],
            status=TestStatus.PASSED,
            screenshots=["evidence.png"],
            comments="All steps passed",
        )

        assert result.status == TestStatus.PASSED
        assert result.executed_by == "tester"
        assert len(result.screenshots) == 1
        assert sample_test_case.test_id in validator.test_results

        # Verify audit was called
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args[1]
        assert call_args["action"] == "system.test.executed"
        assert call_args["details"]["status"] == "passed"

    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.system.audit_event")
    def test_execute_test_with_defects(
        self, mock_audit, mock_user, validator, sample_test_case
    ):
        """Test executing a test with defects."""
        # Mock authenticated user
        mock_user.return_value = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )

        validator.test_cases[sample_test_case.test_id] = sample_test_case

        defects = [
            {"id": "BUG-001", "severity": "high", "description": "Login fails"},
            {"id": "BUG-002", "severity": "low", "description": "UI issue"},
        ]

        result = validator.execute_test(
            test_id=sample_test_case.test_id,
            executed_by="tester",
            actual_results=[
                {"step_number": "1", "actual_result": "Failed", "pass/fail": "fail"}
            ],
            status=TestStatus.FAILED,
            defects=defects,
            comments="Found critical defects",
        )

        assert result.status == TestStatus.FAILED
        assert len(result.defects) == 2
        assert result.defects[0]["severity"] == "high"

    def test_execute_test_unknown_test_case(self, validator):
        """Test executing test with unknown test case."""
        with pytest.raises(ValueError, match="Unknown test case"):
            validator.execute_test(
                test_id="UNKNOWN",
                executed_by="tester",
                actual_results=[],
                status=TestStatus.PASSED,
            )

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.system.audit_event")
    def test_complete_validation_all_passed(
        self, mock_audit, mock_user, mock_sig_user, validator, sample_test_case
    ):
        """Test completing validation with all tests passed."""
        # Mock authenticated user
        user_mock = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_user.return_value = user_mock
        mock_sig_user.return_value = user_mock

        # Setup plan
        plan = SystemValidationPlan(
            plan_id="PLAN-001",
            system_name="Test System",
            system_description="Test",
            validation_level=ValidationLevel.CATEGORY_3,
            in_scope=["Feature A", "Feature B"],
            out_of_scope=["Feature C"],
            test_cases=[sample_test_case],
            test_environments=[{"name": "Test Env", "version": "1.0"}],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
            minimum_pass_rate=0.95,
        )
        validator.validation_plans["PLAN-001"] = plan

        # Add passing test result
        test_result = TestResult(
            result_id="TR-001",
            test_id=sample_test_case.test_id,
            execution_date=datetime.utcnow(),
            executed_by="tester",
            status=TestStatus.PASSED,
            actual_results=[],
        )
        validator.test_results[sample_test_case.test_id] = [test_result]

        # Complete validation
        report = validator.complete_validation(
            plan_id="PLAN-001",
            recommendations=["System ready for production"],
        )

        assert report.validation_status == "validated"
        assert report.pass_rate == 1.0
        assert report.tests_passed == 1
        assert report.tests_failed == 0
        assert len(report.recommendations) == 1
        assert plan.status == "completed"

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.system.audit_event")
    def test_complete_validation_with_failures(
        self, mock_audit, mock_user, mock_sig_user, validator
    ):
        """Test completing validation with some failures."""
        # Mock authenticated user
        user_mock = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_user.return_value = user_mock
        mock_sig_user.return_value = user_mock

        # Create multiple test cases
        test_cases = []
        for i in range(5):
            tc = TestCase(
                test_id=f"TC-{i}",
                name=f"Test {i}",
                description=f"Test case {i}",
                test_type=TestType.SYSTEM,
                preconditions=[],
                test_steps=[],
                postconditions=[],
                requirements=[f"REQ-{i}"],
            )
            test_cases.append(tc)
            validator.test_cases[tc.test_id] = tc

        # Create plan
        plan = SystemValidationPlan(
            plan_id="PLAN-002",
            system_name="Test System",
            system_description="Test",
            validation_level=ValidationLevel.CATEGORY_4,
            in_scope=[],
            out_of_scope=[],
            test_cases=test_cases,
            test_environments=[],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
            minimum_pass_rate=0.8,
        )
        validator.validation_plans["PLAN-002"] = plan

        # Add test results - 4 pass, 1 fail
        for i in range(5):
            status = TestStatus.FAILED if i == 2 else TestStatus.PASSED
            result = TestResult(
                result_id=f"TR-{i}",
                test_id=f"TC-{i}",
                execution_date=datetime.utcnow(),
                executed_by="tester",
                status=status,
                actual_results=[],
                defects=[{"id": f"BUG-{i}"}] if status == TestStatus.FAILED else [],
            )
            validator.test_results[f"TC-{i}"] = [result]

        # Complete validation
        report = validator.complete_validation(
            plan_id="PLAN-002",
            recommendations=["Fix defects and retest"],
        )

        assert report.validation_status == "conditionally_validated"  # 80% pass rate
        assert report.pass_rate == 0.8
        assert report.tests_passed == 4
        assert report.tests_failed == 1
        assert len(report.defect_summary) == 1

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.system.audit_event")
    def test_complete_validation_critical_test_failure(
        self, mock_audit, mock_user, mock_sig_user, validator, sample_test_case
    ):
        """Test completing validation with critical test failure."""
        # Mock authenticated user
        user_mock = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_user.return_value = user_mock
        mock_sig_user.return_value = user_mock

        # Create plan with critical test
        plan = SystemValidationPlan(
            plan_id="PLAN-003",
            system_name="Test System",
            system_description="Test",
            validation_level=ValidationLevel.CATEGORY_5,
            in_scope=[],
            out_of_scope=[],
            test_cases=[sample_test_case],
            test_environments=[],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
            critical_tests=[sample_test_case.test_id],  # Mark as critical
        )
        validator.validation_plans["PLAN-003"] = plan

        # Add failing result for critical test
        test_result = TestResult(
            result_id="TR-001",
            test_id=sample_test_case.test_id,
            execution_date=datetime.utcnow(),
            executed_by="tester",
            status=TestStatus.FAILED,
            actual_results=[],
        )
        validator.test_results[sample_test_case.test_id] = [test_result]

        # Complete validation
        report = validator.complete_validation(
            plan_id="PLAN-003",
            recommendations=[],
        )

        assert report.validation_status == "not_validated"
        assert len(report.restrictions) == 1
        assert f"Critical test {sample_test_case.test_id}" in report.restrictions[0]

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.access_control.get_current_user")
    def test_complete_validation_unknown_plan(
        self, mock_user, mock_sig_user, validator
    ):
        """Test completing validation with unknown plan."""
        # Mock authenticated user with MFA
        user_mock = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_user.return_value = user_mock
        mock_sig_user.return_value = user_mock

        with pytest.raises(ValueError, match="Unknown validation plan"):
            validator.complete_validation(
                plan_id="UNKNOWN",
                recommendations=[],
            )

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.system.audit_event")
    def test_complete_validation_no_test_results(
        self, mock_audit, mock_user, mock_sig_user, validator, sample_test_case
    ):
        """Test completing validation with no test results."""
        # Mock authenticated user with MFA
        user_mock = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_user.return_value = user_mock
        mock_sig_user.return_value = user_mock

        plan = SystemValidationPlan(
            plan_id="PLAN-004",
            system_name="Test System",
            system_description="Test",
            validation_level=ValidationLevel.CATEGORY_3,
            in_scope=[],
            out_of_scope=[],
            test_cases=[sample_test_case],
            test_environments=[],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
        )
        validator.validation_plans["PLAN-004"] = plan

        # No test results added
        report = validator.complete_validation(
            plan_id="PLAN-004",
            recommendations=[],
        )

        assert report.validation_status == "not_validated"
        assert report.pass_rate == 0
        assert report.total_tests == 0

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.system.audit_event")
    def test_complete_validation_requirements_coverage(
        self, mock_audit, mock_user, mock_sig_user, validator
    ):
        """Test requirements coverage tracking."""
        # Mock authenticated user with MFA
        user_mock = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_user.return_value = user_mock
        mock_sig_user.return_value = user_mock

        # Create test cases with overlapping requirements
        tc1 = TestCase(
            test_id="TC-1",
            name="Test 1",
            description="Test 1",
            test_type=TestType.SYSTEM,
            preconditions=[],
            test_steps=[],
            postconditions=[],
            requirements=["REQ-001", "REQ-002"],
        )
        tc2 = TestCase(
            test_id="TC-2",
            name="Test 2",
            description="Test 2",
            test_type=TestType.SYSTEM,
            preconditions=[],
            test_steps=[],
            postconditions=[],
            requirements=["REQ-002", "REQ-003"],
        )

        for tc in [tc1, tc2]:
            validator.test_cases[tc.test_id] = tc

        plan = SystemValidationPlan(
            plan_id="PLAN-005",
            system_name="Test System",
            system_description="Test",
            validation_level=ValidationLevel.CATEGORY_3,
            in_scope=[],
            out_of_scope=[],
            test_cases=[tc1, tc2],
            test_environments=[],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
        )
        validator.validation_plans["PLAN-005"] = plan

        # Add test results
        for tc in [tc1, tc2]:
            result = TestResult(
                result_id=f"TR-{tc.test_id}",
                test_id=tc.test_id,
                execution_date=datetime.utcnow(),
                executed_by="tester",
                status=TestStatus.PASSED,
                actual_results=[],
            )
            validator.test_results[tc.test_id] = [result]

        report = validator.complete_validation(
            plan_id="PLAN-005",
            recommendations=[],
        )

        # Check requirements coverage
        assert "REQ-001" in report.requirements_coverage
        assert "REQ-002" in report.requirements_coverage
        assert "REQ-003" in report.requirements_coverage
        assert (
            len(report.requirements_coverage["REQ-002"]) == 2
        )  # Covered by both tests


class TestGlobalFunctions:
    """Test module-level functions."""

    def test_get_system_validator(self):
        """Test getting global validator instance."""
        validator1 = get_system_validator()
        validator2 = get_system_validator()
        assert validator1 is validator2  # Same instance

    @patch("gxp_toolkit.validation.system.get_system_validator")
    def test_validate_system(self, mock_get_validator):
        """Test validate_system convenience function."""
        mock_validator = MagicMock()
        mock_get_validator.return_value = mock_validator

        test_case = TestCase(
            test_id="TC-001",
            name="Test",
            description="Test",
            test_type=TestType.SYSTEM,
            preconditions=[],
            test_steps=[],
            postconditions=[],
            requirements=[],
        )

        validate_system(
            system_name="Test System",
            validation_level=ValidationLevel.CATEGORY_3,
            test_cases=[test_case],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
        )

        mock_validator.create_validation_plan.assert_called_once()
        call_args = mock_validator.create_validation_plan.call_args[1]
        assert call_args["system_name"] == "Test System"
        assert call_args["system_description"] == ""
        assert call_args["validation_level"] == ValidationLevel.CATEGORY_3

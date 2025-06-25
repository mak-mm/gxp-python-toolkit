"""Simplified tests for validation framework that match actual implementation."""

from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from gxp_toolkit.validation.compliance import (
    ComplianceCategory,
    ComplianceChecker,
    ComplianceStatus,
    check_compliance,
    get_compliance_checker,
)
from gxp_toolkit.validation.process import (
    ProcessValidator,
    ValidationProtocol,
    ValidationRun,
    ValidationStage,
    ValidationStatus,
    get_process_validator,
    validate_process,
)
from gxp_toolkit.validation.system import (
    SystemValidationPlan,
    SystemValidator,
    ValidationLevel,
    get_system_validator,
)


class TestProcessValidation:
    """Test process validation module."""

    def test_get_process_validator(self):
        """Test getting global process validator."""
        validator1 = get_process_validator()
        validator2 = get_process_validator()

        # Should be same instance
        assert validator1 is validator2
        assert isinstance(validator1, ProcessValidator)

    def test_process_validator_init(self):
        """Test process validator initialization."""
        validator = ProcessValidator()

        # Check it has the required attributes/methods
        assert hasattr(validator, "create_validation_plan")
        assert hasattr(validator, "execute_validation_run")

    def test_validate_process_function(self):
        """Test validate_process convenience function exists."""
        # Just check the function exists and is callable
        assert callable(validate_process)


class TestSystemValidation:
    """Test system validation module."""

    def test_get_system_validator(self):
        """Test getting global system validator."""
        validator1 = get_system_validator()
        validator2 = get_system_validator()

        # Should be same instance
        assert validator1 is validator2
        assert isinstance(validator1, SystemValidator)

    def test_system_validator_init(self):
        """Test system validator initialization."""
        validator = SystemValidator()

        # Check attributes
        assert hasattr(validator, "validation_plans")
        assert hasattr(validator, "test_cases")

    def test_system_validator_methods(self):
        """Test system validator has expected methods."""
        validator = SystemValidator()

        # Check expected methods exist
        assert hasattr(validator, "create_validation_plan")
        assert hasattr(validator, "execute_test")


class TestComplianceValidation:
    """Test compliance validation module."""

    def test_get_compliance_checker(self):
        """Test getting global compliance checker."""
        checker1 = get_compliance_checker()
        checker2 = get_compliance_checker()

        # Should be same instance
        assert checker1 is checker2
        assert isinstance(checker1, ComplianceChecker)

    def test_compliance_checker_has_requirements(self):
        """Test compliance checker loads requirements."""
        checker = ComplianceChecker()

        # Should have pre-loaded requirements
        assert len(checker.requirements) > 0

        # Should have CFR Part 11 requirements
        cfr_reqs = [
            r for r in checker.requirements.values() if "21 CFR Part 11" in r.regulation
        ]
        assert len(cfr_reqs) > 0

    def test_assess_requirement_basic(self):
        """Test basic requirement assessment."""
        checker = ComplianceChecker()

        # Get a requirement
        req_id = list(checker.requirements.keys())[0]

        # Assess with minimal data
        assessment = checker.assess_requirement(
            requirement_id=req_id, evidence=[], findings=["Manual review performed"]
        )

        assert assessment.requirement_id == req_id
        assert isinstance(assessment.status, ComplianceStatus)
        assert len(assessment.findings) > 0

    @patch("gxp_toolkit.validation.compliance.get_current_user")
    @patch("gxp_toolkit.validation.compliance.get_config")
    def test_perform_compliance_check(self, mock_config, mock_user):
        """Test performing compliance check."""
        checker = ComplianceChecker()

        # Setup mocks
        mock_user.return_value = Mock(id="test-user")
        mock_config.return_value = Mock(
            require_mfa=True,
            esignature_meaning_required=True,
            audit_enabled=True,
            audit_retention_days=2555,
            password_min_length=12,
            session_timeout_minutes=30,
        )

        # Perform check - note it requires scope parameter
        report = checker.perform_compliance_check(scope="Full system")

        assert report.scope == "Full system"
        assert report.total_requirements > 0

    def test_check_compliance_function(self):
        """Test check_compliance convenience function exists."""
        # Just verify it's callable
        assert callable(check_compliance)


class TestValidationDataclasses:
    """Test validation dataclass structures."""

    def test_validation_protocol_creation(self):
        """Test creating validation protocol."""
        protocol = ValidationProtocol(
            protocol_id="PROT-001",
            name="Test Protocol",
            description="Test protocol description",
            stage=ValidationStage.IQ,
            version="1.0",
            acceptance_criteria=[{"criterion": "Install complete"}],
            test_procedures=[{"procedure": "Run installer"}],
            sample_size=10,
            created_by="tester",
        )

        assert protocol.protocol_id == "PROT-001"
        assert protocol.stage == ValidationStage.IQ
        assert protocol.sample_size == 10

        # Test to_dict
        data = protocol.to_dict()
        assert data["protocol_id"] == "PROT-001"
        assert data["stage"] == "installation_qualification"

    def test_validation_run_creation(self):
        """Test creating validation run."""
        run = ValidationRun(
            run_id="RUN-001",
            protocol_id="PROT-001",
            run_date=datetime.now(),
            operator="test-operator",
            measurements=[1.0, 2.0, 3.0],
            observations=[{"obs": "Normal"}],
            deviations=[],
            passed=True,
        )

        assert run.run_id == "RUN-001"
        assert run.passed is True
        assert len(run.measurements) == 3

        # Test statistics calculation
        stats = run.calculate_statistics()
        assert "mean" in stats
        assert "cv" in stats  # coefficient of variation

    def test_system_validation_plan_creation(self):
        """Test creating system validation plan."""
        plan = SystemValidationPlan(
            plan_id="PLAN-001",
            system_name="Test System",
            system_description="Test system description",
            validation_level=ValidationLevel.CATEGORY_5,
            test_cases=[],
            start_date=datetime.now(),
            end_date=datetime.now(),
            in_scope=["Module A", "Module B"],
            out_of_scope=["Module C"],
            test_environments=["Dev", "QA"],
        )

        assert plan.plan_id == "PLAN-001"
        assert plan.validation_level == ValidationLevel.CATEGORY_5

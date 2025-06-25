"""
Tests for process validation module.
"""

import statistics
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from gxp_toolkit.validation.process import (
    ProcessValidationPlan,
    ProcessValidationReport,
    ProcessValidator,
    ValidationProtocol,
    ValidationRun,
    ValidationStage,
    ValidationStatus,
    get_process_validator,
    validate_process,
)


class TestValidationProtocol:
    """Test validation protocol functionality."""

    def test_protocol_creation(self):
        """Test creating a validation protocol."""
        protocol = ValidationProtocol(
            protocol_id="PROT-001",
            name="Temperature Validation",
            description="Validate temperature control",
            stage=ValidationStage.PQ,
            version="1.0",
            acceptance_criteria=[{"type": "range", "min": 20.0, "max": 25.0}],
            test_procedures=[
                {"step": 1, "action": "Measure temperature", "expected": "20-25°C"}
            ],
            sample_size=10,
            confidence_level=0.95,
            success_rate_required=0.95,
            created_by="test_user",
        )

        assert protocol.protocol_id == "PROT-001"
        assert protocol.stage == ValidationStage.PQ
        assert protocol.sample_size == 10
        assert protocol.created_date is not None
        assert protocol.approved_date is None

    def test_protocol_to_dict(self):
        """Test converting protocol to dictionary."""
        protocol = ValidationProtocol(
            protocol_id="PROT-002",
            name="Humidity Validation",
            description="Validate humidity control",
            stage=ValidationStage.OQ,
            version="1.0",
            acceptance_criteria=[],
            test_procedures=[],
            sample_size=5,
        )

        data = protocol.to_dict()
        assert data["protocol_id"] == "PROT-002"
        assert data["stage"] == "operational_qualification"
        assert data["sample_size"] == 5
        assert "created_date" in data
        assert data["approved_date"] is None


class TestValidationRun:
    """Test validation run functionality."""

    def test_run_creation(self):
        """Test creating a validation run."""
        run = ValidationRun(
            run_id="RUN-001",
            protocol_id="PROT-001",
            run_date=datetime.utcnow(),
            operator="test_operator",
            measurements=[22.1, 22.3, 22.2, 22.4, 22.0],
            observations=[{"temp_stable": True}],
            deviations=[],
            passed=True,
            comments="All measurements within range",
        )

        assert run.run_id == "RUN-001"
        assert run.operator == "test_operator"
        assert len(run.measurements) == 5
        assert run.passed is True

    def test_calculate_statistics_with_measurements(self):
        """Test calculating statistics with measurements."""
        run = ValidationRun(
            run_id="RUN-002",
            protocol_id="PROT-001",
            run_date=datetime.utcnow(),
            operator="test_operator",
            measurements=[10.0, 12.0, 11.0, 11.5, 10.5],
            observations=[],
            deviations=[],
            passed=True,
        )

        stats = run.calculate_statistics()
        assert stats["mean"] == 11.0
        assert stats["min"] == 10.0
        assert stats["max"] == 12.0
        assert "stdev" in stats
        assert "cv" in stats
        assert stats["cv"] > 0

    def test_calculate_statistics_empty_measurements(self):
        """Test calculating statistics with no measurements."""
        run = ValidationRun(
            run_id="RUN-003",
            protocol_id="PROT-001",
            run_date=datetime.utcnow(),
            operator="test_operator",
            measurements=[],
            observations=[],
            deviations=[],
            passed=False,
        )

        stats = run.calculate_statistics()
        assert stats == {}

    def test_calculate_statistics_single_measurement(self):
        """Test calculating statistics with single measurement."""
        run = ValidationRun(
            run_id="RUN-004",
            protocol_id="PROT-001",
            run_date=datetime.utcnow(),
            operator="test_operator",
            measurements=[10.0],
            observations=[],
            deviations=[],
            passed=True,
        )

        stats = run.calculate_statistics()
        assert stats["mean"] == 10.0
        assert stats["stdev"] == 0
        assert stats["cv"] == 0


class TestProcessValidator:
    """Test process validator functionality."""

    @pytest.fixture
    def validator(self):
        """Create a validator instance."""
        return ProcessValidator()

    @pytest.fixture
    def sample_protocol(self):
        """Create a sample protocol."""
        return ValidationProtocol(
            protocol_id="PROT-TEST",
            name="Test Protocol",
            description="Test description",
            stage=ValidationStage.PQ,
            version="1.0",
            acceptance_criteria=[
                {"type": "range", "min": 20.0, "max": 30.0},
                {"type": "mean_range", "min_mean": 22.0, "max_mean": 28.0},
                {"type": "cv_limit", "max_cv": 5.0},
            ],
            test_procedures=[],
            sample_size=3,
        )

    def test_create_validation_plan(self, validator, sample_protocol):
        """Test creating a validation plan."""
        with patch("gxp_toolkit.validation.process.audit_event"):
            plan = validator.create_validation_plan(
                process_name="Test Process",
                process_description="Test process description",
                protocols=[sample_protocol],
                start_date=datetime.utcnow(),
                end_date=datetime.utcnow() + timedelta(days=30),
                number_of_runs=3,
            )

            assert plan.process_name == "Test Process"
            assert len(plan.protocols) == 1
            assert plan.status == ValidationStatus.PLANNED
            assert plan.plan_id in validator.validation_plans
            assert sample_protocol.protocol_id in validator.validation_protocols

    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.process.audit_event")
    def test_execute_validation_run_success(
        self, mock_audit, mock_user, validator, sample_protocol
    ):
        """Test executing a successful validation run."""
        # Mock authenticated user with MFA
        mock_user.return_value = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )

        # First create a plan with the protocol
        validator.validation_protocols[sample_protocol.protocol_id] = sample_protocol

        run = validator.execute_validation_run(
            protocol_id=sample_protocol.protocol_id,
            operator="test_operator",
            measurements=[25.0, 24.5, 25.5, 24.8, 25.2],
            observations=[{"temp_stable": True}],
            deviations=[],
        )

        assert run.passed is True
        assert run.operator == "test_operator"
        assert len(run.measurements) == 5
        assert sample_protocol.protocol_id in validator.validation_runs

        # Verify audit was called
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args[1]
        assert call_args["action"] == "validation.run.executed"
        assert call_args["details"]["passed"] is True

    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.process.audit_event")
    def test_execute_validation_run_failure(
        self, mock_audit, mock_user, validator, sample_protocol
    ):
        """Test executing a failed validation run."""
        # Mock authenticated user with MFA
        mock_user.return_value = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )

        validator.validation_protocols[sample_protocol.protocol_id] = sample_protocol

        # Measurements outside acceptance criteria
        run = validator.execute_validation_run(
            protocol_id=sample_protocol.protocol_id,
            operator="test_operator",
            measurements=[35.0, 36.0, 34.5],  # Outside range
            observations=[],
            deviations=[{"type": "temperature_excursion", "details": "Too high"}],
        )

        assert run.passed is False
        assert len(run.deviations) == 1

    @patch("gxp_toolkit.access_control.get_current_user")
    def test_execute_validation_run_unknown_protocol(self, mock_user, validator):
        """Test executing run with unknown protocol."""
        # Mock authenticated user with MFA
        mock_user.return_value = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )

        with pytest.raises(ValueError, match="Unknown protocol"):
            validator.execute_validation_run(
                protocol_id="UNKNOWN",
                operator="test_operator",
                measurements=[25.0],
                observations=[],
            )

    def test_evaluate_acceptance_criteria_range(self, validator, sample_protocol):
        """Test evaluating range acceptance criteria."""
        # Within range
        result = validator._evaluate_acceptance_criteria(
            sample_protocol,
            measurements=[25.0, 24.0, 26.0],
            observations=[],
        )
        assert result is True

        # Outside range
        result = validator._evaluate_acceptance_criteria(
            sample_protocol,
            measurements=[25.0, 35.0, 26.0],  # 35.0 is outside range
            observations=[],
        )
        assert result is False

    def test_evaluate_acceptance_criteria_mean_range(self, validator, sample_protocol):
        """Test evaluating mean range acceptance criteria."""
        # Mean within range
        result = validator._evaluate_acceptance_criteria(
            sample_protocol,
            measurements=[24.0, 25.0, 26.0],  # Mean = 25.0
            observations=[],
        )
        assert result is True

        # Mean outside range
        result = validator._evaluate_acceptance_criteria(
            sample_protocol,
            measurements=[20.0, 20.5, 21.0],  # Mean = 20.5, below min_mean
            observations=[],
        )
        assert result is False

    def test_evaluate_acceptance_criteria_cv_limit(self, validator, sample_protocol):
        """Test evaluating CV limit acceptance criteria."""
        # Low CV (good)
        result = validator._evaluate_acceptance_criteria(
            sample_protocol,
            measurements=[25.0, 25.1, 24.9, 25.0],  # Very low variation
            observations=[],
        )
        assert result is True

        # High CV (bad)
        result = validator._evaluate_acceptance_criteria(
            sample_protocol,
            measurements=[20.0, 30.0, 25.0],  # High variation
            observations=[],
        )
        assert result is False

    def test_evaluate_acceptance_criteria_empty_measurements(
        self, validator, sample_protocol
    ):
        """Test evaluating criteria with no measurements."""
        result = validator._evaluate_acceptance_criteria(
            sample_protocol,
            measurements=[],
            observations=[],
        )
        assert result is False

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.process.audit_event")
    def test_complete_validation_success(
        self, mock_audit, mock_user, mock_sig_user, validator, sample_protocol
    ):
        """Test completing validation successfully."""
        # Mock authenticated user with permissions
        user_mock = MagicMock(
            is_authenticated=True,
            has_permission=lambda p: True,
            id="test_user",
            email="test@example.com",
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_user.return_value = user_mock
        mock_sig_user.return_value = user_mock

        # Setup
        plan = ProcessValidationPlan(
            plan_id="PLAN-001",
            process_name="Test Process",
            process_description="Test",
            protocols=[sample_protocol],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
            number_of_runs=3,
        )
        validator.validation_plans["PLAN-001"] = plan
        validator.validation_protocols[sample_protocol.protocol_id] = sample_protocol

        # Add successful runs
        for i in range(3):
            run = ValidationRun(
                run_id=f"RUN-{i}",
                protocol_id=sample_protocol.protocol_id,
                run_date=datetime.utcnow(),
                operator="test_operator",
                measurements=[25.0, 24.5, 25.5],
                observations=[],
                deviations=[],
                passed=True,
            )
            if sample_protocol.protocol_id not in validator.validation_runs:
                validator.validation_runs[sample_protocol.protocol_id] = []
            validator.validation_runs[sample_protocol.protocol_id].append(run)

        # Complete validation
        report = validator.complete_validation(
            plan_id="PLAN-001",
            conclusions="Process validated successfully",
            recommendations=["Continue monitoring"],
        )

        assert report.overall_status == ValidationStatus.COMPLETED
        assert report.plan_id == "PLAN-001"
        assert len(report.recommendations) == 1
        assert "total_measurements" in report.statistical_summary
        assert plan.status == ValidationStatus.COMPLETED

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.validation.process.audit_event")
    def test_complete_validation_failure(
        self, mock_audit, mock_user, mock_sig_user, validator, sample_protocol
    ):
        """Test completing validation with failures."""
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

        # Setup
        plan = ProcessValidationPlan(
            plan_id="PLAN-002",
            process_name="Test Process",
            process_description="Test",
            protocols=[sample_protocol],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
            number_of_runs=3,
        )
        validator.validation_plans["PLAN-002"] = plan
        validator.validation_protocols[sample_protocol.protocol_id] = sample_protocol

        # Add only 2 successful runs (not enough)
        for i in range(2):
            run = ValidationRun(
                run_id=f"RUN-{i}",
                protocol_id=sample_protocol.protocol_id,
                run_date=datetime.utcnow(),
                operator="test_operator",
                measurements=[25.0],
                observations=[],
                deviations=[],
                passed=True,
            )
            if sample_protocol.protocol_id not in validator.validation_runs:
                validator.validation_runs[sample_protocol.protocol_id] = []
            validator.validation_runs[sample_protocol.protocol_id].append(run)

        # Complete validation
        report = validator.complete_validation(
            plan_id="PLAN-002",
            conclusions="Insufficient successful runs",
            recommendations=["Repeat validation"],
        )

        assert report.overall_status == ValidationStatus.REJECTED
        assert plan.status == ValidationStatus.REJECTED

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
                conclusions="Test",
                recommendations=[],
            )

    def test_process_validation_report_to_dict(self):
        """Test converting validation report to dictionary."""
        report = ProcessValidationReport(
            report_id="REPORT-001",
            plan_id="PLAN-001",
            overall_status=ValidationStatus.COMPLETED,
            start_date=datetime.utcnow(),
            completion_date=datetime.utcnow(),
            protocol_results={},
            statistical_summary={"mean": 25.0},
            conclusions="Success",
            recommendations=["Continue"],
            deviations_summary=[],
            prepared_by="test_user",
            prepared_date=datetime.utcnow(),
        )

        data = report.to_dict()
        assert data["report_id"] == "REPORT-001"
        assert data["overall_status"] == "completed"
        assert data["statistical_summary"]["mean"] == 25.0
        assert data["reviewed_by"] is None


class TestGlobalFunctions:
    """Test module-level functions."""

    def test_get_process_validator(self):
        """Test getting global validator instance."""
        validator1 = get_process_validator()
        validator2 = get_process_validator()
        assert validator1 is validator2  # Same instance

    @patch("gxp_toolkit.validation.process.get_process_validator")
    def test_validate_process(self, mock_get_validator):
        """Test validate_process convenience function."""
        mock_validator = MagicMock()
        mock_get_validator.return_value = mock_validator

        protocol = ValidationProtocol(
            protocol_id="PROT-001",
            name="Test",
            description="Test",
            stage=ValidationStage.PQ,
            version="1.0",
            acceptance_criteria=[],
            test_procedures=[],
            sample_size=3,
        )

        validate_process(
            process_name="Test Process",
            protocols=[protocol],
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
        )

        mock_validator.create_validation_plan.assert_called_once()
        call_args = mock_validator.create_validation_plan.call_args[1]
        assert call_args["process_name"] == "Test Process"
        assert call_args["process_description"] == ""
        assert len(call_args["protocols"]) == 1

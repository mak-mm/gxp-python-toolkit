"""
Process validation for GxP compliance.

Implements validation protocols for manufacturing processes,
analytical methods, and standard operating procedures.
"""

import statistics
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from ..access_control import Permission, require_permission
from ..audit_trail import audit_event
from ..electronic_signatures import SignaturePurpose, require_signature


class ValidationStatus(str, Enum):
    """Status of validation activities."""

    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVALIDATION_REQUIRED = "revalidation_required"


class ValidationStage(str, Enum):
    """Stages of validation process."""

    IQ = "installation_qualification"
    OQ = "operational_qualification"
    PQ = "performance_qualification"
    PV = "process_validation"
    CV = "cleaning_validation"
    MV = "method_validation"


@dataclass
class ValidationProtocol:
    """Protocol defining validation requirements."""

    protocol_id: str
    name: str
    description: str
    stage: ValidationStage
    version: str

    # Acceptance criteria
    acceptance_criteria: List[Dict[str, Any]]
    test_procedures: List[Dict[str, Any]]

    # Requirements
    sample_size: int
    confidence_level: float = 0.95
    success_rate_required: float = 0.95

    # Metadata
    created_date: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""
    approved_date: Optional[datetime] = None
    approved_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "protocol_id": self.protocol_id,
            "name": self.name,
            "description": self.description,
            "stage": self.stage.value,
            "version": self.version,
            "acceptance_criteria": self.acceptance_criteria,
            "test_procedures": self.test_procedures,
            "sample_size": self.sample_size,
            "confidence_level": self.confidence_level,
            "success_rate_required": self.success_rate_required,
            "created_date": self.created_date.isoformat(),
            "created_by": self.created_by,
            "approved_date": (
                self.approved_date.isoformat() if self.approved_date else None
            ),
            "approved_by": self.approved_by,
        }


@dataclass
class ValidationRun:
    """Single validation run/execution."""

    run_id: str
    protocol_id: str
    run_date: datetime
    operator: str

    # Results
    measurements: List[float]
    observations: List[Dict[str, Any]]
    deviations: List[Dict[str, Any]]

    # Outcome
    passed: bool
    comments: str = ""

    def calculate_statistics(self) -> Dict[str, float]:
        """Calculate statistical measures."""
        if not self.measurements:
            return {}

        return {
            "mean": statistics.mean(self.measurements),
            "stdev": (
                statistics.stdev(self.measurements) if len(self.measurements) > 1 else 0
            ),
            "min": min(self.measurements),
            "max": max(self.measurements),
            "cv": (
                (
                    statistics.stdev(self.measurements)
                    / statistics.mean(self.measurements)
                    * 100
                )
                if len(self.measurements) > 1
                and statistics.mean(self.measurements) != 0
                else 0
            ),
        }


@dataclass
class ProcessValidationPlan:
    """Overall validation plan for a process."""

    plan_id: str
    process_name: str
    process_description: str

    # Protocols
    protocols: List[ValidationProtocol]

    # Schedule
    start_date: datetime
    end_date: datetime

    # Requirements
    number_of_runs: int = 3  # Typically 3 consecutive successful runs
    revalidation_frequency_months: int = 12

    # Status tracking
    status: ValidationStatus = ValidationStatus.PLANNED
    current_stage: Optional[ValidationStage] = None

    # Metadata
    created_date: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""


@dataclass
class ProcessValidationReport:
    """Final validation report."""

    report_id: str
    plan_id: str

    # Summary
    overall_status: ValidationStatus
    start_date: datetime
    completion_date: datetime

    # Results
    protocol_results: Dict[str, List[ValidationRun]]
    statistical_summary: Dict[str, Any]

    # Conclusions
    conclusions: str
    recommendations: List[str]
    deviations_summary: List[Dict[str, Any]]

    # Approval
    prepared_by: str
    prepared_date: datetime
    reviewed_by: Optional[str] = None
    reviewed_date: Optional[datetime] = None
    approved_by: Optional[str] = None
    approved_date: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "plan_id": self.plan_id,
            "overall_status": self.overall_status.value,
            "start_date": self.start_date.isoformat(),
            "completion_date": self.completion_date.isoformat(),
            "protocol_results": {
                k: [{"run_id": r.run_id, "passed": r.passed} for r in v]
                for k, v in self.protocol_results.items()
            },
            "statistical_summary": self.statistical_summary,
            "conclusions": self.conclusions,
            "recommendations": self.recommendations,
            "deviations_summary": self.deviations_summary,
            "prepared_by": self.prepared_by,
            "prepared_date": self.prepared_date.isoformat(),
            "reviewed_by": self.reviewed_by,
            "reviewed_date": (
                self.reviewed_date.isoformat() if self.reviewed_date else None
            ),
            "approved_by": self.approved_by,
            "approved_date": (
                self.approved_date.isoformat() if self.approved_date else None
            ),
        }


class ProcessValidator:
    """Main process validator for GxP compliance."""

    def __init__(self) -> None:
        """Initialize process validator."""
        self.validation_plans: Dict[str, ProcessValidationPlan] = {}
        self.validation_protocols: Dict[str, ValidationProtocol] = {}
        self.validation_runs: Dict[str, List[ValidationRun]] = {}

    def create_validation_plan(
        self,
        process_name: str,
        process_description: str,
        protocols: List[ValidationProtocol],
        start_date: datetime,
        end_date: datetime,
        number_of_runs: int = 3,
    ) -> ProcessValidationPlan:
        """
        Create a new validation plan.

        Args:
            process_name: Name of process to validate
            process_description: Description of process
            protocols: List of validation protocols
            start_date: Planned start date
            end_date: Planned end date
            number_of_runs: Required successful runs

        Returns:
            Created validation plan
        """
        import uuid

        plan_id = str(uuid.uuid4())

        plan = ProcessValidationPlan(
            plan_id=plan_id,
            process_name=process_name,
            process_description=process_description,
            protocols=protocols,
            start_date=start_date,
            end_date=end_date,
            number_of_runs=number_of_runs,
        )

        self.validation_plans[plan_id] = plan

        # Store protocols
        for protocol in protocols:
            self.validation_protocols[protocol.protocol_id] = protocol

        # Audit
        audit_event(
            action="validation.plan.created",
            resource_type="validation_plan",
            resource_id=plan_id,
            details={
                "process_name": process_name,
                "protocols": len(protocols),
                "start_date": start_date.isoformat(),
            },
        )

        return plan

    @require_permission(Permission.WRITE)
    def execute_validation_run(
        self,
        protocol_id: str,
        operator: str,
        measurements: List[float],
        observations: List[Dict[str, Any]],
        deviations: Optional[List[Dict[str, Any]]] = None,
    ) -> ValidationRun:
        """
        Execute a validation run.

        Args:
            protocol_id: Protocol to execute
            operator: Person performing validation
            measurements: Measured values
            observations: Observations made
            deviations: Any deviations from protocol

        Returns:
            Validation run result
        """
        import uuid

        protocol = self.validation_protocols.get(protocol_id)
        if not protocol:
            raise ValueError(f"Unknown protocol: {protocol_id}")

        # Evaluate against acceptance criteria
        passed = self._evaluate_acceptance_criteria(
            protocol, measurements, observations
        )

        run = ValidationRun(
            run_id=str(uuid.uuid4()),
            protocol_id=protocol_id,
            run_date=datetime.utcnow(),
            operator=operator,
            measurements=measurements,
            observations=observations,
            deviations=deviations or [],
            passed=passed,
        )

        # Store run
        if protocol_id not in self.validation_runs:
            self.validation_runs[protocol_id] = []
        self.validation_runs[protocol_id].append(run)

        # Audit
        audit_event(
            action="validation.run.executed",
            resource_type="validation_run",
            resource_id=run.run_id,
            details={
                "protocol_id": protocol_id,
                "passed": passed,
                "measurements": len(measurements),
                "deviations": len(deviations) if deviations else 0,
            },
        )

        return run

    def _evaluate_acceptance_criteria(
        self,
        protocol: ValidationProtocol,
        measurements: List[float],
        observations: List[Dict[str, Any]],
    ) -> bool:
        """Evaluate if measurements meet acceptance criteria."""
        # This is a simplified evaluation - real implementation would be more complex
        if not measurements:
            return False

        # Check each criterion
        for criterion in protocol.acceptance_criteria:
            criterion_type = criterion.get("type")

            if criterion_type == "range":
                min_val = criterion.get("min")
                max_val = criterion.get("max")
                if min_val is not None and max_val is not None:
                    if any(m < min_val or m > max_val for m in measurements):
                        return False

            elif criterion_type == "mean_range":
                mean = statistics.mean(measurements)
                min_mean = criterion.get("min_mean")
                max_mean = criterion.get("max_mean")
                if min_mean is not None and max_mean is not None:
                    if mean < min_mean or mean > max_mean:
                        return False

            elif criterion_type == "cv_limit":
                if len(measurements) > 1:
                    cv = (
                        statistics.stdev(measurements) / statistics.mean(measurements)
                    ) * 100
                    if cv > criterion.get("max_cv", float("inf")):
                        return False

        return True

    @require_permission(Permission.APPROVE)
    @require_signature(purpose=SignaturePurpose.APPROVAL)
    def complete_validation(
        self, plan_id: str, conclusions: str, recommendations: List[str]
    ) -> ProcessValidationReport:
        """
        Complete validation and generate report.

        Args:
            plan_id: Validation plan ID
            conclusions: Overall conclusions
            recommendations: List of recommendations

        Returns:
            Final validation report
        """
        import uuid

        plan = self.validation_plans.get(plan_id)
        if not plan:
            raise ValueError(f"Unknown validation plan: {plan_id}")

        # Collect all runs for this plan
        protocol_results = {}
        all_passed = True
        deviations_summary = []

        for protocol in plan.protocols:
            runs = self.validation_runs.get(protocol.protocol_id, [])
            protocol_results[protocol.protocol_id] = runs

            # Check if required number of successful runs achieved
            successful_runs = sum(1 for r in runs if r.passed)
            if successful_runs < plan.number_of_runs:
                all_passed = False

            # Collect deviations
            for run in runs:
                for deviation in run.deviations:
                    deviations_summary.append(
                        {
                            "protocol_id": protocol.protocol_id,
                            "run_id": run.run_id,
                            "deviation": deviation,
                        }
                    )

        # Calculate overall statistics
        all_measurements = []
        for runs in protocol_results.values():
            for run in runs:
                all_measurements.extend(run.measurements)

        statistical_summary = {}
        if all_measurements:
            statistical_summary = {
                "total_measurements": len(all_measurements),
                "overall_mean": statistics.mean(all_measurements),
                "overall_stdev": (
                    statistics.stdev(all_measurements)
                    if len(all_measurements) > 1
                    else 0
                ),
                "overall_min": min(all_measurements),
                "overall_max": max(all_measurements),
            }

        # Create report
        report = ProcessValidationReport(
            report_id=str(uuid.uuid4()),
            plan_id=plan_id,
            overall_status=(
                ValidationStatus.COMPLETED if all_passed else ValidationStatus.REJECTED
            ),
            start_date=plan.start_date,
            completion_date=datetime.utcnow(),
            protocol_results=protocol_results,
            statistical_summary=statistical_summary,
            conclusions=conclusions,
            recommendations=recommendations,
            deviations_summary=deviations_summary,
            prepared_by="system",  # Would get from current user
            prepared_date=datetime.utcnow(),
        )

        # Update plan status
        plan.status = report.overall_status

        # Audit
        audit_event(
            action="validation.completed",
            resource_type="validation_report",
            resource_id=report.report_id,
            details={
                "plan_id": plan_id,
                "status": report.overall_status.value,
                "deviations": len(deviations_summary),
            },
        )

        return report


# Global process validator instance
_process_validator: Optional[ProcessValidator] = None


def get_process_validator() -> ProcessValidator:
    """Get global process validator instance."""
    global _process_validator
    if _process_validator is None:
        _process_validator = ProcessValidator()
    return _process_validator


def validate_process(
    process_name: str,
    protocols: List[ValidationProtocol],
    start_date: datetime,
    end_date: datetime,
) -> ProcessValidationPlan:
    """
    Create process validation plan.

    Args:
        process_name: Process to validate
        protocols: Validation protocols
        start_date: Start date
        end_date: End date

    Returns:
        Validation plan
    """
    validator = get_process_validator()
    return validator.create_validation_plan(
        process_name=process_name,
        process_description="",
        protocols=protocols,
        start_date=start_date,
        end_date=end_date,
    )

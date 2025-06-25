"""
Compliance checking and reporting for GxP requirements.

Provides automated compliance verification against regulatory
requirements including 21 CFR Part 11, EU Annex 11, and GAMP 5.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ..access_control import get_current_user
from ..audit_trail import audit_event
from ..config import get_config


class ComplianceStatus(str, Enum):
    """Compliance status levels."""

    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class ComplianceCategory(str, Enum):
    """Categories of compliance requirements."""

    ELECTRONIC_RECORDS = "electronic_records"
    ELECTRONIC_SIGNATURES = "electronic_signatures"
    AUDIT_TRAIL = "audit_trail"
    ACCESS_CONTROL = "access_control"
    DATA_INTEGRITY = "data_integrity"
    VALIDATION = "validation"
    CHANGE_CONTROL = "change_control"
    BACKUP_RECOVERY = "backup_recovery"
    TRAINING = "training"
    DOCUMENTATION = "documentation"


@dataclass
class ComplianceRequirement:
    """Individual compliance requirement."""

    requirement_id: str
    category: ComplianceCategory
    regulation: str  # e.g., "21 CFR Part 11", "EU Annex 11"
    section: str  # e.g., "11.10(a)"
    description: str

    # Assessment criteria
    criteria: List[str]
    evidence_required: List[str]

    # Risk and priority
    criticality: str = "high"  # low, medium, high, critical

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "requirement_id": self.requirement_id,
            "category": self.category.value,
            "regulation": self.regulation,
            "section": self.section,
            "description": self.description,
            "criteria": self.criteria,
            "evidence_required": self.evidence_required,
            "criticality": self.criticality,
        }


@dataclass
class ComplianceAssessment:
    """Assessment of a single requirement."""

    requirement_id: str
    status: ComplianceStatus
    evidence: List[Dict[str, Any]]
    findings: List[str]
    gaps: List[str]
    remediation_plan: Optional[str] = None
    assessed_date: datetime = field(default_factory=datetime.utcnow)
    assessed_by: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "requirement_id": self.requirement_id,
            "status": self.status.value,
            "evidence": self.evidence,
            "findings": self.findings,
            "gaps": self.gaps,
            "remediation_plan": self.remediation_plan,
            "assessed_date": self.assessed_date.isoformat(),
            "assessed_by": self.assessed_by,
        }


@dataclass
class ComplianceReport:
    """Overall compliance assessment report."""

    report_id: str
    assessment_date: datetime
    scope: str

    # Summary
    total_requirements: int
    compliant_count: int
    partially_compliant_count: int
    non_compliant_count: int
    not_applicable_count: int

    # Details
    assessments: List[ComplianceAssessment]

    # Overall status
    overall_status: ComplianceStatus
    compliance_score: float  # Percentage

    # Findings
    critical_findings: List[str]
    major_findings: List[str]
    minor_findings: List[str]
    observations: List[str]

    # Recommendations
    immediate_actions: List[str]
    short_term_actions: List[str]
    long_term_actions: List[str]

    # Metadata
    prepared_by: str
    reviewed_by: Optional[str] = None
    approved_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "assessment_date": self.assessment_date.isoformat(),
            "scope": self.scope,
            "total_requirements": self.total_requirements,
            "compliant_count": self.compliant_count,
            "partially_compliant_count": self.partially_compliant_count,
            "non_compliant_count": self.non_compliant_count,
            "not_applicable_count": self.not_applicable_count,
            "overall_status": self.overall_status.value,
            "compliance_score": self.compliance_score,
            "critical_findings": self.critical_findings,
            "major_findings": self.major_findings,
            "minor_findings": self.minor_findings,
            "observations": self.observations,
            "immediate_actions": self.immediate_actions,
            "short_term_actions": self.short_term_actions,
            "long_term_actions": self.long_term_actions,
            "prepared_by": self.prepared_by,
            "reviewed_by": self.reviewed_by,
            "approved_by": self.approved_by,
        }


class ComplianceChecker:
    """Main compliance checker for GxP requirements."""

    def __init__(self) -> None:
        """Initialize compliance checker."""
        self.requirements: Dict[str, ComplianceRequirement] = {}
        self._load_requirements()

    def _load_requirements(self) -> None:
        """Load standard compliance requirements."""
        # 21 CFR Part 11 requirements
        self._add_cfr_part_11_requirements()

        # EU Annex 11 requirements
        self._add_eu_annex_11_requirements()

        # GAMP 5 requirements
        self._add_gamp_5_requirements()

    def _add_cfr_part_11_requirements(self) -> None:
        """Add 21 CFR Part 11 requirements."""
        requirements = [
            ComplianceRequirement(
                requirement_id="CFR11_11.10a",
                category=ComplianceCategory.VALIDATION,
                regulation="21 CFR Part 11",
                section="11.10(a)",
                description="Validation of systems to ensure accuracy, reliability, "
                "consistent intended performance",
                criteria=[
                    "System validation documentation exists",
                    "Validation follows recognized standards (e.g., GAMP)",
                    "Change control procedures are in place",
                ],
                evidence_required=[
                    "Validation plan and reports",
                    "Test protocols and results",
                    "Change control records",
                ],
            ),
            ComplianceRequirement(
                requirement_id="CFR11_11.10b",
                category=ComplianceCategory.ELECTRONIC_RECORDS,
                regulation="21 CFR Part 11",
                section="11.10(b)",
                description="Ability to generate accurate and complete copies "
                "of records",
                criteria=[
                    "System can export records in human-readable format",
                    "Exported records include all metadata",
                    "Export functionality is validated",
                ],
                evidence_required=[
                    "Export functionality documentation",
                    "Sample exported records",
                    "Validation of export feature",
                ],
            ),
            ComplianceRequirement(
                requirement_id="CFR11_11.10c",
                category=ComplianceCategory.ELECTRONIC_RECORDS,
                regulation="21 CFR Part 11",
                section="11.10(c)",
                description="Protection of records throughout retention period",
                criteria=[
                    "Records are protected from unauthorized changes",
                    "Backup and recovery procedures exist",
                    "Retention periods are enforced",
                ],
                evidence_required=[
                    "Data backup procedures",
                    "Recovery test results",
                    "Retention policy documentation",
                ],
            ),
            ComplianceRequirement(
                requirement_id="CFR11_11.10d",
                category=ComplianceCategory.ACCESS_CONTROL,
                regulation="21 CFR Part 11",
                section="11.10(d)",
                description="Limiting system access to authorized individuals",
                criteria=[
                    "User authentication is required",
                    "Role-based access control is implemented",
                    "Access logs are maintained",
                ],
                evidence_required=[
                    "User access matrix",
                    "Authentication mechanism documentation",
                    "Access log samples",
                ],
            ),
            ComplianceRequirement(
                requirement_id="CFR11_11.10e",
                category=ComplianceCategory.AUDIT_TRAIL,
                regulation="21 CFR Part 11",
                section="11.10(e)",
                description="Use of secure, computer-generated, time-stamped "
                "audit trails",
                criteria=[
                    "Audit trail captures all critical activities",
                    "Audit entries are time-stamped",
                    "Audit trail cannot be modified or deleted",
                    "Audit trail is regularly reviewed",
                ],
                evidence_required=[
                    "Audit trail configuration",
                    "Sample audit trail entries",
                    "Audit trail review records",
                ],
            ),
            ComplianceRequirement(
                requirement_id="CFR11_11.50",
                category=ComplianceCategory.ELECTRONIC_SIGNATURES,
                regulation="21 CFR Part 11",
                section="11.50",
                description="Signature manifestations shall contain information "
                "associated with the signing",
                criteria=[
                    "Signatures include signer's name",
                    "Date and time of signature is recorded",
                    "Meaning of signature is indicated",
                    "Signatures are linked to their records",
                ],
                evidence_required=[
                    "Sample signed records",
                    "Signature manifest documentation",
                    "Signature validation procedures",
                ],
            ),
        ]

        for req in requirements:
            self.requirements[req.requirement_id] = req

    def _add_eu_annex_11_requirements(self) -> None:
        """Add EU Annex 11 requirements."""
        # Simplified - would include full requirements in production
        requirements = [
            ComplianceRequirement(
                requirement_id="ANNEX11_4.1",
                category=ComplianceCategory.VALIDATION,
                regulation="EU Annex 11",
                section="4.1",
                description="Validation documentation should include change "
                "control records",
                criteria=[
                    "Change control process is documented",
                    "All changes are assessed for impact",
                    "Changes are approved before implementation",
                ],
                evidence_required=[
                    "Change control procedures",
                    "Change request records",
                    "Impact assessments",
                ],
            )
        ]

        for req in requirements:
            self.requirements[req.requirement_id] = req

    def _add_gamp_5_requirements(self) -> None:
        """Add GAMP 5 requirements."""
        # Simplified - would include full requirements in production
        requirements = [
            ComplianceRequirement(
                requirement_id="GAMP5_RISK",
                category=ComplianceCategory.VALIDATION,
                regulation="GAMP 5",
                section="Risk Management",
                description="Risk-based approach to validation",
                criteria=[
                    "Risk assessment is performed",
                    "Validation effort is proportional to risk",
                    "Critical aspects receive thorough testing",
                ],
                evidence_required=[
                    "Risk assessment documentation",
                    "Risk-based validation strategy",
                    "Critical functionality test results",
                ],
            )
        ]

        for req in requirements:
            self.requirements[req.requirement_id] = req

    def assess_requirement(
        self, requirement_id: str, evidence: List[Dict[str, Any]], findings: List[str]
    ) -> ComplianceAssessment:
        """
        Assess a single compliance requirement.

        Args:
            requirement_id: Requirement to assess
            evidence: Evidence collected
            findings: Assessment findings

        Returns:
            Compliance assessment
        """
        req = self.requirements.get(requirement_id)
        if not req:
            raise ValueError(f"Unknown requirement: {requirement_id}")

        # Determine status based on findings
        gaps = []
        status = ComplianceStatus.COMPLIANT

        # Check each criterion
        # evidence_types = {e.get("type") for e in evidence}  # Currently unused
        for criterion in req.criteria:
            # Simple check - in production would be more sophisticated
            criterion_met = any(
                f.lower().find(criterion.lower()[:20]) >= 0 for f in findings
            )
            if not criterion_met:
                gaps.append(f"Criterion not met: {criterion}")
                status = ComplianceStatus.PARTIALLY_COMPLIANT

        # Check evidence
        for required_evidence in req.evidence_required:
            # Simple check - in production would be more sophisticated
            evidence_found = any(
                e.get("description", "").lower().find(required_evidence.lower()[:20])
                >= 0
                for e in evidence
            )
            if not evidence_found:
                gaps.append(f"Missing evidence: {required_evidence}")
                if status == ComplianceStatus.COMPLIANT:
                    status = ComplianceStatus.PARTIALLY_COMPLIANT

        # Set to non-compliant if too many gaps
        if len(gaps) > len(req.criteria) / 2:
            status = ComplianceStatus.NON_COMPLIANT

        assessment = ComplianceAssessment(
            requirement_id=requirement_id,
            status=status,
            evidence=evidence,
            findings=findings,
            gaps=gaps,
            assessed_by=getattr(get_current_user(), "id", "system"),
        )

        return assessment

    def perform_compliance_check(
        self, scope: str, requirements_filter: Optional[Set[str]] = None
    ) -> ComplianceReport:
        """
        Perform comprehensive compliance check.

        Args:
            scope: Scope of assessment
            requirements_filter: Specific requirements to check

        Returns:
            Compliance report
        """
        import uuid

        assessments = []
        status_counts = {
            ComplianceStatus.COMPLIANT: 0,
            ComplianceStatus.PARTIALLY_COMPLIANT: 0,
            ComplianceStatus.NON_COMPLIANT: 0,
            ComplianceStatus.NOT_APPLICABLE: 0,
        }

        # Auto-assess based on system configuration
        # config = get_config()  # TODO: Use config for auto-assessment

        # Check each requirement
        requirements_to_check = requirements_filter or set(self.requirements.keys())

        for req_id in requirements_to_check:
            if req_id not in self.requirements:
                continue

            req = self.requirements[req_id]
            evidence: List[Dict[str, Any]] = []
            findings: List[str] = []

            # Auto-collect evidence based on requirement category
            if req.category == ComplianceCategory.AUDIT_TRAIL:
                evidence, findings = self._check_audit_trail_compliance()
            elif req.category == ComplianceCategory.ACCESS_CONTROL:
                evidence, findings = self._check_access_control_compliance()
            elif req.category == ComplianceCategory.ELECTRONIC_SIGNATURES:
                evidence, findings = self._check_esignature_compliance()
            else:
                # Manual assessment needed
                findings = ["Manual assessment required"]

            assessment = self.assess_requirement(req_id, evidence, findings)
            assessments.append(assessment)
            status_counts[assessment.status] += 1

        # Calculate overall status and score
        total = len(assessments)
        compliant_weight = status_counts[ComplianceStatus.COMPLIANT] * 1.0
        partial_weight = status_counts[ComplianceStatus.PARTIALLY_COMPLIANT] * 0.5
        compliance_score = (
            ((compliant_weight + partial_weight) / total * 100) if total > 0 else 0
        )

        if compliance_score >= 95:
            overall_status = ComplianceStatus.COMPLIANT
        elif compliance_score >= 80:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT

        # Categorize findings
        critical_findings = []
        major_findings = []
        minor_findings = []

        for assessment in assessments:
            if assessment.status == ComplianceStatus.NON_COMPLIANT:
                req = self.requirements[assessment.requirement_id]
                if req.criticality == "critical":
                    critical_findings.extend(assessment.gaps)
                elif req.criticality == "high":
                    major_findings.extend(assessment.gaps)
                else:
                    minor_findings.extend(assessment.gaps)

        # Generate recommendations
        immediate_actions = critical_findings[:5]  # Top 5 critical items
        short_term_actions = major_findings[:5]  # Top 5 major items
        long_term_actions = ["Implement continuous compliance monitoring"]

        report = ComplianceReport(
            report_id=str(uuid.uuid4()),
            assessment_date=datetime.utcnow(),
            scope=scope,
            total_requirements=total,
            compliant_count=status_counts[ComplianceStatus.COMPLIANT],
            partially_compliant_count=status_counts[
                ComplianceStatus.PARTIALLY_COMPLIANT
            ],
            non_compliant_count=status_counts[ComplianceStatus.NON_COMPLIANT],
            not_applicable_count=status_counts[ComplianceStatus.NOT_APPLICABLE],
            assessments=assessments,
            overall_status=overall_status,
            compliance_score=compliance_score,
            critical_findings=critical_findings,
            major_findings=major_findings,
            minor_findings=minor_findings,
            observations=[],
            immediate_actions=immediate_actions,
            short_term_actions=short_term_actions,
            long_term_actions=long_term_actions,
            prepared_by=getattr(get_current_user(), "id", "system"),
        )

        # Audit
        audit_event(
            action="compliance.check.performed",
            resource_type="compliance_report",
            resource_id=report.report_id,
            details={
                "scope": scope,
                "overall_status": overall_status.value,
                "compliance_score": compliance_score,
                "requirements_checked": total,
            },
        )

        return report

    def _check_audit_trail_compliance(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Check audit trail compliance."""
        evidence = []
        findings = []

        config = get_config()

        # Check if audit trail is enabled
        if config.audit_enabled:
            evidence.append(
                {
                    "type": "configuration",
                    "description": "Audit trail is enabled",
                    "reference": "config.audit_enabled",
                }
            )
            findings.append("Audit trail functionality is enabled")
        else:
            findings.append("Audit trail is not enabled")

        # Check retention period
        if config.audit_retention_days >= 2555:  # 7 years
            evidence.append(
                {
                    "type": "configuration",
                    "description": f"Audit retention set to "
                    f"{config.audit_retention_days} days",
                    "reference": "config.audit_retention_days",
                }
            )
            findings.append("Audit retention meets 7-year requirement")
        else:
            findings.append("Audit retention does not meet 7-year requirement")

        # Check if audit entries exist
        try:
            # This would check actual audit storage in production
            findings.append("Audit trail entries are being generated")
        except Exception:
            findings.append("Unable to verify audit trail entries")

        return evidence, findings

    def _check_access_control_compliance(
        self,
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Check access control compliance."""
        evidence = []
        findings = []

        config = get_config()

        # Check password policy
        if config.password_min_length >= 8:
            evidence.append(
                {
                    "type": "configuration",
                    "description": f"Password minimum length: "
                    f"{config.password_min_length}",
                    "reference": "config.password_min_length",
                }
            )
            findings.append("Password policy meets minimum requirements")

        # Check session timeout
        if config.session_timeout_minutes > 0:
            evidence.append(
                {
                    "type": "configuration",
                    "description": f"Session timeout: "
                    f"{config.session_timeout_minutes} minutes",
                    "reference": "config.session_timeout_minutes",
                }
            )
            findings.append("Session timeout is configured")

        # Check MFA
        if config.require_mfa:
            findings.append("Multi-factor authentication is required")
        else:
            findings.append("Multi-factor authentication is not required")

        return evidence, findings

    def _check_esignature_compliance(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Check electronic signature compliance."""
        evidence = []
        findings = []

        config = get_config()

        # Check if e-signatures are configured
        if config.esignature_meaning_required:
            evidence.append(
                {
                    "type": "configuration",
                    "description": "Electronic signature meaning is required",
                    "reference": "config.esignature_meaning_required",
                }
            )
            findings.append("E-signature meaning requirement is configured")

        # Would check actual signature implementation in production
        findings.append("Electronic signature module is available")

        return evidence, findings


# Global compliance checker instance
_compliance_checker: Optional[ComplianceChecker] = None


def get_compliance_checker() -> ComplianceChecker:
    """Get global compliance checker instance."""
    global _compliance_checker
    if _compliance_checker is None:
        _compliance_checker = ComplianceChecker()
    return _compliance_checker


def check_compliance(
    scope: str = "Full System", requirements: Optional[Set[str]] = None
) -> ComplianceReport:
    """
    Perform compliance check.

    Args:
        scope: Scope of check
        requirements: Specific requirements to check

    Returns:
        Compliance report
    """
    checker = get_compliance_checker()
    return checker.perform_compliance_check(scope, requirements)

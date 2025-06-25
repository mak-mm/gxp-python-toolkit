#!/usr/bin/env python3
"""
Validation Framework Example - GxP Python Toolkit

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

Demonstrates GAMP 5 validation lifecycle:
- Installation Qualification (IQ)
- Operational Qualification (OQ)
- Performance Qualification (PQ)
"""

from datetime import datetime, timedelta

# Audit trail and signature imports would be used in full implementation
# from gxp_toolkit.audit_trail import audit_event  # noqa: F401
# from gxp_toolkit.electronic_signatures import SignaturePurpose  # noqa: F401
from gxp_toolkit.validation import (
    ProcessValidator,
    SystemValidator,
    TestCase,
    TestStatus,
    TestType,
    ValidationLevel,
    ValidationProtocol,
    ValidationRun,
    ValidationStage,
)


def create_iq_protocol() -> ValidationProtocol:
    """Create Installation Qualification protocol."""
    return ValidationProtocol(
        protocol_id="IQ-LIMS-2024-001",
        name="Laboratory Information Management System IQ",
        description="Verify correct installation of LIMS v2.0",
        stage=ValidationStage.IQ,
        version="1.0",
        acceptance_criteria=[
            {"criterion": "All software components installed", "critical": True},
            {"criterion": "Database connections established", "critical": True},
            {"criterion": "User permissions configured", "critical": True},
            {"criterion": "Backup systems operational", "critical": False},
        ],
        test_procedures=[
            {"step": 1, "procedure": "Verify software version", "expected": "v2.0.0"},
            {
                "step": 2,
                "procedure": "Check database connectivity",
                "expected": "Connected",
            },
            {
                "step": 3,
                "procedure": "Validate file permissions",
                "expected": "Read/Write",
            },
            {"step": 4, "procedure": "Test backup procedure", "expected": "Successful"},
        ],
    )


def create_oq_protocol() -> ValidationProtocol:
    """Create Operational Qualification protocol."""
    return ValidationProtocol(
        protocol_id="OQ-LIMS-2024-001",
        name="Laboratory Information Management System OQ",
        description="Verify LIMS operates according to specifications",
        stage=ValidationStage.OQ,
        version="1.0",
        acceptance_criteria=[
            {"criterion": "Sample registration functions correctly", "critical": True},
            {"criterion": "Result entry validates ranges", "critical": True},
            {"criterion": "Reports generate accurately", "critical": True},
            {"criterion": "Audit trail captures all changes", "critical": True},
        ],
        test_procedures=[
            {
                "step": 1,
                "procedure": "Register test sample",
                "expected": "Sample ID generated",
            },
            {
                "step": 2,
                "procedure": "Enter out-of-range result",
                "expected": "Warning displayed",
            },
            {"step": 3, "procedure": "Generate COA report", "expected": "PDF created"},
            {
                "step": 4,
                "procedure": "Modify result and check audit",
                "expected": "Change logged",
            },
        ],
    )


def create_pq_protocol() -> ValidationProtocol:
    """Create Performance Qualification protocol."""
    return ValidationProtocol(
        protocol_id="PQ-LIMS-2024-001",
        name="Laboratory Information Management System PQ",
        description="Verify LIMS performs effectively in production environment",
        stage=ValidationStage.PQ,
        version="1.0",
        acceptance_criteria=[
            {"criterion": "Process 100 samples without errors", "critical": True},
            {"criterion": "Generate reports within 5 seconds", "critical": False},
            {"criterion": "Support 20 concurrent users", "critical": True},
            {"criterion": "Maintain 99.9% uptime over test period", "critical": True},
        ],
        test_procedures=[
            {
                "step": 1,
                "procedure": "Process batch of 100 samples",
                "expected": "All processed",
            },
            {
                "step": 2,
                "procedure": "Time report generation",
                "expected": "<5 seconds",
            },
            {
                "step": 3,
                "procedure": "Load test with 20 users",
                "expected": "No errors",
            },
            {"step": 4, "procedure": "Monitor uptime for 7 days", "expected": ">99.9%"},
        ],
        sample_size=100,  # Performance testing sample size
    )


def main():
    """Demonstrate complete validation lifecycle."""
    print("📋 Validation Framework Example (GAMP 5)\n")

    # Initialize validators
    process_validator = ProcessValidator()
    system_validator = SystemValidator()

    # 1. Create validation protocols
    print("1️⃣ Creating Validation Protocols:")

    iq_protocol = create_iq_protocol()
    oq_protocol = create_oq_protocol()
    pq_protocol = create_pq_protocol()

    protocols = [iq_protocol, oq_protocol, pq_protocol]

    for protocol in protocols:
        process_validator.protocols[protocol.protocol_id] = protocol
        print(f"  ✓ Created {protocol.stage.value}: {protocol.name}")

    # 2. Create test cases for system validation
    print("\n2️⃣ Creating Test Cases:")

    test_cases = [
        TestCase(
            test_id="TC-001",
            name="Verify User Authentication",
            description="Ensure only authorized users can access system",
            test_type=TestType.SECURITY,
            preconditions=["System installed", "Test users created"],
            test_steps=[
                {
                    "step": "1",
                    "action": "Login with valid credentials",
                    "expected": "Access granted",
                },
                {
                    "step": "2",
                    "action": "Login with invalid password",
                    "expected": "Access denied",
                },
                {
                    "step": "3",
                    "action": "Check audit log",
                    "expected": "Login attempts recorded",
                },
            ],
            postconditions=["User session active", "Audit trail updated"],
            requirements=["REQ-SEC-001", "REQ-AUD-001"],
            risk_level="high",
        ),
        TestCase(
            test_id="TC-002",
            name="Data Integrity Verification",
            description="Verify data integrity controls are functional",
            test_type=TestType.INTEGRATION,
            preconditions=["System operational", "Test data available"],
            test_steps=[
                {
                    "step": "1",
                    "action": "Create test record",
                    "expected": "Record created",
                },
                {"step": "2", "action": "Modify record", "expected": "Change tracked"},
                {
                    "step": "3",
                    "action": "Verify checksum",
                    "expected": "Checksum valid",
                },
            ],
            postconditions=["Data integrity maintained"],
            requirements=["REQ-DI-001", "REQ-DI-002"],
            risk_level="high",
        ),
    ]

    for tc in test_cases:
        print(f"  ✓ Test case {tc.test_id}: {tc.name}")

    # 3. Execute Installation Qualification
    print("\n3️⃣ Executing Installation Qualification (IQ):")

    iq_run = ValidationRun(
        run_id="RUN-IQ-001",
        protocol_id=iq_protocol.protocol_id,
        run_date=datetime.utcnow(),
        operator="validation_engineer_01",
        environment="Production",
        measurements=[],  # IQ typically doesn't have measurements
        observations=[
            "Software version confirmed as v2.0.0",
            "Database connection successful",
            "All file permissions correct",
            "Backup completed in 4.2 minutes",
        ],
        deviations=[],
        passed=True,
    )

    # Record results
    process_validator.execute_protocol(
        protocol_id=iq_protocol.protocol_id, run_data=iq_run
    )

    print(f"  ✓ IQ executed by: {iq_run.operator}")
    print(f"  ✓ Result: {'PASSED' if iq_run.passed else 'FAILED'}")
    print(f"  ✓ Observations: {len(iq_run.observations)}")

    # 4. Execute Operational Qualification
    print("\n4️⃣ Executing Operational Qualification (OQ):")

    oq_run = ValidationRun(
        run_id="RUN-OQ-001",
        protocol_id=oq_protocol.protocol_id,
        run_date=datetime.utcnow() + timedelta(days=1),
        operator="validation_engineer_02",
        environment="Production",
        measurements=[],
        observations=[
            "Sample registration generated ID: TST-2024-0042",
            "Out-of-range warning displayed correctly",
            "COA report generated in 2.3 seconds",
            "Audit trail captured all 4 test changes",
        ],
        deviations=[
            "Report footer showed incorrect version - documented as known issue"
        ],
        passed=True,
    )

    process_validator.execute_protocol(
        protocol_id=oq_protocol.protocol_id, run_data=oq_run
    )

    print(f"  ✓ OQ executed by: {oq_run.operator}")
    print(f"  ✓ Result: {'PASSED' if oq_run.passed else 'FAILED'}")
    print(f"  ✓ Deviations: {len(oq_run.deviations)}")

    # 5. Execute Performance Qualification
    print("\n5️⃣ Executing Performance Qualification (PQ):")

    # Simulate performance measurements
    report_times = [4.2, 3.8, 4.5, 4.1, 4.9, 3.9, 4.3, 4.0, 4.4, 4.2]  # seconds

    pq_run = ValidationRun(
        run_id="RUN-PQ-001",
        protocol_id=pq_protocol.protocol_id,
        run_date=datetime.utcnow() + timedelta(days=7),
        operator="validation_engineer_01",
        environment="Production",
        measurements=report_times,
        observations=[
            "Processed 100 samples successfully",
            "Average report time: 4.23 seconds",
            "20 concurrent users supported",
            "Uptime: 99.97% over 7 days",
        ],
        deviations=[],
        passed=True,
    )

    process_validator.execute_protocol(
        protocol_id=pq_protocol.protocol_id, run_data=pq_run
    )

    # Calculate statistics
    stats = pq_run.calculate_statistics()

    print(f"  ✓ PQ executed by: {pq_run.operator}")
    print(f"  ✓ Result: {'PASSED' if pq_run.passed else 'FAILED'}")
    print("  ✓ Performance stats:")
    print(f"    - Mean response time: {stats['mean']:.2f} seconds")
    print(f"    - Std deviation: {stats['std_dev']:.2f}")
    print(f"    - Min/Max: {stats['min']:.2f}/{stats['max']:.2f} seconds")

    # 6. Create system validation plan
    print("\n6️⃣ Creating System Validation Plan:")

    validation_plan = system_validator.create_validation_plan(
        system_name="Laboratory Information Management System",
        system_description="LIMS for clinical laboratory operations",
        validation_level=ValidationLevel.CATEGORY_4,  # Configured software
        test_cases=test_cases,
        start_date=datetime.utcnow(),
        end_date=datetime.utcnow() + timedelta(days=30),
    )

    print(f"  ✓ Validation plan created: {validation_plan.plan_id}")
    print(f"  ✓ System: {validation_plan.system_name}")
    print(f"  ✓ GAMP category: {validation_plan.validation_level.value}")
    print(f"  ✓ Risk level: {validation_plan.risk_assessment['overall_risk']}")

    # 7. Execute system test cases
    print("\n7️⃣ Executing System Test Cases:")

    for test_case in test_cases:
        # Simulate test execution
        actual_results = []
        for step in test_case.test_steps:
            actual_results.append(
                {
                    "step": step["step"],
                    "actual": step["expected"],  # Simulating success
                    "pass": True,
                }
            )

        result = system_validator.execute_test(
            test_id=test_case.test_id,
            executed_by="test_engineer_01",
            actual_results=actual_results,
            status=TestStatus.PASSED,
            comments=f"Test {test_case.test_id} completed successfully",
        )

        print(f"  ✓ {test_case.name}: {result.status.value}")

    # 8. Complete validation
    print("\n8️⃣ Completing System Validation:")

    summary_report = system_validator.complete_validation(
        plan_id=validation_plan.plan_id,
        recommendations=[
            "Implement automated backup monitoring",
            "Schedule annual revalidation",
            "Update user training materials",
        ],
    )

    print(f"  ✓ Validation status: {summary_report.validation_status}")
    print(
        f"  ✓ Tests passed: {summary_report.tests_passed}/{summary_report.total_tests}"
    )
    print(f"  ✓ Pass rate: {summary_report.pass_rate*100:.1f}%")
    print(f"  ✓ Recommendations: {len(summary_report.recommendations)}")

    # 9. Summary
    print("\n9️⃣ Validation Summary:")
    print("  ✅ Installation Qualification - PASSED")
    print("  ✅ Operational Qualification - PASSED")
    print("  ✅ Performance Qualification - PASSED")
    print("  ✅ System Validation - VALIDATED")

    print("\n📌 Key Validation Principles:")
    print("  • Document everything")
    print("  • Test against predefined criteria")
    print("  • Use risk-based approach")
    print("  • Maintain independence")
    print("  • Ensure traceability")
    print("  • Regular revalidation")

    print("\n✅ Validation framework example completed!")


if __name__ == "__main__":
    main()

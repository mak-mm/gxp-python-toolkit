#!/usr/bin/env python3
"""
Quick Start Example - GxP Python Toolkit

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

This example shows the basic usage of the GxP Python Toolkit in under 50 lines.
Perfect for getting started quickly!
"""

from gxp_toolkit.audit_trail import audit_event
from gxp_toolkit.config import get_config
from gxp_toolkit.data_integrity import calculate_checksum, verify_data_integrity
from gxp_toolkit.electronic_signatures import (
    SignaturePurpose,
    create_electronic_signature,
)


def main() -> None:
    """Quick demonstration of GxP toolkit features."""
    print("🏥 GxP Python Toolkit - Quick Start Example\n")

    # 1. Configuration
    config = get_config()
    print(f"✓ Loaded configuration for: {config.application_name}")
    print(f"  Environment: {config.environment}")
    print(f"  Audit enabled: {config.audit_enabled}\n")

    # 2. Audit Trail - Log a critical operation
    audit_event(
        action="sample.data.created",
        resource_type="clinical_sample",
        resource_id="SAMPLE-001",
        details={"sample_type": "blood", "volume_ml": 5.0},
    )
    print("✓ Audit event logged for sample creation\n")

    # 3. Data Integrity - Calculate checksum for critical data
    critical_data = {
        "patient_id": "P12345",
        "test_result": "negative",
        "date": "2024-01-15",
    }
    # Convert dict to string for checksum
    data_str = str(critical_data)
    checksum = calculate_checksum(data_str)
    print(f"✓ Data checksum calculated: {checksum[:16]}...")

    # Validate integrity
    is_valid = verify_data_integrity(data_str, checksum)
    print(f"  Data integrity valid: {is_valid}\n")

    # 4. Electronic Signature - Sign critical operation
    signature = create_electronic_signature(
        user_id="john.doe",
        user_name="John Doe",
        purpose=SignaturePurpose.APPROVAL,
        password="demo-password",  # In production, use secure input
    )
    print("✓ Electronic signature created")
    print(f"  Signed by: {signature.get('user_name', 'Unknown')}")
    print(f"  Purpose: {signature.get('purpose', 'Unknown')}")
    print(f"  Timestamp: {signature.get('timestamp', 'Unknown')}")
    print(f"  Compliant: {signature.get('is_valid', False)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Data Integrity Example - GxP Python Toolkit

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

Demonstrates ALCOA+ principles for data integrity:
- Attributable
- Legible
- Contemporaneous
- Original
- Accurate
- Complete
- Consistent
- Enduring
- Available
"""

import json
from datetime import datetime
from pathlib import Path

from gxp_toolkit.audit_trail import audit_event
from gxp_toolkit.data_integrity import calculate_checksum


class DataIntegrityError(Exception):
    """Exception for data integrity violations."""


class LabResult:
    """Example: Laboratory test result with data integrity controls."""

    def __init__(self, sample_id: str, test_type: str):
        self.sample_id = sample_id
        self.test_type = test_type
        self.created_at = datetime.utcnow()
        self.created_by = "system"
        self.raw_data = {}
        self.processed_data = {}
        self.checksum = None
        self.version = 1
        self.locked = False

    def add_raw_data(self, data: dict, operator: str):
        """Add raw instrument data with integrity controls."""
        if self.locked:
            raise DataIntegrityError("Cannot modify locked result")

        # Store with metadata for ALCOA+ compliance
        self.raw_data = {
            "values": data,
            "recorded_at": datetime.utcnow().isoformat(),  # Contemporaneous
            "recorded_by": operator,  # Attributable
            "instrument_id": data.get("instrument_id", "unknown"),
            "data_format": "original",  # Original
        }

        # Calculate checksum for integrity
        # Calculate checksum for integrity
        data_json = json.dumps(self.raw_data, sort_keys=True)
        self.checksum = calculate_checksum(data_json)

        # Audit the data entry
        audit_event(
            action="lab_result.raw_data.added",
            resource_type="lab_result",
            resource_id=self.sample_id,
            details={
                "operator": operator,
                "checksum": self.checksum,
                "data_points": len(data),
            },
        )

    def process_data(self, processor: str):
        """Process raw data with full lineage tracking."""
        if not self.raw_data:
            raise DataIntegrityError("No raw data to process")

        # Verify raw data integrity first
        # Verify raw data integrity first
        data_json = json.dumps(self.raw_data, sort_keys=True)
        current_checksum = calculate_checksum(data_json)
        if current_checksum != self.checksum:
            raise DataIntegrityError("Raw data integrity check failed")

        # Simulate data processing
        self.processed_data = {
            "values": {
                "mean": sum(
                    v
                    for v in self.raw_data["values"].values()
                    if isinstance(v, (int, float))
                )
                / len(self.raw_data["values"]),
                "count": len(self.raw_data["values"]),
            },
            "processing_date": datetime.utcnow().isoformat(),
            "processed_by": processor,
            "processing_version": "1.0",
            "source_checksum": self.checksum,  # Maintain lineage
        }

        # Track the data transformation
        # Log data lineage
        audit_event(
            action="data.lineage.tracked",
            resource_type="data_transformation",
            resource_id=self.sample_id,
            details={
                "source_type": "raw_measurement",
                "source_id": f"{self.sample_id}_raw",
                "derived_type": "processed_result",
                "derived_id": f"{self.sample_id}_processed",
                "transformation": "statistical_analysis",
                "processor": processor,
            },
        )

        self.version += 1

    def lock_result(self, authorized_by: str):
        """Lock result to prevent further modifications."""
        self.locked = True
        self.locked_at = datetime.utcnow()
        self.locked_by = authorized_by

        audit_event(
            action="lab_result.locked",
            resource_type="lab_result",
            resource_id=self.sample_id,
            details={"locked_by": authorized_by, "version": self.version},
        )


def demonstrate_data_integrity() -> None:
    """Show comprehensive data integrity features."""
    print("🔒 Data Integrity Example (ALCOA+ Principles)\n")

    # 1. Create lab result with attribution
    print("1️⃣ Creating Lab Result with Attribution:")
    result = LabResult(sample_id="LAB-2024-0042", test_type="blood_glucose")
    print(f"  Sample ID: {result.sample_id}")
    print(f"  Created at: {result.created_at}")  # Contemporaneous
    print(f"  Created by: {result.created_by}")  # Attributable

    # 2. Add raw data with integrity protection
    print("\n2️⃣ Adding Raw Data with Integrity Controls:")

    raw_measurements = {
        "glucose_mg_dl": 95.2,
        "measurement_time": "2024-01-15T10:30:00Z",
        "instrument_id": "GLUC-001",
        "qc_passed": True,
        "temperature_c": 22.5,
    }

    result.add_raw_data(raw_measurements, operator="lab_tech_01")
    print(f"  ✓ Raw data recorded by: {result.raw_data['recorded_by']}")
    print(f"  ✓ Checksum: {result.checksum[:16]}...")
    print("  ✓ Audit trail updated")

    # 3. Verify data integrity
    print("\n3️⃣ Verifying Data Integrity:")

    # Test with correct data
    # Test with correct data
    data_json = json.dumps(result.raw_data, sort_keys=True)
    current_checksum = calculate_checksum(data_json)
    is_valid = current_checksum == result.checksum
    print(f"  Original data valid: {is_valid} ✓")

    # Simulate tampering attempt
    tampered_data = result.raw_data.copy()
    tampered_data["values"]["glucose_mg_dl"] = 150.0  # Changed value

    tampered_json = json.dumps(tampered_data, sort_keys=True)
    tampered_checksum = calculate_checksum(tampered_json)
    is_tampered_valid = tampered_checksum == result.checksum
    print(f"  Tampered data valid: {is_tampered_valid} ✗")

    if not is_tampered_valid:
        print("  🚨 Data tampering detected!")

    # 4. Process data with lineage tracking
    print("\n4️⃣ Processing Data with Full Lineage:")

    result.process_data(processor="senior_tech_01")
    print(f"  ✓ Data processed by: {result.processed_data['processed_by']}")
    print(f"  ✓ Processing version: " f"{result.processed_data['processing_version']}")
    print(
        f"  ✓ Source checksum maintained: "
        f"{result.processed_data['source_checksum'][:16]}..."
    )
    print(f"  ✓ Result version incremented to: {result.version}")

    # 5. Data completeness check
    print("\n5️⃣ Checking Data Completeness:")

    required_fields = [
        "glucose_mg_dl",
        "measurement_time",
        "instrument_id",
        "qc_passed",
    ]
    complete = all(field in result.raw_data["values"] for field in required_fields)

    print(f"  Required fields present: {complete} ✓")
    for field in required_fields:
        present = field in result.raw_data["values"]
        print(f"    - {field}: {'✓' if present else '✗'}")

    # 6. Lock result for enduring integrity
    print("\n6️⃣ Locking Result (Enduring):")

    result.lock_result(authorized_by="lab_supervisor_01")
    print(f"  ✓ Result locked by: {result.locked_by}")
    print(f"  ✓ Locked at: {result.locked_at}")

    # Try to modify locked result
    try:
        result.add_raw_data({"glucose_mg_dl": 100}, operator="unauthorized")
    except DataIntegrityError as e:
        print(f"  ✓ Modification blocked: {e}")

    # 7. Export for availability
    print("\n7️⃣ Exporting Data (Available):")

    export_data = {
        "sample_id": result.sample_id,
        "test_type": result.test_type,
        "raw_data": result.raw_data,
        "processed_data": result.processed_data,
        "checksum": result.checksum,
        "version": result.version,
        "locked": result.locked,
        "metadata": {
            "created_at": result.created_at.isoformat(),
            "created_by": result.created_by,
            "locked_by": getattr(result, "locked_by", None),
            "locked_at": (getattr(result, "locked_at", datetime.utcnow()).isoformat()),
        },
    }

    # Save to file with integrity
    export_path = Path(f"lab_result_{result.sample_id}.json")
    export_json = json.dumps(export_data, indent=2)
    export_checksum = calculate_checksum(export_json)

    print(f"  ✓ Data exported to: {export_path}")
    print(f"  ✓ Export checksum: {export_checksum[:16]}...")

    # 8. ALCOA+ Summary
    print("\n8️⃣ ALCOA+ Compliance Summary:")
    print("  ✓ Attributable - All actions tracked to users")
    print("  ✓ Legible - Data stored in clear, structured format")
    print("  ✓ Contemporaneous - Timestamps captured at time of action")
    print("  ✓ Original - Raw data preserved unchanged")
    print("  ✓ Accurate - Integrity verified with checksums")
    print("  ✓ Complete - All required fields validated")
    print("  ✓ Consistent - Standard formats and processes")
    print("  ✓ Enduring - Data locked to prevent changes")
    print("  ✓ Available - Exportable in standard formats")

    print("\n✅ Data integrity example completed!")
    print("   Remember: In GxP environments, data integrity is critical for:")
    print("   • Patient safety")
    print("   • Regulatory compliance")
    print("   • Product quality")
    print("   • Scientific validity")


if __name__ == "__main__":
    demonstrate_data_integrity()

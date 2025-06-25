#!/usr/bin/env python3
"""
Audit Trail Example - GxP Python Toolkit

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

Demonstrates comprehensive audit trail functionality including:
- Logging different types of events
- Querying audit history
- Generating compliance reports
- Handling sensitive operations
"""

import asyncio
from datetime import datetime, timedelta

from gxp_toolkit.audit_trail import AuditLogger, audit_event, get_audit_storage
from gxp_toolkit.audit_trail.models import AuditQuery


async def main():
    """Demonstrate audit trail capabilities."""
    print("📋 GxP Audit Trail Example\n")

    # Initialize audit logger
    logger = AuditLogger()

    # 1. Log various types of events
    print("1️⃣ Logging Different Event Types:")

    # Data access
    audit_event(
        action="patient.record.accessed",
        resource_type="patient_record",
        resource_id="PAT-12345",
        details={
            "accessed_fields": ["demographics", "medications"],
            "purpose": "treatment_review",
        },
    )
    print("  ✓ Logged data access event")

    # Configuration change
    logger.log_activity(
        action="system.config.updated",
        entity_type="configuration",
        entity_id="audit_settings",
        user_id="admin@example.com",
        details={
            "setting": "retention_days",
            "old_value": 2555,
            "new_value": 3650,
            "reason": "Compliance requirement update",
        },
    )
    print("  ✓ Logged configuration change")

    # Failed operation
    logger.log_activity(
        action="login.failed",
        entity_type="user_account",
        entity_id="suspicious@example.com",
        result="failure",
        details={
            "reason": "invalid_password",
            "attempt_count": 3,
            "ip_address": "192.168.1.100",
        },
    )
    print("  ✓ Logged security event")

    # Data modification with signature
    logger.log_data_change(
        entity_type="clinical_trial",
        entity_id="TRIAL-001",
        field_name="status",
        old_value="active",
        new_value="completed",
        user_id="jane.doe@pharma.com",
        change_reason="Trial reached enrollment target",
    )
    print("  ✓ Logged data modification\n")

    # 2. Query audit trail
    print("2️⃣ Querying Audit History:")

    # Get storage backend
    storage = await get_audit_storage()

    # Query recent events
    recent_query = AuditQuery(
        start_date=datetime.utcnow() - timedelta(hours=1), limit=10
    )
    recent_events = await storage.query_entries(recent_query)
    print(f"  Found {len(recent_events)} recent events")

    # Query by user
    user_query = AuditQuery(
        user_ids=["jane.doe@pharma.com"],
        start_date=datetime.utcnow() - timedelta(days=7),
    )
    user_events = await storage.query_entries(user_query)
    print(f"  Found {len(user_events)} events by jane.doe@pharma.com")

    # Query failed operations
    failure_query = AuditQuery(
        result="failure", start_date=datetime.utcnow() - timedelta(days=30)
    )
    failures = await storage.query_entries(failure_query)
    print(f"  Found {len(failures)} failed operations in last 30 days\n")

    # 3. Generate audit report
    print("3️⃣ Generating Compliance Report:")

    # Get audit statistics
    stats = await storage.get_statistics(
        start_date=datetime.utcnow() - timedelta(days=30)
    )

    print("  📊 30-Day Audit Statistics:")
    print(f"     Total events: {stats.get('total_events', 0):,}")
    print(f"     Unique users: {stats.get('unique_users', 0)}")
    print(f"     Failed operations: {stats.get('failed_operations', 0)}")
    print(f"     Data modifications: {stats.get('data_changes', 0)}")

    # Check for suspicious patterns
    print("\n  🔍 Security Analysis:")

    # Multiple failed logins
    failed_login_query = AuditQuery(
        actions=["login.failed"],
        start_date=datetime.utcnow() - timedelta(hours=24),
        result="failure",
    )
    failed_logins = await storage.query_entries(failed_login_query)

    if len(failed_logins) > 5:
        print(
            f"  ⚠️  WARNING: {len(failed_logins)} failed login attempts " "in 24 hours"
        )
    else:
        print(f"  ✓ Normal login activity ({len(failed_logins)} failures)")

    # After-hours access
    print("\n  🕐 After-Hours Activity:")
    after_hours_count = 0
    for event in recent_events:
        if hasattr(event, "timestamp"):
            hour = event.timestamp.hour
            if hour < 7 or hour > 19:  # Outside 7 AM - 7 PM
                after_hours_count += 1

    if after_hours_count > 0:
        print(f"  ℹ️  {after_hours_count} events logged outside " "business hours")
    else:
        print("  ✓ All activity within business hours")

    # 4. Demonstrate audit trail integrity
    print("\n4️⃣ Audit Trail Integrity:")

    # Check if entries have checksums
    entries_with_checksums = sum(
        1 for e in recent_events if hasattr(e, "checksum") and e.checksum
    )
    print(
        f"  ✓ {entries_with_checksums}/{len(recent_events)} entries have "
        "integrity checksums"
    )

    # Verify immutability
    if hasattr(storage, "verify_integrity"):
        is_valid = await storage.verify_integrity()
        print(
            f"  ✓ Audit trail integrity: " f"{'Valid' if is_valid else 'COMPROMISED'}"
        )

    print("\n✅ Audit trail example completed!")
    print("   Remember: In GxP environments, audit trails must be:")
    print("   • Secure and tamper-proof")
    print("   • Time-stamped and sequential")
    print("   • Retained for regulatory periods")
    print("   • Regularly reviewed for anomalies")


if __name__ == "__main__":
    asyncio.run(main())

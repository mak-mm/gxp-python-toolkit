Audit Trail Guide
=================

The audit trail module provides comprehensive logging of all critical activities in your GxP system, ensuring compliance with 21 CFR Part 11 and EU Annex 11 requirements.

.. contents:: Table of Contents
   :local:
   :depth: 2

Overview
--------

An audit trail is a secure, computer-generated, time-stamped electronic record that allows reconstruction of events relating to the creation, modification, or deletion of an electronic record.

Key Features
~~~~~~~~~~~~

* **Immutable Records**: Once created, audit records cannot be modified or deleted
* **Automatic Capture**: Decorators for automatic activity logging
* **Comprehensive Metadata**: Who, what, when, where, why, and how
* **Secure Storage**: Multiple backend options with encryption
* **Query Capabilities**: Powerful search and filtering
* **Compliance Reports**: Pre-built report templates

Basic Usage
-----------

Using the Decorator
~~~~~~~~~~~~~~~~~~~

The simplest way to add audit logging is with the ``@log_activity`` decorator:

.. code-block:: python

   from gxp_toolkit import AuditLogger

   audit = AuditLogger()

   @audit.log_activity("USER_LOGIN")
   def login(username: str, ip_address: str) -> dict:
       """User login with audit trail."""
       # Your authentication logic
       return {"status": "success", "user": username}

This automatically captures:

* Function name and parameters
* User identity (from context)
* Timestamp (UTC)
* Return values
* Any exceptions

Manual Logging
~~~~~~~~~~~~~~

For more control, use manual logging:

.. code-block:: python

   audit.log_event(
       action="DATA_EXPORT",
       user="john.doe",
       details={
           "export_type": "CSV",
           "record_count": 1500,
           "destination": "reports/batch_data.csv"
       },
       severity="INFO",
       category="DATA_ACCESS"
   )

Advanced Configuration
----------------------

Storage Backends
~~~~~~~~~~~~~~~~

Configure different storage backends based on your needs:

**PostgreSQL Backend** (Recommended for production)

.. code-block:: python

   from gxp_toolkit import GxPConfig

   config = GxPConfig(
       audit_storage_backend="postgresql",
       audit_connection_string="postgresql://user:pass@localhost/auditdb",
       audit_table_name="audit_trail",
       audit_retention_days=2555  # 7 years
   )

**SQLite Backend** (For development/testing)

.. code-block:: python

   config = GxPConfig(
       audit_storage_backend="sqlite",
       audit_connection_string="sqlite:///audit_trail.db"
   )

**Custom Backend**

.. code-block:: python

   from gxp_toolkit.audit_trail import AuditStorageInterface

   class CustomAuditStorage(AuditStorageInterface):
       """Custom audit storage implementation."""

       async def store_event(self, event: AuditEvent) -> str:
           # Your implementation
           pass

       async def get_event(self, event_id: str) -> AuditEvent:
           # Your implementation
           pass

Security Features
~~~~~~~~~~~~~~~~~

**Encryption at Rest**

.. code-block:: python

   config = GxPConfig(
       audit_encryption_key="your-256-bit-key",
       audit_encrypt_pii=True  # Encrypt personally identifiable information
   )

**Digital Signatures**

.. code-block:: python

   config = GxPConfig(
       audit_sign_events=True,
       audit_signing_key="path/to/private_key.pem"
   )

Querying Audit Data
-------------------

Basic Queries
~~~~~~~~~~~~~

.. code-block:: python

   from datetime import datetime, timedelta

   # Get storage instance
   storage = audit.get_storage()

   # Query by user
   user_events = await storage.query_events(
       user="jane.smith",
       limit=100
   )

   # Query by date range
   recent_events = await storage.query_events(
       start_date=datetime.now() - timedelta(days=30),
       end_date=datetime.now()
   )

   # Query by action
   login_events = await storage.query_events(
       action="USER_LOGIN",
       start_date=datetime.now() - timedelta(hours=24)
   )

Advanced Queries
~~~~~~~~~~~~~~~~

.. code-block:: python

   # Complex query with multiple filters
   critical_events = await storage.query_events(
       severity=["WARNING", "ERROR"],
       category="SECURITY",
       user_pattern="admin_*",  # Wildcard matching
       start_date=datetime.now() - timedelta(days=7)
   )

   # Full-text search in details
   export_events = await storage.search_events(
       search_term="batch_export",
       fields=["action", "details"]
   )

Aggregations
~~~~~~~~~~~~

.. code-block:: python

   # Get event statistics
   stats = await storage.get_statistics(
       start_date=datetime.now() - timedelta(days=30),
       group_by=["action", "user"]
   )

   # Activity timeline
   timeline = await storage.get_timeline(
       granularity="hour",
       start_date=datetime.now() - timedelta(days=1)
   )

Compliance Reporting
--------------------

Pre-built Reports
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from gxp_toolkit.audit_trail import ReportGenerator

   generator = ReportGenerator(storage)

   # 21 CFR Part 11 compliance report
   cfr_report = await generator.generate_cfr11_report(
       start_date=datetime(2024, 1, 1),
       end_date=datetime(2024, 12, 31)
   )

   # User activity report
   user_report = await generator.generate_user_activity_report(
       user="john.doe",
       start_date=datetime.now() - timedelta(days=90)
   )

   # System access report
   access_report = await generator.generate_access_report(
       include_failed_attempts=True,
       start_date=datetime.now() - timedelta(days=30)
   )

Custom Reports
~~~~~~~~~~~~~~

.. code-block:: python

   # Create custom report template
   custom_template = {
       "title": "Critical Operations Report",
       "filters": {
           "severity": ["WARNING", "ERROR"],
           "category": ["DATA_MODIFICATION", "SECURITY"]
       },
       "columns": ["timestamp", "user", "action", "details", "ip_address"],
       "sort_by": "timestamp",
       "group_by": "user"
   }

   custom_report = await generator.generate_custom_report(
       template=custom_template,
       start_date=datetime.now() - timedelta(days=7),
       format="xlsx"  # Options: csv, xlsx, pdf, json
   )

Integration Patterns
--------------------

With Electronic Signatures
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from gxp_toolkit import require_signature

   @audit.log_activity("APPROVE_CHANGE")
   @require_signature("Approve configuration change")
   def approve_change(change_id: str, user: User, password: str):
       """Approve change with signature and audit."""
       # The audit trail will automatically capture:
       # - The signature event
       # - Link to the signature record
       # - All parameters and outcomes
       return {"change_id": change_id, "approved": True}

With Data Integrity
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from gxp_toolkit.data_integrity import track_changes

   @audit.log_activity("DATA_UPDATE")
   @track_changes
   def update_critical_data(record_id: str, new_data: dict):
       """Update data with full change tracking."""
       # Audit trail captures:
       # - Before and after values
       # - Checksums
       # - Change reason
       pass

Batch Operations
~~~~~~~~~~~~~~~~

.. code-block:: python

   @audit.log_activity("BATCH_PROCESS")
   def process_batch(items: list):
       """Process multiple items with audit trail."""
       results = []

       with audit.batch_context() as batch:
           for item in items:
               # Each iteration logged as part of batch
               result = process_item(item)
               batch.add_detail(f"Processed {item['id']}")
               results.append(result)

       return results

Best Practices
--------------

1. **Categorize Events**

   .. code-block:: python

      # Use consistent categories
      CATEGORIES = {
          "AUTHENTICATION": ["LOGIN", "LOGOUT", "PASSWORD_CHANGE"],
          "DATA_ACCESS": ["VIEW", "EXPORT", "REPORT"],
          "DATA_MODIFICATION": ["CREATE", "UPDATE", "DELETE"],
          "SECURITY": ["PERMISSION_CHANGE", "FAILED_ACCESS"],
          "SYSTEM": ["STARTUP", "SHUTDOWN", "CONFIG_CHANGE"]
      }

2. **Include Business Context**

   .. code-block:: python

      @audit.log_activity("BATCH_RELEASE",
                         capture_reason=True,  # Require reason
                         capture_params=True)  # Log all parameters
      def release_batch(batch_id: str, reason: str):
           pass

3. **Handle Sensitive Data**

   .. code-block:: python

      @audit.log_activity("USER_UPDATE",
                         exclude_params=["password", "ssn"],  # Don't log
                         mask_params=["email"])  # Partially mask
      def update_user(user_id: str, email: str, password: str):
           pass

4. **Performance Considerations**

   .. code-block:: python

      # Use async operations for high-throughput systems
      @audit.log_activity_async("HIGH_VOLUME_OPERATION")
      async def process_high_volume(data):
           pass

      # Batch operations for bulk processing
      with audit.batch_context(flush_size=100):
           for item in large_dataset:
               process_item(item)

Troubleshooting
---------------

Common Issues
~~~~~~~~~~~~~

**Storage Connection Issues**

.. code-block:: python

   # Enable connection retry
   config = GxPConfig(
       audit_connection_retry_count=3,
       audit_connection_retry_delay=5  # seconds
   )

**Performance Problems**

.. code-block:: python

   # Enable write buffering
   config = GxPConfig(
       audit_buffer_size=1000,
       audit_flush_interval=30  # seconds
   )

**Query Timeouts**

.. code-block:: python

   # Set query timeout
   events = await storage.query_events(
       user="john.doe",
       timeout=30  # seconds
   )

Monitoring
~~~~~~~~~~

.. code-block:: python

   # Get audit system health
   health = await storage.get_health()
   print(f"Storage status: {health['status']}")
   print(f"Event count: {health['total_events']}")
   print(f"Storage size: {health['storage_size_mb']} MB")

   # Monitor performance
   metrics = await storage.get_metrics()
   print(f"Write latency: {metrics['avg_write_ms']} ms")
   print(f"Query latency: {metrics['avg_query_ms']} ms")

CLI Commands
------------

The toolkit includes CLI commands for audit trail management:

.. code-block:: bash

   # View recent events
   gxp audit tail --follow

   # Search audit trail
   gxp audit search --user john.doe --action LOGIN --days 7

   # Generate report
   gxp audit report --type cfr11 --start 2024-01-01 --output report.pdf

   # Export audit data
   gxp audit export --format csv --start 2024-01-01 --end 2024-12-31

   # Verify audit trail integrity
   gxp audit verify --check-signatures --check-sequence

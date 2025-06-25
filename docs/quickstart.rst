Quick Start Guide
=================

This guide will help you get started with the GxP Python Toolkit in minutes.

Installation
------------

Install from PyPI
~~~~~~~~~~~~~~~~~

.. code-block:: bash

   pip install gxp-python-toolkit

Install from Source
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   git clone https://github.com/gxp-python-toolkit/gxp-python-toolkit.git
   cd gxp-python-toolkit
   pip install -e ".[dev]"

Basic Configuration
-------------------

Create a ``gxp_config.py`` file in your project:

.. code-block:: python

   from gxp_toolkit import GxPConfig

   config = GxPConfig(
       # Audit trail settings
       audit_retention_days=2555,  # 7 years per CFR requirements
       audit_storage_backend="postgresql",

       # Electronic signature settings
       signature_timeout_minutes=15,
       require_password_complexity=True,
       require_mfa=True,  # Multi-factor authentication

       # Access control settings
       max_login_attempts=3,
       session_timeout_minutes=30,

       # Data integrity settings
       checksum_algorithm="sha256",
       require_change_reason=True,
   )

Your First GxP-Compliant Function
---------------------------------

Here's a simple example that demonstrates the key features:

.. code-block:: python

   from gxp_toolkit import AuditLogger, require_signature
   from gxp_toolkit.access_control import require_roles, User
   from gxp_toolkit.data_integrity import track_changes

   # Initialize the audit logger
   audit = AuditLogger()

   @audit.log_activity("CRITICAL_OPERATION")
   @require_signature("Approve critical operation")
   @require_roles(["Supervisor", "QA"])
   @track_changes
   def approve_batch_release(batch_id: str, user: User, password: str, reason: str):
       """
       Approve a batch for release with full GxP compliance.

       This function will:
       1. Verify user has appropriate roles (Supervisor or QA)
       2. Require electronic signature with password
       3. Log all activities to audit trail
       4. Track all data changes

       Args:
           batch_id: The batch identifier
           user: The authenticated user
           password: User's password for signature
           reason: Business reason for approval

       Returns:
           dict: Approval confirmation with timestamp
       """
       # Your business logic here
       result = {
           "batch_id": batch_id,
           "status": "approved",
           "approved_by": user.username,
           "reason": reason
       }

       return result

Using the Function
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Authenticate user
   user = authenticate_user("john.doe", "password123")

   # Call the GxP-compliant function
   try:
       result = approve_batch_release(
           batch_id="BATCH-2024-001",
           user=user,
           password="password123",
           reason="All QC tests passed, meets specifications"
       )
       print(f"Batch {result['batch_id']} approved successfully")
   except PermissionError as e:
       print(f"Access denied: {e}")
   except ValueError as e:
       print(f"Invalid signature: {e}")

What Happens Behind the Scenes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When you call this function:

1. **Access Control**: Verifies the user has "Supervisor" or "QA" role
2. **Electronic Signature**:

   - Validates the password
   - Creates a tamper-proof signature record
   - Links the signature to the specific action

3. **Audit Trail**:

   - Records who did what, when, and why
   - Captures all parameters and results
   - Stores in immutable format

4. **Data Integrity**:

   - Tracks all changes made
   - Maintains chain of custody
   - Ensures ALCOA+ compliance

Working with Audit Trails
-------------------------

Querying Audit Records
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from gxp_toolkit.audit_trail import get_audit_storage
   from datetime import datetime, timedelta

   # Get audit storage instance
   audit_storage = get_audit_storage()

   # Query recent activities
   recent_events = audit_storage.query_events(
       start_date=datetime.now() - timedelta(days=7),
       user="john.doe",
       action="CRITICAL_OPERATION"
   )

   for event in recent_events:
       print(f"{event.timestamp}: {event.user} - {event.action}")
       print(f"  Details: {event.details}")

Generating Audit Reports
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Generate compliance report
   report = audit_storage.generate_report(
       start_date=datetime(2024, 1, 1),
       end_date=datetime(2024, 12, 31),
       format="csv"
   )

   # Save to file
   with open("audit_report_2024.csv", "w") as f:
       f.write(report)

Implementing Soft Delete
------------------------

Never lose critical data with soft delete:

.. code-block:: python

   from sqlalchemy import create_engine, Column, String
   from sqlalchemy.ext.declarative import declarative_base
   from sqlalchemy.orm import sessionmaker
   from gxp_toolkit.soft_delete import SoftDeleteMixin

   Base = declarative_base()

   class CriticalRecord(Base, SoftDeleteMixin):
       __tablename__ = 'critical_records'

       id = Column(String, primary_key=True)
       data = Column(String)
       classification = Column(String)

   # Setup database
   engine = create_engine("postgresql://user:pass@localhost/gxpdb")
   Session = sessionmaker(bind=engine)
   session = Session()

   # Soft delete with audit trail
   record = session.query(CriticalRecord).filter_by(id="REC-001").first()
   record.soft_delete(
       user_id="john.doe",
       reason="Duplicate entry, see REC-002"
   )
   session.commit()

   # Records are never truly deleted
   deleted_records = session.query(CriticalRecord).filter_by(is_deleted=True).all()

Next Steps
----------

Now that you've seen the basics, explore:

1. :doc:`guides/audit_trail` - Deep dive into audit trail configuration
2. :doc:`guides/electronic_signatures` - Advanced signature scenarios
3. :doc:`guides/validation` - Process and system validation
4. :doc:`examples/index` - Real-world implementation examples

Common Patterns
---------------

Batch Processing with Compliance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   @audit.log_activity("BATCH_PROCESSING")
   @require_signature("Start batch processing")
   @track_changes
   def process_batch(batch_data: list, user: User, password: str):
       """Process multiple records with full compliance tracking."""
       results = []

       for item in batch_data:
           # Process each item
           result = process_item(item)
           results.append(result)

       return {
           "processed": len(results),
           "results": results,
           "processor": user.username
       }

Multi-Step Workflows
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   class GxPWorkflow:
       """Multi-step workflow with compliance at each step."""

       @audit.log_activity("WORKFLOW_START")
       @require_roles(["Operator"])
       def start_workflow(self, workflow_id: str, user: User):
           """Start a new workflow."""
           return {"workflow_id": workflow_id, "status": "started"}

       @audit.log_activity("WORKFLOW_REVIEW")
       @require_signature("Review workflow step")
       @require_roles(["Reviewer"])
       def review_step(self, workflow_id: str, user: User, password: str):
           """Review and approve workflow step."""
           return {"workflow_id": workflow_id, "status": "reviewed"}

       @audit.log_activity("WORKFLOW_APPROVE")
       @require_signature("Final workflow approval", require_mfa=True)
       @require_roles(["Manager", "QA"])
       def final_approval(self, workflow_id: str, user: User, password: str):
           """Final approval requiring MFA."""
           return {"workflow_id": workflow_id, "status": "approved"}

Tips for Success
----------------

1. **Always Initialize Early**: Set up your GxP configuration at application startup
2. **Use Decorators Consistently**: Apply compliance decorators to all critical functions
3. **Document Reasons**: Always provide clear business reasons for actions
4. **Test Your Compliance**: Use the provided test utilities to verify compliance
5. **Regular Audits**: Schedule regular audit trail reviews and reports

Getting Help
------------

If you run into issues:

1. Check the :doc:`troubleshooting` guide
2. Review :doc:`faq` for common questions
3. Visit our `GitHub Discussions <https://github.com/gxp-python-toolkit/discussions>`_
4. Report bugs via `GitHub Issues <https://github.com/gxp-python-toolkit/issues>`_

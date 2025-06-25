"""
GxP Python Toolkit - Enterprise-grade compliance tools for life sciences software.

This toolkit provides production-ready implementations of GxP (Good Practice)
requirements for the pharmaceutical, biotechnology, and medical device industries.
It helps developers build software systems that comply with FDA 21 CFR Part 11,
EU Annex 11, and other regulatory requirements.

Key Features
------------
* **Audit Trail**: Automatic, tamper-proof logging of all critical activities
* **Electronic Signatures**: Multi-factor authentication and non-repudiation
* **Data Integrity**: ALCOA+ principles with checksums and change tracking
* **Access Control**: Role-based permissions with session management
* **Soft Delete**: Maintain data integrity with recoverable deletions
* **Validation Framework**: Process and system validation with documentation

Quick Start
-----------
>>> from gxp_toolkit import AuditLogger, require_signature, GxPConfig
>>>
>>> # Configure the toolkit
>>> config = GxPConfig(
...     audit_retention_days=2555,  # 7 years
...     require_mfa=True
... )
>>>
>>> # Create audit logger
>>> audit = AuditLogger()
>>>
>>> # Use decorators for compliance
>>> @audit.log_activity("CRITICAL_OPERATION")
>>> @require_signature("Approve operation")
>>> def perform_critical_operation(data, user, password):
...     '''Perform operation with full GxP compliance.'''
...     return process_data(data)

Compliance Standards
-------------------
This toolkit helps achieve compliance with:

* FDA 21 CFR Part 11 (Electronic Records and Signatures)
* EU GMP Annex 11 (Computerised Systems)
* GAMP 5 (Good Automated Manufacturing Practice)
* ICH Q10 (Pharmaceutical Quality System)
* ISO 13485 (Medical Device Quality Management)
* ALCOA+ Data Integrity Principles

Documentation
-------------
See the /examples directory for usage examples and the /docs directory for documentation.

Support
-------
* Email: manuel.knott@curevac.com

License
-------
MIT License - See LICENSE file for details.

Note: While this toolkit implements GxP compliance patterns, users are
responsible for validating it in their specific environment and ensuring
compliance with applicable regulations.
"""

__version__ = "1.0.0"
__author__ = "Manuel Knott"
__email__ = "manuel.knott@curevac.com"

from .access_control import check_permission, has_role, require_permission

# Import main components for easy access
from .audit_trail import AuditLogger, audit_event
from .config import GxPConfig
from .electronic_signatures import ElectronicSignatureProvider, require_signature
from .soft_delete import SoftDeleteMixin, SoftDeleteService

__all__ = [
    # Audit Trail
    "AuditLogger",
    "audit_event",
    # Electronic Signatures
    "require_signature",
    "ElectronicSignatureProvider",
    # Soft Delete
    "SoftDeleteMixin",
    "SoftDeleteService",
    # Access Control
    "require_permission",
    "check_permission",
    "has_role",
    # Configuration
    "GxPConfig",
]

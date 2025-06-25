GxP Python Toolkit Documentation
================================

.. image:: https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue
   :target: https://www.python.org
   :alt: Python Version

.. image:: https://img.shields.io/badge/License-MIT-yellow.svg
   :target: https://opensource.org/licenses/MIT
   :alt: License

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/psf/black
   :alt: Code style

Welcome to the GxP Python Toolkit documentation! This toolkit provides production-ready modules for implementing GxP-compliant software systems in the life sciences industry.

.. warning::
   While this toolkit implements GxP compliance patterns, users are responsible for validating the toolkit in their specific environment and ensuring compliance with applicable regulations.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   quickstart

.. toctree::
   :maxdepth: 2
   :caption: User Guides

   guides/audit_trail

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/index

.. toctree::
   :maxdepth: 2
   :caption: Development

   troubleshooting

Key Features
------------

**🔍 Audit Trail**
   Automatic audit logging with immutable storage and comprehensive query capabilities.

**✍️ Electronic Signatures**
   21 CFR Part 11 compliant signatures with multiple authentication methods.

**🗑️ Soft Delete**
   Never lose data - mark as deleted with full recovery capabilities.

**🔐 Access Control**
   Role-Based Access Control (RBAC) with permission decorators.

**✅ Data Integrity**
   ALCOA+ compliance with checksum verification and validation.

**📊 Validation Framework**
   Comprehensive validation for processes and computer systems.

Quick Example
-------------

.. code-block:: python

   from gxp_toolkit import AuditLogger, require_signature
   from gxp_toolkit.access_control import require_roles

   # Initialize audit logger
   audit = AuditLogger()

   @audit.log_activity("BATCH_RELEASE")
   @require_signature("Release batch for distribution")
   @require_roles(["QA", "Manager"])
   def release_batch(batch_id: str, user: User, password: str):
       """Release a batch with full GxP compliance."""
       # Your business logic here
       return {"status": "released", "batch_id": batch_id}

Compliance Standards
--------------------

This toolkit helps achieve compliance with:

* 🇺🇸 FDA 21 CFR Part 11
* 🇪🇺 EU Annex 11
* 📊 GAMP 5
* 🔍 ALCOA+ principles
* 📁 ICH Q10

Getting Help
------------

* 📧 Email: support@gxp-toolkit.org
* 💬 `GitHub Discussions <https://github.com/gxp-python-toolkit/discussions>`_
* 🐛 `GitHub Issues <https://github.com/gxp-python-toolkit/issues>`_

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

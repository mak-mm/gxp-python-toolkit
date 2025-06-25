"""
GxP Python Toolkit Examples

This package contains comprehensive examples demonstrating real-world usage
of the GxP Python Toolkit in regulated environments.

Available Examples:
------------------

basic_usage.py
    Simple examples showing core functionality like audit logging,
    electronic signatures, and access control.

pharmaceutical_batch_release.py
    Complete pharmaceutical manufacturing batch release system
    demonstrating multi-level approvals, QC testing, and release
    workflows.

laboratory_lims_integration.py
    Laboratory Information Management System (LIMS) integration
    showing sample tracking, chain of custody, instrument integration,
    and result reporting.

Running Examples:
----------------

Each example can be run standalone:

    python examples/basic_usage.py
    python examples/pharmaceutical_batch_release.py
    python examples/laboratory_lims_integration.py

Note: Most examples use simulated databases and external systems.
For production use, configure real database connections and integrate
with actual systems.

Learning Path:
-------------

1. Start with basic_usage.py to understand core concepts
2. Review pharmaceutical_batch_release.py for workflow examples
3. Study laboratory_lims_integration.py for complex integrations

Additional Resources:
--------------------

- Full documentation: https://gxp-python-toolkit.readthedocs.io
- API reference: https://gxp-python-toolkit.readthedocs.io/api
- GitHub: https://github.com/gxp-python-toolkit/gxp-python-toolkit
"""

# Example categories for easy discovery
EXAMPLES = {
    "basic": ["basic_usage.py - Core functionality demonstration"],
    "manufacturing": ["pharmaceutical_batch_release.py - Batch release workflow"],
    "laboratory": ["laboratory_lims_integration.py - LIMS integration"],
    "clinical": [
        # Future: clinical_trial_management.py
    ],
    "quality": [
        # Future: quality_management_system.py
    ],
}


def list_examples():
    """Print available examples by category."""
    print("GxP Python Toolkit Examples")
    print("=" * 50)

    for category, examples in EXAMPLES.items():
        if examples:
            print(f"\n{category.title()}:")
            for example in examples:
                print(f"  - {example}")


if __name__ == "__main__":
    list_examples()

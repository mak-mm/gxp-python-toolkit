# GxP Python Toolkit Examples

This directory contains practical examples demonstrating how to use the GxP Python Toolkit for various compliance scenarios in life sciences software development.

## 🚀 Quick Start

The easiest way to get started:

```bash
# Install the toolkit
pip install gxp-python-toolkit

# Run the quick start example
python examples/quick_start.py
```

## 📚 Example Scripts

### 1. **quick_start.py** - Getting Started (5 minutes)
A concise example showing the core features in under 50 lines:
- Configuration management
- Audit trail logging
- Data integrity checksums
- Electronic signatures

Perfect for understanding the basics quickly.

### 2. **audit_trail_example.py** - Comprehensive Audit Logging
Learn how to implement 21 CFR Part 11 compliant audit trails:
- Log different types of events (access, changes, failures)
- Query audit history with filters
- Generate compliance reports
- Detect security anomalies
- Verify audit trail integrity

### 3. **electronic_signatures_example.py** - E-Signature Workflows
Implement electronic signature requirements:
- Single and multi-level approval workflows
- Signature manifests for complex approvals
- Signature verification and validation
- Integration with audit trails
- 21 CFR Part 11 compliance features

### 4. **data_integrity_example.py** - ALCOA+ Principles
Ensure data integrity following ALCOA+ principles:
- **A**ttributable - Track who did what
- **L**egible - Clear, structured data
- **C**ontemporaneous - Real-time timestamps
- **O**riginal - Preserve raw data
- **A**ccurate - Integrity verification
- Complete, Consistent, Enduring, Available

### 5. **soft_delete_example.py** - Data Retention Patterns
Implement soft delete for regulatory compliance:
- Preserve data for audit trails
- Cascade soft deletes for related data
- Restore accidentally deleted records
- Retention policy enforcement
- Query deleted records for reports

### 6. **validation_framework_example.py** - GAMP 5 Validation
Complete system validation lifecycle:
- Installation Qualification (IQ)
- Operational Qualification (OQ)
- Performance Qualification (PQ)
- Test case management
- Risk-based validation approach
- Compliance documentation

## 🏢 Industry-Specific Examples

### **pharmaceutical_batch_release.py** - Pharmaceutical Manufacturing
A complete batch release system showing:
- Multi-level QA approvals
- Electronic batch records
- QC test result management
- Deviation handling
- Certificate of Analysis generation

### **laboratory_lims_integration.py** - Clinical Laboratory
Laboratory Information Management System (LIMS) integration:
- Sample accessioning and tracking
- Chain of custody management
- Result entry with range validation
- Instrument integration
- HL7 message generation

## 🛠️ Running the Examples

### Prerequisites

1. Python 3.8 or higher
2. GxP Python Toolkit installed
3. (Optional) SQLAlchemy for database examples

### Basic Usage

```bash
# Run any example directly
python examples/quick_start.py

# Some examples use async features
python examples/audit_trail_example.py

# Database examples create in-memory SQLite databases
python examples/soft_delete_example.py
```

### Environment Setup

For production-like testing, set environment variables:

```bash
export GXP_ENVIRONMENT=development
export GXP_AUDIT_BACKEND=postgresql
export GXP_DATABASE_URL=postgresql://user:pass@localhost/gxpdb
```

## 📖 Learning Path

We recommend going through the examples in this order:

1. **Start Here**: `quick_start.py` - Get familiar with basic concepts
2. **Core Features**:
   - `audit_trail_example.py` - Understand audit logging
   - `electronic_signatures_example.py` - Learn about e-signatures
   - `data_integrity_example.py` - Master data integrity
3. **Advanced Features**:
   - `soft_delete_example.py` - Database patterns
   - `validation_framework_example.py` - System validation
4. **Real-World Applications**:
   - `pharmaceutical_batch_release.py` - Manufacturing scenario
   - `laboratory_lims_integration.py` - Clinical lab scenario

## 🔧 Customization

Each example can be customized for your specific needs:

- Modify configuration values in `quick_start.py`
- Add custom audit event types in `audit_trail_example.py`
- Implement your approval workflow in `electronic_signatures_example.py`
- Define your data models in `soft_delete_example.py`
- Create industry-specific validation protocols in `validation_framework_example.py`

## 📝 Best Practices Demonstrated

All examples follow GxP best practices:

- ✅ Comprehensive audit trails for all operations
- ✅ Electronic signatures for critical actions
- ✅ Data integrity verification
- ✅ Proper error handling and validation
- ✅ Clear separation of concerns
- ✅ Compliance with 21 CFR Part 11
- ✅ GAMP 5 validation approaches

## 🤝 Contributing

Have a great example to share? We welcome contributions! Please:

1. Follow the existing example format
2. Include clear comments explaining GxP concepts
3. Add your example to this README
4. Ensure all regulatory requirements are demonstrated

## 📚 Further Reading

- [FDA 21 CFR Part 11](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/part-11-electronic-records-electronic-signatures-scope-and-application)
- [EU Annex 11](https://ec.europa.eu/health/sites/health/files/files/eudralex/vol-4/annex11_01-2011_en.pdf)
- [GAMP 5 Guide](https://ispe.org/publications/guidance-documents/gamp-5)
- [ALCOA+ Principles](https://www.fda.gov/media/97005/download)

## ❓ Questions?

- Check the [main documentation](../docs/)
- Review the [API reference](../docs/api/)
- Open an [issue](https://github.com/gxp-python-toolkit/gxp-python-toolkit/issues)

---

Remember: These examples are for learning purposes. Always validate your implementation against current regulatory requirements and your organization's SOPs.

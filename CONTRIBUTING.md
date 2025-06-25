# Contributing to GxP Python Toolkit

First off, thank you for considering contributing to the GxP Python Toolkit! It's people like you that make this toolkit a great resource for the life sciences community.

## 📋 Table of Contents


- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)


## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- A GitHub account
- Basic understanding of GxP compliance requirements

### Setting Up Your Development Environment

1. **Fork the repository**
   ```bash
   # Click the 'Fork' button on GitHub
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR-USERNAME/gxp-python-toolkit.git
   cd gxp-python-toolkit
   ```

3. **Add upstream remote**
   ```bash
   git remote add upstream https://github.com/gxp-python-toolkit/gxp-python-toolkit.git
   ```

4. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

5. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

6. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## 💻 Development Process

### Branch Naming Convention

- `feature/` - New features (e.g., `feature/add-csv-export`)
- `fix/` - Bug fixes (e.g., `fix/audit-trail-timezone`)
- `docs/` - Documentation updates (e.g., `docs/update-api-reference`)
- `test/` - Test additions or fixes (e.g., `test/improve-coverage`)
- `refactor/` - Code refactoring (e.g., `refactor/simplify-validation`)

### Workflow

1. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write your code
   - Add/update tests
   - Update documentation

3. **Run tests locally**
   ```bash
   pytest
   pytest --cov=gxp_toolkit --cov-report=term-missing
   ```

4. **Check code quality**
   ```bash
   # Pre-commit will run automatically on commit, but you can run manually:
   pre-commit run --all-files

   # Or run individual tools:
   black .
   isort .
   flake8
   mypy gxp_toolkit
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new validation rule for temperature ranges"
   ```

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, missing semicolons, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks
- `perf:` - Performance improvements

Examples:
```
feat: add support for biometric signatures
fix: correct timezone handling in audit trail
docs: update installation instructions for Windows
test: add edge cases for soft delete service
```

## 📏 Coding Standards

### Python Style Guide

We follow PEP 8 with the following specifications:

- **Line length**: 88 characters (Black default)
- **Imports**: Sorted with `isort`
- **Type hints**: Required for all functions
- **Docstrings**: Google style, required for all public functions

### Example Code

```python
from typing import List, Optional

from gxp_toolkit.audit_trail import AuditEntry


def process_audit_entries(
    entries: List[AuditEntry],
    user_id: Optional[str] = None,
    validate: bool = True,
) -> List[AuditEntry]:
    """
    Process audit entries with optional filtering and validation.

    Args:
        entries: List of audit entries to process
        user_id: Optional user ID to filter by
        validate: Whether to validate entries before processing

    Returns:
        List of processed audit entries

    Raises:
        ValidationError: If validation fails and validate=True
    """
    processed = []

    for entry in entries:
        if user_id and entry.user_id != user_id:
            continue

        if validate:
            entry.validate()

        processed.append(entry)

    return processed
```

### GxP-Specific Requirements

When contributing features that impact compliance:

1. **Audit Trail**: All data modifications must be auditable
2. **Electronic Signatures**: Follow 21 CFR Part 11 requirements
3. **Data Integrity**: Ensure ALCOA+ principles are maintained
4. **Validation**: Add appropriate validation documentation

## 🧪 Testing Requirements

### Test Coverage

- Minimum 80% coverage for new code
- Critical GxP functions require 100% coverage
- Include both positive and negative test cases

### Test Structure

```python
import pytest
from unittest.mock import Mock, patch

from gxp_toolkit.your_module import YourClass


class TestYourClass:
    """Test cases for YourClass."""

    @pytest.fixture
    def instance(self):
        """Create instance for testing."""
        return YourClass()

    def test_normal_operation(self, instance):
        """Test normal operation of the method."""
        result = instance.method("input")
        assert result == "expected"

    def test_edge_case(self, instance):
        """Test edge case handling."""
        with pytest.raises(ValueError):
            instance.method(None)

    @patch("gxp_toolkit.your_module.external_service")
    def test_with_mock(self, mock_service, instance):
        """Test with mocked external service."""
        mock_service.return_value = "mocked"
        result = instance.method_with_service()
        assert result == "processed_mocked"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=gxp_toolkit --cov-report=html

# Run specific test file
pytest tests/test_audit_trail.py

# Run with verbose output
pytest -v

# Run only marked tests
pytest -m "not slow"
```

## 📚 Documentation

### Code Documentation

- All public functions must have docstrings
- Use Google style docstrings
- Include type hints
- Document exceptions that can be raised
- Add usage examples for complex functions

### User Documentation

When adding new features:

1. Update the relevant section in `README.md`
2. Add/update examples in the `examples/` directory
3. Update API documentation if applicable
4. Consider adding a tutorial or guide

### GxP Documentation

For compliance-critical features, also provide:

- Validation rationale
- Risk assessment considerations
- Regulatory mapping (which requirements it addresses)
- Testing recommendations for end users

## 🚢 Submitting Changes

### Pull Request Process

1. **Update your fork**
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Push your branch**
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create Pull Request**
   - Go to GitHub and click "New Pull Request"
   - Select your branch
   - Fill out the PR template completely

### Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] Commit messages follow conventional commits
- [ ] No merge conflicts with main branch
- [ ] Security implications considered
- [ ] GxP compliance maintained

### Review Process

1. Automated checks must pass (tests, linting, type checking)
2. At least one maintainer approval required
3. All review comments addressed
4. No merge conflicts

## 🐛 Reporting Issues

### Before Submitting an Issue

1. Check existing issues (including closed ones)
2. Verify you're using the latest version
3. Try to reproduce with minimal code

### Issue Template

When creating an issue, please include:

- **Description**: Clear description of the issue
- **Steps to Reproduce**: Minimal code example
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: Python version, OS, toolkit version
- **GxP Impact**: Any compliance implications

## 🔒 Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Instead, please email [manuel.knott@curevac.com](mailto:manuel.knott@curevac.com) with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

See our [Security Policy](SECURITY.md) for more details.

## 🎯 What We're Looking For

### High Priority Contributions

- Performance improvements for audit trail queries
- Additional electronic signature methods
- Database backend implementations
- Validation framework enhancements
- Integration examples with popular frameworks

### Good First Issues

Look for issues labeled `good first issue` for:

- Documentation improvements
- Test coverage increases
- Simple bug fixes
- Code cleanup tasks

## 🙏 Recognition

Contributors will be:

- Listed in our CONTRIBUTORS.md file
- Mentioned in release notes
- Given credit in relevant documentation

## 💬 Questions?

- Check our [FAQ](docs/FAQ.md)
- Join our [GitHub Discussions](https://github.com/gxp-python-toolkit/gxp-python-toolkit/discussions)
- Email us at [contribute@gxp-toolkit.org](mailto:contribute@gxp-toolkit.org)

Thank you for helping make GxP Python Toolkit better for everyone! 🎉

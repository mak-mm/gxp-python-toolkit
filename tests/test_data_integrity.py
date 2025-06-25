"""Tests for data integrity module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from gxp_toolkit.config import ChecksumAlgorithm
from gxp_toolkit.data_integrity import (  # Checksums; Validation; Integrity
    ChecksumProvider,
    DataValidator,
    IntegrityChecker,
    IntegrityReport,
    ValidationResult,
    ValidationRule,
    calculate_checksum,
    calculate_file_checksum,
    track_changes,
    validate_data,
    validate_schema,
    verify_checksum,
    verify_data_integrity,
    verify_file_checksum,
)
from gxp_toolkit.data_integrity.integrity import ChangeRecord


class TestChecksumProvider:
    """Test checksum calculation and verification."""

    def test_checksum_calculation(self):
        """Test basic checksum calculation."""
        provider = ChecksumProvider(ChecksumAlgorithm.SHA256)

        # Test string input
        checksum1 = provider.calculate("test data")
        assert isinstance(checksum1, str)
        assert len(checksum1) > 0

        # Test bytes input
        checksum2 = provider.calculate(b"test data")
        assert checksum1 == checksum2

        # Test different data produces different checksums
        checksum3 = provider.calculate("different data")
        assert checksum1 != checksum3

    def test_checksum_hex_format(self):
        """Test hex format checksum."""
        provider = ChecksumProvider(ChecksumAlgorithm.SHA256)

        checksum_hex = provider.calculate_hex("test data")
        assert isinstance(checksum_hex, str)
        assert all(c in "0123456789abcdef" for c in checksum_hex)

    def test_checksum_verification(self):
        """Test checksum verification."""
        provider = ChecksumProvider(ChecksumAlgorithm.SHA256)

        data = "test data for verification"
        checksum = provider.calculate(data)

        # Verify correct checksum
        assert provider.verify(data, checksum) is True

        # Verify incorrect checksum
        assert provider.verify("different data", checksum) is False

        # Verify with hex format
        checksum_hex = provider.calculate_hex(data)
        assert provider.verify(data, checksum_hex) is True

    @pytest.mark.parametrize(
        "algorithm",
        [
            ChecksumAlgorithm.MD5,
            ChecksumAlgorithm.SHA256,
            ChecksumAlgorithm.SHA512,
            ChecksumAlgorithm.BLAKE2B,
        ],
    )
    def test_different_algorithms(self, algorithm):
        """Test different checksum algorithms."""
        provider = ChecksumProvider(algorithm)

        data = "test data"
        checksum = provider.calculate(data)

        assert isinstance(checksum, str)
        assert provider.verify(data, checksum) is True

    def test_file_checksum(self):
        """Test file checksum calculation."""
        provider = ChecksumProvider(ChecksumAlgorithm.SHA256)

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test file content\n" * 100)
            temp_path = f.name

        try:
            # Calculate file checksum
            checksum = provider.calculate_file(temp_path)
            assert isinstance(checksum, str)

            # Verify file checksum
            assert provider.verify_file(temp_path, checksum) is True

            # Modify file and verify checksum fails
            with open(temp_path, "a") as f:
                f.write("additional content")

            assert provider.verify_file(temp_path, checksum) is False

        finally:
            os.unlink(temp_path)

    def test_hmac_calculation(self):
        """Test HMAC calculation and verification."""
        provider = ChecksumProvider(ChecksumAlgorithm.SHA256)

        data = "sensitive data"
        key = "secret_key"

        hmac = provider.calculate_hmac(data, key)
        assert isinstance(hmac, str)

        # Verify HMAC
        assert provider.verify_hmac(data, key, hmac) is True

        # Verify with wrong key
        assert provider.verify_hmac(data, "wrong_key", hmac) is False

        # Verify with wrong data
        assert provider.verify_hmac("wrong data", key, hmac) is False


class TestDataValidator:
    """Test data validation framework."""

    def test_basic_validation(self):
        """Test basic validation rules."""
        validator = DataValidator()

        # Test required field
        rules = {ValidationRule.REQUIRED: True}
        result = validator.validate(None, rules)
        assert result.is_valid is False
        assert len(result.errors) > 0

        result = validator.validate("value", rules)
        assert result.is_valid is True

    def test_string_validation(self):
        """Test string validation rules."""
        validator = DataValidator()

        # Test length validation
        rules = {ValidationRule.MIN_LENGTH: 5, ValidationRule.MAX_LENGTH: 10}

        result = validator.validate("test", rules)
        assert result.is_valid is False  # Too short

        result = validator.validate("valid", rules)
        assert result.is_valid is True

        result = validator.validate("this is too long", rules)
        assert result.is_valid is False  # Too long

    def test_pattern_validation(self):
        """Test regex pattern validation."""
        validator = DataValidator()

        rules = {ValidationRule.PATTERN: r"^\d{3}-\d{3}-\d{4}$"}

        result = validator.validate("123-456-7890", rules)
        assert result.is_valid is True

        result = validator.validate("invalid", rules)
        assert result.is_valid is False

    def test_numeric_validation(self):
        """Test numeric validation rules."""
        validator = DataValidator()

        rules = {ValidationRule.MIN_VALUE: 10, ValidationRule.MAX_VALUE: 100}

        result = validator.validate(50, rules)
        assert result.is_valid is True

        result = validator.validate(5, rules)
        assert result.is_valid is False

        result = validator.validate(150, rules)
        assert result.is_valid is False

    def test_list_validation(self):
        """Test list validation rules."""
        validator = DataValidator()

        rules = {ValidationRule.IN_LIST: ["apple", "banana", "orange"]}

        result = validator.validate("apple", rules)
        assert result.is_valid is True

        result = validator.validate("grape", rules)
        assert result.is_valid is False

    def test_email_validation(self):
        """Test email validation."""
        validator = DataValidator()

        rules = {ValidationRule.EMAIL: True}

        result = validator.validate("user@example.com", rules)
        assert result.is_valid is True

        result = validator.validate("invalid-email", rules)
        assert result.is_valid is False

    def test_dict_validation(self):
        """Test dictionary validation."""
        validator = DataValidator()

        rules = {
            "_required_fields": ["name", "age"],
            "name": {ValidationRule.MIN_LENGTH: 2},
            "age": {ValidationRule.MIN_VALUE: 0},
        }

        data = {"name": "John", "age": 30}
        result = validator.validate(data, rules)
        assert result.is_valid is True

        # Missing required field
        data = {"name": "John"}
        result = validator.validate(data, rules)
        assert result.is_valid is False
        # Check that there are field errors instead
        assert len(result.field_errors) > 0 or len(result.errors) > 0

    def test_custom_validator(self):
        """Test custom validator registration."""
        validator = DataValidator()

        # Register custom validator
        def is_even(value):
            return isinstance(value, int) and value % 2 == 0

        validator.register_validator("even", is_even)

        rules = {ValidationRule.CUSTOM: "even"}

        result = validator.validate(4, rules)
        assert result.is_valid is True

        result = validator.validate(5, rules)
        assert result.is_valid is False

    def test_schema_registration(self):
        """Test schema registration and validation."""
        validator = DataValidator()

        schema = {
            "_required_fields": ["username", "email"],
            "username": {
                ValidationRule.MIN_LENGTH: 3,
                ValidationRule.MAX_LENGTH: 20,
                ValidationRule.PATTERN: r"^[a-zA-Z0-9_]+$",
            },
            "email": {ValidationRule.EMAIL: True},
        }

        validator.register_schema("user_schema", schema)

        # Valid data
        data = {"username": "john_doe", "email": "john@example.com"}
        result = validator.validate(data, schema_name="user_schema")
        assert result.is_valid is True

        # Invalid data
        data = {"username": "jd", "email": "invalid"}
        result = validator.validate(data, schema_name="user_schema")
        assert result.is_valid is False
        assert len(result.field_errors) == 2


class TestIntegrityChecker:
    """Test integrity checking and change tracking."""

    def test_integrity_verification(self):
        """Test data integrity verification."""
        import json

        checker = IntegrityChecker()

        data = {"field1": "value1", "field2": 123}

        # Calculate checksum using the same method as IntegrityChecker
        checksum = checker.checksum_provider.calculate(json.dumps(data, sort_keys=True))

        # Verify integrity with correct checksum
        is_valid, error = checker.verify_integrity(data, checksum)
        assert is_valid is True
        assert error is None

        # Verify integrity with wrong checksum
        is_valid, error = checker.verify_integrity(data, "wrong_checksum")
        assert is_valid is False
        assert "Checksum mismatch" in error

    def test_integrity_with_validation(self):
        """Test integrity verification with validation rules."""
        checker = IntegrityChecker()

        data = {"age": 25}
        rules = {ValidationRule.MIN_VALUE: 18}

        # Valid data
        is_valid, error = checker.verify_integrity(data["age"], validation_rules=rules)
        assert is_valid is True

        # Invalid data
        data = {"age": 15}
        is_valid, error = checker.verify_integrity(data["age"], validation_rules=rules)
        assert is_valid is False
        assert "Validation failed" in error

    @patch("gxp_toolkit.data_integrity.integrity.audit_event")
    def test_collection_verification(self, mock_audit):
        """Test collection integrity verification."""
        import json

        checker = IntegrityChecker()

        # Create test collection
        items = []
        for i in range(3):
            item_data = {"id": f"item-{i}", "value": i}
            # Calculate checksum using the same method as IntegrityChecker
            data_without_checksum = {"id": f"item-{i}", "value": i}
            checksum = checker.checksum_provider.calculate(
                json.dumps(data_without_checksum, sort_keys=True)
            )
            item_data["checksum"] = checksum
            items.append(item_data)

        # Verify collection
        report = checker.verify_collection(items)
        assert report.is_valid is True
        assert report.items_valid == 3
        assert report.items_invalid == 0

        # Corrupt one item
        items[1]["value"] = 999  # Change value but keep old checksum

        report = checker.verify_collection(items)
        assert report.is_valid is False
        assert report.items_valid == 2
        assert report.items_invalid == 1
        assert len(report.errors) == 1

        # Check audit was called
        mock_audit.assert_called()

    @patch("gxp_toolkit.data_integrity.integrity.audit_event")
    def test_change_tracking(self, mock_audit):
        """Test change tracking between data states."""
        checker = IntegrityChecker()

        old_data = {"name": "John", "age": 30, "email": "john@example.com"}

        new_data = {
            "name": "John",
            "age": 31,
            "email": "john.doe@example.com",
            "phone": "123-456-7890",
        }

        changes = checker.track_changes(
            old_data,
            new_data,
            entity_type="user",
            entity_id="user-123",
            user_id="admin",
            reason="Annual update",
        )

        assert len(changes) == 3  # age modified, email modified, phone added

        # Check change types
        change_types = {c.field: c.change_type for c in changes}
        assert change_types["age"] == "modified"
        assert change_types["email"] == "modified"
        assert change_types["phone"] == "added"

        # Check values
        age_change = next(c for c in changes if c.field == "age")
        assert age_change.old_value == 30
        assert age_change.new_value == 31

        # Check audit was called
        mock_audit.assert_called_once()

    def test_change_tracking_with_deletions(self):
        """Test change tracking with field deletions."""
        checker = IntegrityChecker()

        old_data = {"field1": "value1", "field2": "value2"}
        new_data = {"field1": "value1"}

        changes = checker.track_changes(
            old_data, new_data, entity_type="test", entity_id="test-1"
        )

        assert len(changes) == 1
        assert changes[0].field == "field2"
        assert changes[0].change_type == "deleted"
        assert changes[0].old_value == "value2"
        assert changes[0].new_value is None

    def test_change_tracking_with_ignore_fields(self):
        """Test change tracking with ignored fields."""
        checker = IntegrityChecker()

        old_data = {"name": "John", "updated_at": "2023-01-01", "version": 1}

        new_data = {"name": "Jane", "updated_at": "2023-01-02", "version": 2}

        changes = checker.track_changes(
            old_data,
            new_data,
            entity_type="test",
            entity_id="test-1",
            ignore_fields={"updated_at", "version"},
        )

        assert len(changes) == 1
        assert changes[0].field == "name"

    def test_data_signature(self):
        """Test data signature calculation."""
        checker = IntegrityChecker()

        data = {"id": "123", "name": "Test", "value": 42, "metadata": {"key": "value"}}

        # Calculate signature for all fields
        sig1 = checker.calculate_data_signature(data)
        assert isinstance(sig1, str)

        # Calculate signature for specific fields
        sig2 = checker.calculate_data_signature(data, fields_to_sign=["id", "name"])
        assert isinstance(sig2, str)
        assert sig1 != sig2  # Different fields signed

        # Same data produces same signature
        sig3 = checker.calculate_data_signature(data)
        assert sig1 == sig3

    def test_data_lineage_verification(self):
        """Test data lineage verification."""
        import json

        checker = IntegrityChecker()

        # Create parent item
        parent_data = {"id": "parent-1", "data": "parent data"}
        parent = parent_data.copy()
        parent["checksum"] = checker.checksum_provider.calculate(
            json.dumps(parent_data, sort_keys=True)
        )

        # Create child items
        child1_data = {"id": "child-1", "parent_id": "parent-1", "data": "child 1 data"}
        child1 = child1_data.copy()
        child1["checksum"] = checker.checksum_provider.calculate(
            json.dumps(child1_data, sort_keys=True)
        )

        child2 = {"id": "child-2", "parent_id": "non-existent", "data": "child 2 data"}

        items = [parent, child1, child2]

        result = checker.verify_data_lineage(items)
        assert result.is_valid is False
        # Should have error for non-existent parent
        assert any("non-existent parent" in error for error in result.errors)


class TestGlobalFunctions:
    """Test module-level convenience functions."""

    def test_calculate_checksum(self):
        """Test global checksum calculation."""
        checksum = calculate_checksum("test data")
        assert isinstance(checksum, str)

        # With specific algorithm
        checksum2 = calculate_checksum("test data", ChecksumAlgorithm.SHA512)
        assert isinstance(checksum2, str)
        assert checksum != checksum2  # Different algorithms

    def test_verify_checksum(self):
        """Test global checksum verification."""
        data = "test data"
        checksum = calculate_checksum(data)

        assert verify_checksum(data, checksum) is True
        assert verify_checksum("wrong data", checksum) is False

    def test_file_checksum_functions(self):
        """Test global file checksum functions."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test content")
            temp_path = f.name

        try:
            checksum = calculate_file_checksum(temp_path)
            assert isinstance(checksum, str)

            assert verify_file_checksum(temp_path, checksum) is True

        finally:
            os.unlink(temp_path)

    def test_validate_data_function(self):
        """Test global validate_data function."""
        rules = {ValidationRule.MIN_LENGTH: 5}

        result = validate_data("test", rules)
        assert result.is_valid is False

        result = validate_data("valid data", rules)
        assert result.is_valid is True

    def test_validate_schema_function(self):
        """Test validate_schema with Pydantic."""
        from pydantic import BaseModel

        class UserSchema(BaseModel):
            name: str
            age: int

        # Valid data
        result = validate_schema({"name": "John", "age": 30}, UserSchema)
        assert result.is_valid is True

        # Invalid data
        result = validate_schema({"name": "John", "age": "thirty"}, UserSchema)
        assert result.is_valid is False
        assert len(result.field_errors) > 0

    def test_verify_data_integrity_function(self):
        """Test global verify_data_integrity function."""
        import json

        data = {"test": "data"}
        # Use json.dumps to match IntegrityChecker behavior
        checksum = calculate_checksum(json.dumps(data, sort_keys=True))

        is_valid, error = verify_data_integrity(data, checksum)
        assert is_valid is True

        is_valid, error = verify_data_integrity(data, "wrong_checksum")
        assert is_valid is False

    @patch("gxp_toolkit.data_integrity.integrity.audit_event")
    def test_track_changes_function(self, mock_audit):
        """Test global track_changes function."""
        old = {"field": "old"}
        new = {"field": "new"}

        changes = track_changes(old, new, "test", "test-1")
        assert len(changes) == 1
        assert changes[0].change_type == "modified"

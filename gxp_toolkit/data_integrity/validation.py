"""
Data validation framework for GxP compliance.

Provides comprehensive validation capabilities for ensuring
data quality and compliance with regulatory requirements.
"""

import re
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type

from pydantic import BaseModel, ValidationError


class ValidationRule(str, Enum):
    """Standard validation rules."""

    REQUIRED = "required"
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"
    PATTERN = "pattern"
    MIN_VALUE = "min_value"
    MAX_VALUE = "max_value"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    EMAIL = "email"
    URL = "url"
    DATE_FORMAT = "date_format"
    CUSTOM = "custom"


@dataclass
class ValidationResult:
    """Result of validation operation."""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    field_errors: Dict[str, List[str]] = field(default_factory=dict)

    def add_error(self, message: str, field: Optional[str] = None) -> None:
        """Add validation error."""
        self.is_valid = False
        if field:
            if field not in self.field_errors:
                self.field_errors[field] = []
            self.field_errors[field].append(message)
        else:
            self.errors.append(message)

    def add_warning(self, message: str) -> None:
        """Add validation warning."""
        self.warnings.append(message)

    def merge(self, other: "ValidationResult") -> None:
        """Merge another validation result."""
        self.is_valid = self.is_valid and other.is_valid
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        for field_name, errors in other.field_errors.items():
            if field_name not in self.field_errors:
                self.field_errors[field_name] = []
            self.field_errors[field_name].extend(errors)


class DataValidator:
    """Main data validator for GxP compliance."""

    def __init__(self) -> None:
        """Initialize validator."""
        self.custom_validators: Dict[str, Callable[..., bool]] = {}
        self.schemas: Dict[str, Dict[str, Any]] = {}

        # Register built-in validators
        self._register_builtin_validators()

    def _register_builtin_validators(self) -> None:
        """Register built-in validation functions."""
        self.custom_validators["email"] = self._validate_email
        self.custom_validators["url"] = self._validate_url
        self.custom_validators["phone"] = self._validate_phone
        self.custom_validators["alphanumeric"] = self._validate_alphanumeric
        self.custom_validators["numeric"] = self._validate_numeric
        self.custom_validators["alphabetic"] = self._validate_alphabetic

    def register_validator(self, name: str, validator: Callable[[Any], bool]) -> None:
        """
        Register custom validator function.

        Args:
            name: Validator name
            validator: Function that returns True if valid
        """
        self.custom_validators[name] = validator

    def register_schema(self, name: str, schema: Dict[str, Any]) -> None:
        """
        Register validation schema.

        Args:
            name: Schema name
            schema: Validation schema definition
        """
        self.schemas[name] = schema

    def validate(
        self,
        data: Any,
        rules: Optional[Dict[str, Any]] = None,
        schema_name: Optional[str] = None,
    ) -> ValidationResult:
        """
        Validate data against rules or schema.

        Args:
            data: Data to validate
            rules: Validation rules
            schema_name: Name of registered schema

        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)

        # Get rules from schema if specified
        if schema_name:
            if schema_name not in self.schemas:
                result.add_error(f"Unknown schema: {schema_name}")
                return result
            rules = self.schemas[schema_name]

        if not rules:
            result.add_warning("No validation rules specified")
            return result

        # Validate based on data type
        if isinstance(data, dict):
            self._validate_dict(data, rules, result)
        elif isinstance(data, list):
            self._validate_list(data, rules, result)
        else:
            self._validate_value(data, rules, result)

        return result

    def _validate_dict(
        self, data: Dict[str, Any], rules: Dict[str, Any], result: ValidationResult
    ) -> None:
        """Validate dictionary data."""
        for field_name, field_rules in rules.items():
            if field_name == "_required_fields":
                # Check required fields
                for required_field in field_rules:
                    if required_field not in data:
                        result.add_error(
                            f"Required field missing: {required_field}", required_field
                        )
                continue

            # Get field value
            value = data.get(field_name)

            # Validate field
            if isinstance(field_rules, dict):
                self._validate_field(value, field_name, field_rules, result)
            else:
                # Simple type check
                if not isinstance(value, field_rules):
                    result.add_error(
                        f"Field {field_name} must be of type {field_rules.__name__}",
                        field_name,
                    )

    def _validate_list(
        self, data: List[Any], rules: Dict[str, Any], result: ValidationResult
    ) -> None:
        """Validate list data."""
        # Check list constraints
        if "min_length" in rules and len(data) < rules["min_length"]:
            result.add_error(f"List must have at least {rules['min_length']} items")

        if "max_length" in rules and len(data) > rules["max_length"]:
            result.add_error(f"List must have at most {rules['max_length']} items")

        # Validate items if rules specified
        if "items" in rules:
            item_rules = rules["items"]
            for i, item in enumerate(data):
                item_result = ValidationResult(is_valid=True)
                if isinstance(item_rules, dict):
                    self._validate_value(item, item_rules, item_result)
                else:
                    # Type check
                    if not isinstance(item, item_rules):
                        item_result.add_error(
                            f"Item at index {i} must be of type {item_rules.__name__}"
                        )

                # Merge results
                if not item_result.is_valid:
                    for error in item_result.errors:
                        result.add_error(f"Item {i}: {error}")

    def _validate_value(
        self, value: Any, rules: Dict[str, Any], result: ValidationResult
    ) -> None:
        """Validate single value."""
        # Required check
        if rules.get(ValidationRule.REQUIRED) and value is None:
            result.add_error("Value is required")
            return

        if value is None:
            return  # Skip other validations for None

        # String validations
        if isinstance(value, str):
            if ValidationRule.MIN_LENGTH in rules:
                if len(value) < rules[ValidationRule.MIN_LENGTH]:
                    result.add_error(
                        f"Value must be at least "
                        f"{rules[ValidationRule.MIN_LENGTH]} characters"
                    )

            if ValidationRule.MAX_LENGTH in rules:
                if len(value) > rules[ValidationRule.MAX_LENGTH]:
                    result.add_error(
                        f"Value must be at most "
                        f"{rules[ValidationRule.MAX_LENGTH]} characters"
                    )

            if ValidationRule.PATTERN in rules:
                pattern = rules[ValidationRule.PATTERN]
                if not re.match(pattern, value):
                    result.add_error(f"Value does not match pattern: {pattern}")

            if ValidationRule.EMAIL in rules and rules[ValidationRule.EMAIL]:
                if not self._validate_email(value):
                    result.add_error("Invalid email address")

            if ValidationRule.URL in rules and rules[ValidationRule.URL]:
                if not self._validate_url(value):
                    result.add_error("Invalid URL")

        # Numeric validations
        if isinstance(value, (int, float, Decimal)):
            if ValidationRule.MIN_VALUE in rules:
                if value < rules[ValidationRule.MIN_VALUE]:
                    result.add_error(
                        f"Value must be at least {rules[ValidationRule.MIN_VALUE]}"
                    )

            if ValidationRule.MAX_VALUE in rules:
                if value > rules[ValidationRule.MAX_VALUE]:
                    result.add_error(
                        f"Value must be at most {rules[ValidationRule.MAX_VALUE]}"
                    )

        # List validations
        if ValidationRule.IN_LIST in rules:
            allowed_values = rules[ValidationRule.IN_LIST]
            if value not in allowed_values:
                result.add_error(
                    f"Value must be one of: {', '.join(map(str, allowed_values))}"
                )

        if ValidationRule.NOT_IN_LIST in rules:
            forbidden_values = rules[ValidationRule.NOT_IN_LIST]
            if value in forbidden_values:
                result.add_error(f"Value is not allowed: {value}")

        # Custom validation
        if ValidationRule.CUSTOM in rules:
            custom_name = rules[ValidationRule.CUSTOM]
            if custom_name in self.custom_validators:
                if not self.custom_validators[custom_name](value):
                    result.add_error(f"Custom validation failed: {custom_name}")
            else:
                result.add_warning(f"Unknown custom validator: {custom_name}")

    def _validate_field(
        self,
        value: Any,
        field_name: str,
        rules: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Validate field with rules."""
        field_result = ValidationResult(is_valid=True)
        self._validate_value(value, rules, field_result)

        # Add field context to errors
        for error in field_result.errors:
            result.add_error(error, field_name)

        result.warnings.extend(field_result.warnings)
        result.is_valid = result.is_valid and field_result.is_valid

    # Built-in validators
    def _validate_email(self, value: str) -> bool:
        """Validate email address."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, value))

    def _validate_url(self, value: str) -> bool:
        """Validate URL."""
        pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        return bool(re.match(pattern, value))

    def _validate_phone(self, value: str) -> bool:
        """Validate phone number."""
        # Simple validation - can be customized
        pattern = r"^\+?[\d\s\-\(\)]+$"
        return bool(re.match(pattern, value)) and len(value) >= 10

    def _validate_alphanumeric(self, value: str) -> bool:
        """Validate alphanumeric string."""
        return value.isalnum()

    def _validate_numeric(self, value: str) -> bool:
        """Validate numeric string."""
        return value.isdigit()

    def _validate_alphabetic(self, value: str) -> bool:
        """Validate alphabetic string."""
        return value.isalpha()


# Global validator instance
_validator: Optional[DataValidator] = None


def get_validator() -> DataValidator:
    """Get global validator instance."""
    global _validator
    if _validator is None:
        _validator = DataValidator()
    return _validator


def validate_data(
    data: Any, rules: Optional[Dict[str, Any]] = None, schema_name: Optional[str] = None
) -> ValidationResult:
    """
    Validate data against rules or schema.

    Args:
        data: Data to validate
        rules: Validation rules
        schema_name: Name of registered schema

    Returns:
        ValidationResult
    """
    validator = get_validator()
    return validator.validate(data, rules, schema_name)


def validate_schema(data: Dict[str, Any], schema: Type[BaseModel]) -> ValidationResult:
    """
    Validate data against Pydantic schema.

    Args:
        data: Data to validate
        schema: Pydantic model class

    Returns:
        ValidationResult
    """
    result = ValidationResult(is_valid=True)

    try:
        schema(**data)
    except ValidationError as e:
        result.is_valid = False
        for error in e.errors():
            field_path = ".".join(str(loc) for loc in error["loc"])
            result.add_error(error["msg"], field_path)

    return result

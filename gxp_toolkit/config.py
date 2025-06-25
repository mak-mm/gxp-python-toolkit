"""
Configuration module for GxP Python Toolkit.

Provides centralized configuration management for all GxP compliance features.
"""

from datetime import timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, get_args, get_origin

from pydantic import BaseModel, Field, field_validator


class StorageBackend(str, Enum):
    """Supported storage backends for audit trails."""

    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"
    FILE = "file"
    MONGODB = "mongodb"


class ChecksumAlgorithm(str, Enum):
    """Supported checksum algorithms for data integrity."""

    SHA256 = "sha256"
    SHA512 = "sha512"
    MD5 = "md5"  # Not recommended for security
    BLAKE2B = "blake2b"


class GxPConfig(BaseModel):
    """Central configuration for all GxP compliance features.

    This class provides a comprehensive configuration system for the GxP Python Toolkit,
    covering all modules including audit trails, electronic signatures, access control,
    data integrity, and validation. Configuration can be loaded from multiple sources
    including environment variables, configuration files, or set programmatically.

    The configuration follows GxP best practices with secure defaults and validation
    to ensure compliance with regulations such as FDA 21 CFR Part 11 and EU Annex 11.

    Configuration Sources (in order of precedence):
        1. Programmatic settings (highest priority)
        2. Environment variables (GXP_ prefix)
        3. Configuration files (gxp_config.py, config.json)
        4. Default values (lowest priority)

    Example:
        Basic configuration:

        >>> config = GxPConfig(
        ...     application_name="MyPharmaApp",
        ...     audit_retention_days=2555,  # 7 years
        ...     require_mfa=True
        ... )

        Loading from environment:

        >>> import os
        >>> os.environ['GXP_AUDIT_RETENTION_DAYS'] = '2555'
        >>> os.environ['GXP_REQUIRE_MFA'] = 'true'
        >>> config = GxPConfig.from_env()

        Loading from file:

        >>> config = GxPConfig.from_file('production_config.json')

    Environment Variables:
        All configuration options can be set via environment variables using
        the GXP_ prefix. For example:

        - GXP_APPLICATION_NAME
        - GXP_AUDIT_RETENTION_DAYS
        - GXP_SIGNATURE_TIMEOUT_MINUTES
        - GXP_REQUIRE_MFA

    Validation:
        All configuration values are validated according to GxP requirements:

        - Audit retention must be appropriate for regulatory requirements
        - Password policies must meet security standards
        - Timeout values must be within reasonable ranges
        - Required fields must be provided

    Security Considerations:
        - Sensitive values like connection strings should use environment variables
        - Key material should never be stored in configuration files
        - Production configurations should enforce strict security policies

    Note:
        Changes to configuration may require system restart to take effect.
        Some settings (like audit retention) have regulatory implications
        and should not be modified without proper change control procedures.
    """

    # General settings
    application_name: str = Field(
        "GxP Application", description="Name of the application for audit trails"
    )
    environment: str = Field(
        "production", description="Environment (development, staging, production)"
    )
    timezone: str = Field("UTC", description="Default timezone for timestamps")

    # Audit trail settings
    audit_enabled: bool = Field(True, description="Enable audit trail logging")
    audit_retention_days: int = Field(
        2555, description="Days to retain audit logs", gt=0  # 7 years
    )
    audit_storage_backend: StorageBackend = Field(
        StorageBackend.FILE, description="Storage backend for audit trails"
    )
    audit_batch_size: int = Field(
        100, description="Batch size for audit log writes", gt=0, le=1000
    )
    audit_async_writes: bool = Field(
        True, description="Enable asynchronous audit log writes"
    )
    audit_backend: Optional[str] = Field(
        None, description="Audit backend connection string"
    )
    audit_file_path: Optional[str] = Field(
        "./audit_logs", description="Path for file-based audit storage"
    )

    # Electronic signature settings
    signature_required_actions: List[str] = Field(
        default_factory=lambda: ["approve", "release", "reject", "delete"],
        description="Actions requiring electronic signature",
    )
    signature_timeout_minutes: int = Field(
        15, description="Minutes before signature session expires", gt=0, le=60
    )
    esignature_meaning_required: bool = Field(
        True, description="Require meaning/intent for electronic signatures"
    )
    require_password_complexity: bool = Field(
        True, description="Enforce password complexity rules"
    )
    password_min_length: int = Field(12, description="Minimum password length", ge=8)
    password_require_uppercase: bool = Field(
        True, description="Require uppercase letters"
    )
    password_require_lowercase: bool = Field(
        True, description="Require lowercase letters"
    )
    password_require_numbers: bool = Field(True, description="Require numbers")
    password_require_special: bool = Field(
        True, description="Require special characters"
    )
    password_history_count: int = Field(
        12, description="Number of previous passwords to check", ge=0
    )

    # Access control settings
    max_login_attempts: int = Field(
        3, description="Maximum failed login attempts", gt=0, le=10
    )
    lockout_duration_minutes: int = Field(
        30, description="Account lockout duration", gt=0
    )
    session_timeout_minutes: int = Field(
        30, description="Session timeout period", gt=0, le=480  # 8 hours max
    )
    session_absolute_timeout_minutes: int = Field(
        480, description="Absolute session timeout", gt=0  # 8 hours
    )
    require_mfa_for_critical: bool = Field(
        True, description="Require MFA for critical operations"
    )
    require_mfa: bool = Field(False, description="Require MFA for all operations")

    # Data integrity settings
    checksum_algorithm: ChecksumAlgorithm = Field(
        ChecksumAlgorithm.SHA256, description="Algorithm for data integrity checks"
    )
    require_change_reason: bool = Field(
        True, description="Require reason for all data changes"
    )
    change_reason_min_length: int = Field(
        10, description="Minimum length for change reasons", ge=5
    )

    # Soft delete settings
    soft_delete_enabled: bool = Field(
        True, description="Enable soft delete functionality"
    )
    cascade_delete_enabled: bool = Field(
        True, description="Enable cascade soft deletes"
    )
    deletion_reason_min_length: int = Field(
        10, description="Minimum length for deletion reasons", ge=5
    )
    restoration_requires_approval: bool = Field(
        True, description="Require approval for data restoration"
    )

    # Validation settings
    strict_validation: bool = Field(True, description="Enable strict data validation")
    validation_error_details: bool = Field(
        True, description="Include detailed validation errors"
    )

    # Compliance reporting
    compliance_reports_enabled: bool = Field(
        True, description="Enable compliance reporting"
    )
    report_retention_days: int = Field(
        3650, description="Days to retain compliance reports", gt=0  # 10 years
    )

    # Performance settings
    enable_caching: bool = Field(True, description="Enable caching for performance")
    cache_ttl_seconds: int = Field(
        300, description="Cache time-to-live", gt=0  # 5 minutes
    )

    # Security settings
    encrypt_sensitive_data: bool = Field(
        True, description="Encrypt sensitive data at rest"
    )
    encryption_key_rotation_days: int = Field(
        90, description="Days between encryption key rotation", gt=0
    )

    # Azure RBAC settings
    azure_tenant_id: Optional[str] = Field(
        None, description="Azure AD tenant ID for authentication"
    )
    azure_subscription_id: Optional[str] = Field(
        None, description="Azure subscription ID for RBAC operations"
    )
    azure_resource_group: Optional[str] = Field(
        None, description="Azure resource group for authorization scope"
    )
    azure_key_vault_name: Optional[str] = Field(
        None, description="Azure Key Vault name for secret storage"
    )
    azure_rbac_cache_ttl: int = Field(
        3600, description="Cache TTL for Azure RBAC permissions in seconds", gt=0
    )

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Ensure environment is valid."""
        valid_environments = {"development", "staging", "production", "validation"}
        if v.lower() not in valid_environments:
            raise ValueError(
                f"Environment must be one of: {', '.join(valid_environments)}"
            )
        return v.lower()

    @field_validator("audit_retention_days")
    @classmethod
    def validate_audit_retention(cls, v: int) -> int:
        """Ensure audit retention meets regulatory requirements."""
        if v < 2555:  # 7 years
            raise ValueError(
                "Audit logs must be retained for at least 7 years (2555 days) "
                "to meet GxP requirements"
            )
        return v

    @field_validator("password_min_length")
    @classmethod
    def validate_password_length(cls, v: int) -> int:
        """Ensure password length meets security requirements."""
        if v < 8:
            raise ValueError("Password minimum length must be at least 8 characters")
        return v

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return self.model_dump()

    @classmethod
    def from_env(cls, prefix: str = "GXP_") -> "GxPConfig":
        """
        Load configuration from environment variables.

        Args:
            prefix: Prefix for environment variables

        Returns:
            Configuration instance
        """
        import os

        config_dict: Dict[str, Any] = {}

        # Map environment variables to config fields
        for field_name, field_info in cls.model_fields.items():
            env_var = f"{prefix}{field_name.upper()}"
            if env_var in os.environ:
                value = os.environ[env_var]

                # Get the actual type annotation
                field_type = field_info.annotation

                # Handle Optional types
                if get_origin(field_type) is Union:
                    # Get the non-None type from Optional[T]
                    args = get_args(field_type)
                    field_type = next(
                        (arg for arg in args if arg is not type(None)), str
                    )

                # Type conversion based on field type
                try:
                    # Handle boolean fields
                    if field_type == bool:
                        config_dict[field_name] = value.lower() in (
                            "true",
                            "1",
                            "yes",
                            "on",
                        )
                    # Handle integer fields
                    elif field_type == int:
                        config_dict[field_name] = int(value)
                    # Handle list fields
                    elif get_origin(field_type) is list:
                        config_dict[field_name] = [
                            item.strip() for item in value.split(",")
                        ]
                    # Handle enum fields
                    elif isinstance(field_type, type) and issubclass(field_type, Enum):
                        config_dict[field_name] = field_type(value)
                    else:
                        config_dict[field_name] = value
                except (ValueError, TypeError):
                    # If conversion fails, use the raw string value
                    config_dict[field_name] = value

        # Create instance with defaults for missing fields
        return cls.model_validate(config_dict)

    def get_session_config(self) -> Dict[str, Any]:
        """Get session-related configuration."""
        return {
            "timeout": timedelta(minutes=self.session_timeout_minutes),
            "absolute_timeout": timedelta(
                minutes=self.session_absolute_timeout_minutes
            ),
            "require_mfa_for_critical": self.require_mfa_for_critical,
        }

    def get_password_policy(self) -> Dict[str, Any]:
        """Get password policy configuration."""
        return {
            "min_length": self.password_min_length,
            "require_uppercase": self.password_require_uppercase,
            "require_lowercase": self.password_require_lowercase,
            "require_numbers": self.password_require_numbers,
            "require_special": self.password_require_special,
            "history_count": self.password_history_count,
        }

    def get_audit_config(self) -> Dict[str, Any]:
        """Get audit trail configuration."""
        return {
            "enabled": self.audit_enabled,
            "retention_days": self.audit_retention_days,
            "backend": self.audit_storage_backend,
            "batch_size": self.audit_batch_size,
            "async_writes": self.audit_async_writes,
        }


# Global configuration instance
_config: Optional[GxPConfig] = None


def get_config() -> GxPConfig:
    """
    Get the global configuration instance.

    Returns:
        Global configuration
    """
    global _config

    if _config is None:
        # Try to load from environment first
        try:
            _config = GxPConfig.from_env()
        except Exception:
            # Fall back to default configuration
            # Use model_validate with empty dict to get all defaults
            _config = GxPConfig.model_validate({})

    return _config


def set_config(config: GxPConfig) -> None:
    """
    Set the global configuration instance.

    Args:
        config: Configuration to set
    """
    global _config
    _config = config


def configure(**kwargs: Any) -> GxPConfig:
    """
    Configure GxP toolkit with keyword arguments.

    Args:
        **kwargs: Configuration parameters

    Returns:
        Updated configuration
    """
    global _config

    if _config is None:
        _config = GxPConfig(**kwargs)
    else:
        # Update existing config
        config_dict = _config.to_dict()
        config_dict.update(kwargs)
        _config = GxPConfig(**config_dict)

    return _config

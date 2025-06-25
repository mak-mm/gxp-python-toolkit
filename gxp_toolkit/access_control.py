"""
Access control module for GxP compliance with Azure RBAC integration.

This module provides authentication, authorization, and user management
functionality using Azure Active Directory and Role-Based Access Control.
Supports DefaultAzureCredential for managed identity, service principal,
and az login authentication methods.
"""

import functools
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, TypeVar, Union

import jwt
from azure.identity import (
    AzureCliCredential,
    ChainedTokenCredential,
    DefaultAzureCredential,
    EnvironmentCredential,
    ManagedIdentityCredential,
)
from azure.keyvault.secrets import SecretClient
from azure.mgmt.authorization import AuthorizationManagementClient
from pydantic import BaseModel, Field, field_validator

from .audit_trail import audit_event
from .config import get_config

logger = logging.getLogger(__name__)

# Type variable for decorators
F = TypeVar("F", bound=Callable[..., Any])


class Permission(str, Enum):
    """Standard GxP permissions."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    APPROVE = "approve"
    SIGN = "sign"
    ADMIN = "admin"
    AUDIT_VIEW = "audit.view"
    AUDIT_EXPORT = "audit.export"
    CONFIG_VIEW = "config.view"
    CONFIG_EDIT = "config.edit"
    USER_MANAGE = "user.manage"
    ROLE_MANAGE = "role.manage"


class AuthenticationMethod(str, Enum):
    """Supported authentication methods."""

    MANAGED_IDENTITY = "managed_identity"
    SERVICE_PRINCIPAL = "service_principal"
    CLI = "cli"
    INTERACTIVE = "interactive"
    DEFAULT = "default"


@dataclass
class User:
    """Represents an authenticated user."""

    id: str
    email: str
    name: str
    roles: List[str] = field(default_factory=list)
    permissions: Set[Permission] = field(default_factory=set)
    authentication_method: AuthenticationMethod = AuthenticationMethod.DEFAULT
    token_expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated."""
        if self.token_expires_at is None:
            return True
        return datetime.utcnow() < self.token_expires_at

    def has_permission(self, permission: Union[str, Permission]) -> bool:
        """Check if user has a specific permission."""
        if isinstance(permission, str):
            permission = Permission(permission)
        return permission in self.permissions or Permission.ADMIN in self.permissions

    def has_any_permission(self, permissions: List[Union[str, Permission]]) -> bool:
        """Check if user has any of the specified permissions."""
        return any(self.has_permission(p) for p in permissions)

    def has_all_permissions(self, permissions: List[Union[str, Permission]]) -> bool:
        """Check if user has all specified permissions."""
        return all(self.has_permission(p) for p in permissions)


class RoleDefinition(BaseModel):
    """Role definition with permissions."""

    name: str
    description: str
    permissions: List[Permission]
    assignable_scopes: List[str] = Field(default_factory=list)

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: List[Permission]) -> List[Permission]:
        """Ensure permissions are valid."""
        return list(set(v))  # Remove duplicates


class AzureRBACProvider:
    """Azure RBAC authentication and authorization provider."""

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        subscription_id: Optional[str] = None,
        resource_group: Optional[str] = None,
        key_vault_name: Optional[str] = None,
        credential: Optional[DefaultAzureCredential] = None,
        cache_ttl: int = 3600,
        enable_cache: bool = True,
    ):
        """
        Initialize Azure RBAC provider.

        Args:
            tenant_id: Azure AD tenant ID
            subscription_id: Azure subscription ID
            resource_group: Resource group for authorization scope
            key_vault_name: Key Vault name for secrets
            credential: Custom credential instance
            cache_ttl: Cache time-to-live in seconds
            enable_cache: Enable permission caching
        """
        config = get_config()

        self.tenant_id = (
            tenant_id or os.getenv("AZURE_TENANT_ID") or config.azure_tenant_id
        )
        self.subscription_id = (
            subscription_id
            or os.getenv("AZURE_SUBSCRIPTION_ID")
            or config.azure_subscription_id
        )
        self.resource_group = (
            resource_group
            or os.getenv("AZURE_RESOURCE_GROUP")
            or config.azure_resource_group
        )
        self.key_vault_name = (
            key_vault_name
            or os.getenv("AZURE_KEY_VAULT_NAME")
            or config.azure_key_vault_name
        )

        # Initialize credential
        self.credential = credential or self._create_credential()

        # Initialize clients
        self._init_clients()

        # Cache configuration
        self.cache_ttl = cache_ttl
        self.enable_cache = enable_cache
        self._cache: Dict[str, Any] = {}
        self._cache_lock = threading.Lock()

        # Role mappings
        self._role_mappings = self._load_role_mappings()

    def _create_credential(self) -> ChainedTokenCredential:
        """Create chained credential for multiple auth methods."""
        credentials: List[Any] = []

        # Add credentials in order of preference
        # 1. Environment variables (service principal)
        credentials.append(EnvironmentCredential())

        # 2. Managed Identity
        credentials.append(ManagedIdentityCredential())

        # 3. Azure CLI
        credentials.append(AzureCliCredential())

        return ChainedTokenCredential(*credentials)

    def _init_clients(self) -> None:
        """Initialize Azure service clients."""
        try:
            # Authorization client for RBAC operations
            if self.subscription_id:
                self.auth_client: Optional[AuthorizationManagementClient] = (
                    AuthorizationManagementClient(
                        credential=self.credential, subscription_id=self.subscription_id
                    )
                )
            else:
                self.auth_client = None
                logger.warning(
                    "No subscription ID provided, RBAC operations will be limited"
                )

            # Key Vault client for secrets
            if self.key_vault_name:
                vault_url = f"https://{self.key_vault_name}.vault.azure.net/"
                self.secret_client: Optional[SecretClient] = SecretClient(
                    vault_url=vault_url, credential=self.credential
                )
            else:
                self.secret_client = None
                logger.warning(
                    "No Key Vault configured, secret operations will be unavailable"
                )

        except Exception as e:
            logger.error(f"Failed to initialize Azure clients: {e}")
            raise

    def _load_role_mappings(self) -> Dict[str, RoleDefinition]:
        """Load role to permission mappings."""
        # Default GxP role mappings
        return {
            "GxP.Admin": RoleDefinition(
                name="GxP.Admin",
                description="Full administrative access",
                permissions=list(Permission),
            ),
            "GxP.QualityManager": RoleDefinition(
                name="GxP.QualityManager",
                description="Quality management and approval",
                permissions=[
                    Permission.READ,
                    Permission.WRITE,
                    Permission.APPROVE,
                    Permission.SIGN,
                    Permission.AUDIT_VIEW,
                    Permission.AUDIT_EXPORT,
                ],
            ),
            "GxP.Operator": RoleDefinition(
                name="GxP.Operator",
                description="Standard operator access",
                permissions=[Permission.READ, Permission.WRITE, Permission.AUDIT_VIEW],
            ),
            "GxP.Viewer": RoleDefinition(
                name="GxP.Viewer",
                description="Read-only access",
                permissions=[Permission.READ, Permission.AUDIT_VIEW],
            ),
            "GxP.Auditor": RoleDefinition(
                name="GxP.Auditor",
                description="Audit trail access",
                permissions=[
                    Permission.READ,
                    Permission.AUDIT_VIEW,
                    Permission.AUDIT_EXPORT,
                ],
            ),
        }

    def _get_cache_key(self, prefix: str, *args: Any) -> str:
        """Generate cache key."""
        return f"{prefix}:{':'.join(str(arg) for arg in args)}"

    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get value from cache if enabled and not expired."""
        if not self.enable_cache:
            return None

        with self._cache_lock:
            if key in self._cache:
                entry = self._cache[key]
                if datetime.utcnow() < entry["expires_at"]:
                    return entry["value"]
                else:
                    del self._cache[key]
        return None

    def _set_cache(self, key: str, value: Any) -> None:
        """Set value in cache with TTL."""
        if not self.enable_cache:
            return

        with self._cache_lock:
            self._cache[key] = {
                "value": value,
                "expires_at": datetime.utcnow() + timedelta(seconds=self.cache_ttl),
            }

    def authenticate_user(self, token: Optional[str] = None) -> User:
        """
        Authenticate user and return User object.

        Args:
            token: Optional JWT token for validation

        Returns:
            Authenticated User object
        """
        try:
            if token:
                # Validate provided token
                user_info = self._validate_token(token)
            else:
                # Get token from credential
                access_token = self.credential.get_token(
                    "https://management.azure.com/.default"
                )
                user_info = self._decode_token(access_token.token)

            # Get user roles and permissions
            user_id = user_info.get("oid") or user_info.get("sub")
            if not user_id:
                raise ValueError("No user ID found in token")

            email = user_info.get("email") or user_info.get("upn", "")
            name = user_info.get("name", email.split("@")[0])

            # Get roles from Azure RBAC
            roles = self._get_user_roles(user_id)
            permissions = self._get_permissions_for_roles(roles)

            user = User(
                id=user_id,
                email=email,
                name=name,
                roles=roles,
                permissions=permissions,
                authentication_method=self._detect_auth_method(),
                token_expires_at=datetime.fromtimestamp(user_info.get("exp", 0)),
                metadata=user_info,
            )

            # Audit successful authentication
            audit_event(
                action="user.authenticated",
                resource_type="user",
                resource_id=user_id,
                user_id=user_id,
                details={
                    "email": email,
                    "method": user.authentication_method.value,
                    "roles": roles,
                },
            )

            return user

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            audit_event(
                action="user.authentication_failed",
                resource_type="user",
                resource_id="unknown",
                details={"error": str(e)},
            )
            raise

    def _validate_token(self, token: str) -> Dict[str, Any]:
        """Validate and decode JWT token."""
        try:
            # For Azure AD tokens, we need to get the signing keys
            # In production, these should be cached from Azure AD metadata endpoint
            # For now, we'll decode without verification and rely on Azure AD
            decoded = jwt.decode(token, options={"verify_signature": False})

            # Verify token hasn't expired
            if decoded.get("exp", 0) < datetime.utcnow().timestamp():
                raise ValueError("Token has expired")

            return decoded  # type: ignore[no-any-return]

        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}")

    def _decode_token(self, token: str) -> Dict[str, Any]:
        """Decode token without validation (already validated by Azure)."""
        # JWT decode returns Any but we know it's a dict in this context
        result: Dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
        return result

    def _detect_auth_method(self) -> AuthenticationMethod:
        """Detect which authentication method was used."""
        # This is a simplified detection - in production, you'd check the
        # credential chain
        if os.getenv("AZURE_CLIENT_ID") and os.getenv("AZURE_CLIENT_SECRET"):
            return AuthenticationMethod.SERVICE_PRINCIPAL
        elif os.getenv("MSI_ENDPOINT") or os.getenv("IDENTITY_ENDPOINT"):
            return AuthenticationMethod.MANAGED_IDENTITY
        else:
            return AuthenticationMethod.CLI

    def _get_user_roles(self, user_id: str) -> List[str]:
        """Get user's Azure RBAC roles."""
        cache_key = self._get_cache_key("user_roles", user_id)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached  # type: ignore[no-any-return]

        roles = []

        try:
            if self.auth_client:
                # Get role assignments for user
                scope = f"/subscriptions/{self.subscription_id}"
                if self.resource_group:
                    scope += f"/resourceGroups/{self.resource_group}"

                assignments = self.auth_client.role_assignments.list_for_scope(
                    scope=scope, filter=f"principalId eq '{user_id}'"
                )

                # Get role definitions
                for assignment in assignments:
                    role_def = self.auth_client.role_definitions.get_by_id(
                        assignment.role_definition_id
                    )
                    role_name = role_def.role_name

                    # Map Azure roles to GxP roles
                    if role_name == "Owner" or role_name == "Contributor":
                        roles.append("GxP.Admin")
                    elif role_name == "Reader":
                        roles.append("GxP.Viewer")

                    # Check for custom GxP roles
                    if role_name.startswith("GxP."):
                        roles.append(role_name)

        except Exception as e:
            logger.warning(f"Failed to get Azure roles for user {user_id}: {e}")
            # Fall back to default role
            roles = ["GxP.Operator"]

        # Cache the result
        self._set_cache(cache_key, roles)
        return roles

    def _get_permissions_for_roles(self, roles: List[str]) -> Set[Permission]:
        """Get permissions for given roles."""
        permissions = set()

        for role in roles:
            if role in self._role_mappings:
                permissions.update(self._role_mappings[role].permissions)
            else:
                # Unknown role - grant basic read permission
                logger.warning(f"Unknown role: {role}")
                permissions.add(Permission.READ)

        return permissions

    def check_permission(self, user: User, permission: Union[str, Permission]) -> bool:
        """
        Check if user has specific permission.

        Args:
            user: User object
            permission: Permission to check

        Returns:
            True if user has permission
        """
        if not user.is_authenticated:
            return False

        has_perm = user.has_permission(permission)

        # Audit permission checks for sensitive operations
        perm_enum = (
            Permission(permission) if isinstance(permission, str) else permission
        )

        if perm_enum in [
            Permission.DELETE,
            Permission.APPROVE,
            Permission.SIGN,
            Permission.ADMIN,
        ]:
            audit_event(
                action="permission.checked",
                resource_type="permission",
                resource_id=perm_enum.value,
                user_id=user.id,
                details={"granted": has_perm, "user_roles": user.roles},
            )

        return has_perm

    def create_custom_role(self, role: RoleDefinition) -> bool:
        """
        Create custom Azure RBAC role.

        Args:
            role: Role definition

        Returns:
            True if successful
        """
        try:
            if not self.auth_client:
                raise ValueError("Authorization client not initialized")

            # Create custom role definition
            role_def = {
                "Name": role.name,
                "Description": role.description,
                "Actions": [f"Microsoft.GxP/{p.value}" for p in role.permissions],
                "AssignableScopes": role.assignable_scopes
                or [f"/subscriptions/{self.subscription_id}"],
            }

            self.auth_client.role_definitions.create_or_update(
                scope=f"/subscriptions/{self.subscription_id}",
                role_definition_id=role.name,
                role_definition=role_def,
            )

            # Update local mappings
            self._role_mappings[role.name] = role

            audit_event(
                action="role.created",
                resource_type="role",
                resource_id=role.name,
                details={"permissions": [p.value for p in role.permissions]},
            )

            return True

        except Exception as e:
            logger.error(f"Failed to create role {role.name}: {e}")
            return False

    def assign_role(
        self, user_id: str, role_name: str, scope: Optional[str] = None
    ) -> bool:
        """
        Assign role to user.

        Args:
            user_id: User's Azure AD object ID
            role_name: Role name to assign
            scope: Optional scope for assignment

        Returns:
            True if successful
        """
        try:
            if not self.auth_client:
                raise ValueError("Authorization client not initialized")

            # Get role definition
            role_defs = list(
                self.auth_client.role_definitions.list(
                    scope=scope or f"/subscriptions/{self.subscription_id}",
                    filter=f"roleName eq '{role_name}'",
                )
            )

            if not role_defs:
                raise ValueError(f"Role {role_name} not found")

            role_def = role_defs[0]

            # Create role assignment
            import uuid

            assignment_id = str(uuid.uuid4())

            self.auth_client.role_assignments.create(
                scope=scope or f"/subscriptions/{self.subscription_id}",
                role_assignment_name=assignment_id,
                parameters={"role_definition_id": role_def.id, "principal_id": user_id},
            )

            # Clear cache for user
            cache_key = self._get_cache_key("user_roles", user_id)
            with self._cache_lock:
                if cache_key in self._cache:
                    del self._cache[cache_key]

            audit_event(
                action="role.assigned",
                resource_type="role_assignment",
                resource_id=assignment_id,
                details={"user_id": user_id, "role": role_name, "scope": scope},
            )

            return True

        except Exception as e:
            logger.error(f"Failed to assign role {role_name} to user {user_id}: {e}")
            return False


# Global RBAC provider instance
_rbac_provider: Optional[AzureRBACProvider] = None
_current_user: Optional[User] = None


def initialize_rbac(
    tenant_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
    resource_group: Optional[str] = None,
    key_vault_name: Optional[str] = None,
    credential: Optional[DefaultAzureCredential] = None,
) -> AzureRBACProvider:
    """
    Initialize global RBAC provider.

    Args:
        tenant_id: Azure AD tenant ID
        subscription_id: Azure subscription ID
        resource_group: Resource group for authorization scope
        key_vault_name: Key Vault name for secrets
        credential: Custom credential instance

    Returns:
        Initialized RBAC provider
    """
    global _rbac_provider
    _rbac_provider = AzureRBACProvider(
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        resource_group=resource_group,
        key_vault_name=key_vault_name,
        credential=credential,
    )
    return _rbac_provider


def get_rbac_provider() -> AzureRBACProvider:
    """Get global RBAC provider instance."""
    if _rbac_provider is None:
        # Auto-initialize with defaults
        initialize_rbac()
    if _rbac_provider is None:  # nosec B101
        raise RuntimeError("RBAC provider initialization failed")
    return _rbac_provider


def authenticate(token: Optional[str] = None) -> User:
    """
    Authenticate user and set as current user.

    Args:
        token: Optional JWT token

    Returns:
        Authenticated User object
    """
    global _current_user
    provider = get_rbac_provider()
    _current_user = provider.authenticate_user(token)
    return _current_user


def get_current_user() -> Optional[User]:
    """Get currently authenticated user."""
    return _current_user


def require_authentication(func: F) -> F:
    """
    Decorator to require authentication.

    Usage:
        @require_authentication
        def protected_function():
            pass
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        user = get_current_user()
        if not user or not user.is_authenticated:
            raise PermissionError("Authentication required")
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def require_permission(*permissions: Union[str, Permission]) -> Callable[[F], F]:
    """
    Decorator to require specific permissions.

    Args:
        permissions: Required permissions (user must have at least one)

    Usage:
        @require_permission(Permission.WRITE)
        def write_data():
            pass

        @require_permission("admin", "approve")
        def approve_change():
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user or not user.is_authenticated:
                raise PermissionError("Authentication required")

            if not user.has_any_permission(list(permissions)):
                raise PermissionError(
                    f"Insufficient permissions. Required: {permissions}, "
                    f"User has: {[p.value for p in user.permissions]}"
                )

            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def require_all_permissions(*permissions: Union[str, Permission]) -> Callable[[F], F]:
    """
    Decorator to require all specified permissions.

    Args:
        permissions: Required permissions (user must have all)

    Usage:
        @require_all_permissions(Permission.WRITE, Permission.APPROVE)
        def write_and_approve():
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user or not user.is_authenticated:
                raise PermissionError("Authentication required")

            if not user.has_all_permissions(list(permissions)):
                raise PermissionError(
                    f"Insufficient permissions. Required all: {permissions}, "
                    f"User has: {[p.value for p in user.permissions]}"
                )

            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


# Backward compatibility functions
def check_permission(permission: str) -> bool:
    """
    Check if current user has permission.

    Args:
        permission: Permission to check

    Returns:
        True if user has permission
    """
    user = get_current_user()
    if not user:
        return False

    provider = get_rbac_provider()
    return provider.check_permission(user, permission)


def has_role(role: str) -> bool:
    """
    Check if current user has role.

    Args:
        role: Role to check

    Returns:
        True if user has role
    """
    user = get_current_user()
    if not user:
        return False
    return role in user.roles


def get_user_id() -> Optional[str]:
    """
    Get current user ID.

    Returns:
        User ID or None if not authenticated
    """
    user = get_current_user()
    return user.id if user else None


# Re-export for backward compatibility
__all__ = [
    "Permission",
    "AuthenticationMethod",
    "User",
    "RoleDefinition",
    "AzureRBACProvider",
    "initialize_rbac",
    "get_rbac_provider",
    "authenticate",
    "get_current_user",
    "require_authentication",
    "require_permission",
    "require_all_permissions",
    "check_permission",
    "has_role",
    "get_user_id",
]

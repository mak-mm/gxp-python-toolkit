"""Tests for access control module with Azure RBAC."""

import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

import jwt
import pytest

from gxp_toolkit.access_control import (
    AuthenticationMethod,
    AzureRBACProvider,
    Permission,
    RoleDefinition,
    User,
    authenticate,
    check_permission,
    get_current_user,
    get_rbac_provider,
    get_user_id,
    has_role,
    initialize_rbac,
    require_all_permissions,
    require_authentication,
    require_permission,
)


class TestUser:
    """Test User class functionality."""

    def test_user_creation(self):
        """Test creating a user."""
        user = User(
            id="test-id",
            email="test@example.com",
            name="Test User",
            roles=["GxP.Operator"],
            permissions={Permission.READ, Permission.WRITE},
        )

        assert user.id == "test-id"
        assert user.email == "test@example.com"
        assert user.name == "Test User"
        assert "GxP.Operator" in user.roles
        assert Permission.READ in user.permissions

    def test_user_authentication_status(self):
        """Test user authentication status."""
        # User without expiry is authenticated
        user = User(
            id="test-id",
            email="test@example.com",
            name="Test User",
        )
        assert user.is_authenticated

        # User with future expiry is authenticated
        user.token_expires_at = datetime.utcnow() + timedelta(hours=1)
        assert user.is_authenticated

        # User with past expiry is not authenticated
        user.token_expires_at = datetime.utcnow() - timedelta(hours=1)
        assert not user.is_authenticated

    def test_user_permissions(self):
        """Test user permission checking."""
        user = User(
            id="test-id",
            email="test@example.com",
            name="Test User",
            permissions={Permission.READ, Permission.WRITE},
        )

        # Check single permission
        assert user.has_permission(Permission.READ)
        assert user.has_permission("write")
        assert not user.has_permission(Permission.DELETE)

        # Check any permission
        assert user.has_any_permission([Permission.READ, Permission.DELETE])
        assert not user.has_any_permission([Permission.DELETE, Permission.ADMIN])

        # Check all permissions
        assert user.has_all_permissions([Permission.READ, Permission.WRITE])
        assert not user.has_all_permissions([Permission.READ, Permission.DELETE])

    def test_admin_permission_override(self):
        """Test that admin permission grants all permissions."""
        user = User(
            id="admin-id",
            email="admin@example.com",
            name="Admin User",
            permissions={Permission.ADMIN},
        )

        # Admin should have all permissions
        assert user.has_permission(Permission.READ)
        assert user.has_permission(Permission.WRITE)
        assert user.has_permission(Permission.DELETE)
        assert user.has_permission(Permission.APPROVE)


class TestRoleDefinition:
    """Test RoleDefinition class."""

    def test_role_creation(self):
        """Test creating a role definition."""
        role = RoleDefinition(
            name="Test Role",
            description="Test role description",
            permissions=[Permission.READ, Permission.WRITE],
        )

        assert role.name == "Test Role"
        assert role.description == "Test role description"
        assert Permission.READ in role.permissions
        assert Permission.WRITE in role.permissions

    def test_role_permission_deduplication(self):
        """Test that duplicate permissions are removed."""
        role = RoleDefinition(
            name="Test Role",
            description="Test role",
            permissions=[Permission.READ, Permission.READ, Permission.WRITE],
        )

        assert len(role.permissions) == 2
        assert Permission.READ in role.permissions
        assert Permission.WRITE in role.permissions


class TestAzureRBACProvider:
    """Test AzureRBACProvider functionality."""

    @patch("gxp_toolkit.access_control.get_config")
    def test_provider_initialization(self, mock_config):
        """Test RBAC provider initialization."""
        mock_config.return_value = Mock(
            azure_tenant_id="test-tenant",
            azure_subscription_id="test-sub",
            azure_resource_group="test-rg",
            azure_key_vault_name="test-kv",
        )

        with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
            with patch("gxp_toolkit.access_control.SecretClient"):
                provider = AzureRBACProvider()

                assert provider.tenant_id == "test-tenant"
                assert provider.subscription_id == "test-sub"
                assert provider.resource_group == "test-rg"
                assert provider.key_vault_name == "test-kv"

    @patch("gxp_toolkit.access_control.get_config")
    def test_provider_credential_chain(self, mock_config):
        """Test credential chain creation."""
        mock_config.return_value = Mock(
            azure_tenant_id=None,
            azure_subscription_id=None,
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
            with patch("gxp_toolkit.access_control.SecretClient"):
                provider = AzureRBACProvider()

                # Should create ChainedTokenCredential
                assert provider.credential is not None

    @patch("gxp_toolkit.access_control.get_config")
    @patch("gxp_toolkit.access_control.audit_event")
    def test_authenticate_user_with_token(self, mock_audit, mock_config):
        """Test user authentication with provided token."""
        mock_config.return_value = Mock(
            azure_tenant_id="test-tenant",
            azure_subscription_id="test-sub",
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        # Create a mock token
        token_data = {
            "oid": "user-123",
            "email": "user@example.com",
            "name": "Test User",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        }

        with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
            with patch("gxp_toolkit.access_control.SecretClient"):
                provider = AzureRBACProvider()

                # Mock the token validation
                with patch.object(provider, "_validate_token", return_value=token_data):
                    with patch.object(
                        provider, "_get_user_roles", return_value=["GxP.Operator"]
                    ):
                        user = provider.authenticate_user("fake-token")

                        assert user.id == "user-123"
                        assert user.email == "user@example.com"
                        assert user.name == "Test User"
                        assert "GxP.Operator" in user.roles
                        assert Permission.READ in user.permissions

                        # Check audit was called
                        mock_audit.assert_called_once()

    @patch("gxp_toolkit.access_control.get_config")
    def test_role_mappings(self, mock_config):
        """Test default role mappings."""
        mock_config.return_value = Mock(
            azure_tenant_id=None,
            azure_subscription_id=None,
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
            with patch("gxp_toolkit.access_control.SecretClient"):
                provider = AzureRBACProvider()

                # Check default roles exist
                assert "GxP.Admin" in provider._role_mappings
                assert "GxP.QualityManager" in provider._role_mappings
                assert "GxP.Operator" in provider._role_mappings
                assert "GxP.Viewer" in provider._role_mappings
                assert "GxP.Auditor" in provider._role_mappings

                # Check admin has all permissions
                admin_role = provider._role_mappings["GxP.Admin"]
                assert len(admin_role.permissions) == len(list(Permission))

    @patch("gxp_toolkit.access_control.get_config")
    def test_caching(self, mock_config):
        """Test permission caching functionality."""
        mock_config.return_value = Mock(
            azure_tenant_id=None,
            azure_subscription_id=None,
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
            with patch("gxp_toolkit.access_control.SecretClient"):
                provider = AzureRBACProvider(cache_ttl=1, enable_cache=True)

                # Set cache value
                provider._set_cache("test_key", "test_value")

                # Get cached value
                assert provider._get_from_cache("test_key") == "test_value"

                # Wait for cache to expire
                import time

                time.sleep(1.1)

                # Should return None after expiry
                assert provider._get_from_cache("test_key") is None

    @patch("gxp_toolkit.access_control.get_config")
    def test_caching_disabled(self, mock_config):
        """Test with caching disabled."""
        mock_config.return_value = Mock(
            azure_tenant_id=None,
            azure_subscription_id=None,
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
            with patch("gxp_toolkit.access_control.SecretClient"):
                provider = AzureRBACProvider(enable_cache=False)

                # Set cache value
                provider._set_cache("test_key", "test_value")

                # Should return None when cache is disabled
                assert provider._get_from_cache("test_key") is None

    @patch("gxp_toolkit.access_control.get_config")
    @patch("gxp_toolkit.access_control.audit_event")
    def test_check_permission_auditing(self, mock_audit, mock_config):
        """Test that sensitive permissions are audited."""
        mock_config.return_value = Mock(
            azure_tenant_id=None,
            azure_subscription_id=None,
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        user = User(
            id="test-id",
            email="test@example.com",
            name="Test User",
            permissions={Permission.DELETE},
        )

        with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
            with patch("gxp_toolkit.access_control.SecretClient"):
                provider = AzureRBACProvider()

                # Check sensitive permission
                result = provider.check_permission(user, Permission.DELETE)

                assert result is True
                # Audit should be called for sensitive permissions
                mock_audit.assert_called_once()

                # Reset mock
                mock_audit.reset_mock()

                # Check non-sensitive permission
                user.permissions = {Permission.READ}
                result = provider.check_permission(user, Permission.READ)

                assert result is True
                # Audit should not be called for non-sensitive permissions
                mock_audit.assert_not_called()


class TestGlobalFunctions:
    """Test global authentication functions."""

    @patch("gxp_toolkit.access_control.AzureRBACProvider")
    def test_initialize_rbac(self, mock_provider_class):
        """Test RBAC initialization."""
        mock_provider = Mock()
        mock_provider_class.return_value = mock_provider

        result = initialize_rbac(
            tenant_id="test-tenant",
            subscription_id="test-sub",
        )

        assert result == mock_provider
        mock_provider_class.assert_called_once_with(
            tenant_id="test-tenant",
            subscription_id="test-sub",
            resource_group=None,
            key_vault_name=None,
            credential=None,
        )

    def test_get_rbac_provider_auto_init(self):
        """Test auto-initialization of RBAC provider."""
        # Reset global provider
        import gxp_toolkit.access_control

        gxp_toolkit.access_control._rbac_provider = None

        with patch("gxp_toolkit.access_control.initialize_rbac") as mock_init:
            mock_provider = Mock()
            mock_init.return_value = mock_provider

            # Mock should set the global variable
            def set_provider(*args, **kwargs):
                gxp_toolkit.access_control._rbac_provider = mock_provider
                return mock_provider

            mock_init.side_effect = set_provider

            result = get_rbac_provider()

            assert result == mock_provider
            mock_init.assert_called_once()

    @patch("gxp_toolkit.access_control.get_rbac_provider")
    def test_authenticate(self, mock_get_provider):
        """Test authenticate function."""
        mock_provider = Mock()
        mock_user = Mock()
        mock_provider.authenticate_user.return_value = mock_user
        mock_get_provider.return_value = mock_provider

        result = authenticate("test-token")

        assert result == mock_user
        mock_provider.authenticate_user.assert_called_once_with("test-token")

    def test_get_current_user(self):
        """Test getting current user."""
        # Set a test user
        import gxp_toolkit.access_control

        test_user = Mock()
        gxp_toolkit.access_control._current_user = test_user

        result = get_current_user()
        assert result == test_user

        # Test with no user
        gxp_toolkit.access_control._current_user = None
        result = get_current_user()
        assert result is None


class TestDecorators:
    """Test authentication and permission decorators."""

    def test_require_authentication_success(self):
        """Test require_authentication decorator with authenticated user."""
        # Set up authenticated user
        import gxp_toolkit.access_control

        mock_user = Mock(is_authenticated=True)
        gxp_toolkit.access_control._current_user = mock_user

        @require_authentication
        def protected_function():
            return "success"

        result = protected_function()
        assert result == "success"

    def test_require_authentication_failure(self):
        """Test require_authentication decorator without authenticated user."""
        # No current user
        import gxp_toolkit.access_control

        gxp_toolkit.access_control._current_user = None

        @require_authentication
        def protected_function():
            return "success"

        with pytest.raises(PermissionError, match="Authentication required"):
            protected_function()

    def test_require_permission_success(self):
        """Test require_permission decorator with correct permissions."""
        # Set up user with permissions
        import gxp_toolkit.access_control

        mock_user = Mock(
            is_authenticated=True, permissions={Permission.READ, Permission.WRITE}
        )
        mock_user.has_any_permission = Mock(return_value=True)
        gxp_toolkit.access_control._current_user = mock_user

        @require_permission(Permission.READ)
        def protected_function():
            return "success"

        result = protected_function()
        assert result == "success"

    def test_require_permission_failure(self):
        """Test require_permission decorator without correct permissions."""
        # Set up user without required permissions
        import gxp_toolkit.access_control

        mock_user = Mock(is_authenticated=True, permissions={Permission.READ})
        mock_user.has_any_permission = Mock(return_value=False)
        gxp_toolkit.access_control._current_user = mock_user

        @require_permission(Permission.DELETE)
        def protected_function():
            return "success"

        with pytest.raises(PermissionError, match="Insufficient permissions"):
            protected_function()

    def test_require_all_permissions_success(self):
        """Test require_all_permissions decorator with all permissions."""
        # Set up user with all required permissions
        import gxp_toolkit.access_control

        mock_user = Mock(
            is_authenticated=True,
            permissions={Permission.READ, Permission.WRITE, Permission.APPROVE},
        )
        mock_user.has_all_permissions = Mock(return_value=True)
        gxp_toolkit.access_control._current_user = mock_user

        @require_all_permissions(Permission.READ, Permission.WRITE)
        def protected_function():
            return "success"

        result = protected_function()
        assert result == "success"

    def test_require_all_permissions_failure(self):
        """Test require_all_permissions decorator without all permissions."""
        # Set up user missing some permissions
        import gxp_toolkit.access_control

        mock_user = Mock(is_authenticated=True, permissions={Permission.READ})
        mock_user.has_all_permissions = Mock(return_value=False)
        gxp_toolkit.access_control._current_user = mock_user

        @require_all_permissions(Permission.READ, Permission.WRITE)
        def protected_function():
            return "success"

        with pytest.raises(PermissionError, match="Insufficient permissions"):
            protected_function()


class TestBackwardCompatibility:
    """Test backward compatibility functions."""

    @patch("gxp_toolkit.access_control.get_current_user")
    @patch("gxp_toolkit.access_control.get_rbac_provider")
    def test_check_permission(self, mock_get_provider, mock_get_user):
        """Test check_permission function."""
        mock_user = Mock()
        mock_provider = Mock()
        mock_provider.check_permission.return_value = True

        mock_get_user.return_value = mock_user
        mock_get_provider.return_value = mock_provider

        result = check_permission("read")

        assert result is True
        mock_provider.check_permission.assert_called_once_with(mock_user, "read")

    @patch("gxp_toolkit.access_control.get_current_user")
    def test_has_role(self, mock_get_user):
        """Test has_role function."""
        mock_user = Mock(roles=["GxP.Operator", "GxP.Viewer"])
        mock_get_user.return_value = mock_user

        assert has_role("GxP.Operator") is True
        assert has_role("GxP.Admin") is False

    @patch("gxp_toolkit.access_control.get_current_user")
    def test_get_user_id(self, mock_get_user):
        """Test get_user_id function."""
        mock_user = Mock(id="user-123")
        mock_get_user.return_value = mock_user

        assert get_user_id() == "user-123"

        # Test with no user
        mock_get_user.return_value = None
        assert get_user_id() is None


class TestAuthenticationMethods:
    """Test authentication method detection."""

    @patch("gxp_toolkit.access_control.get_config")
    def test_detect_service_principal(self, mock_config):
        """Test detection of service principal authentication."""
        mock_config.return_value = Mock(
            azure_tenant_id=None,
            azure_subscription_id=None,
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        with patch.dict(
            os.environ,
            {"AZURE_CLIENT_ID": "test-client-id", "AZURE_CLIENT_SECRET": "test-secret"},
        ):
            with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
                with patch("gxp_toolkit.access_control.SecretClient"):
                    provider = AzureRBACProvider()
                    assert (
                        provider._detect_auth_method()
                        == AuthenticationMethod.SERVICE_PRINCIPAL
                    )

    @patch("gxp_toolkit.access_control.get_config")
    def test_detect_managed_identity(self, mock_config):
        """Test detection of managed identity authentication."""
        mock_config.return_value = Mock(
            azure_tenant_id=None,
            azure_subscription_id=None,
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        with patch.dict(
            os.environ,
            {
                "MSI_ENDPOINT": "http://localhost:12345",
                "AZURE_CLIENT_ID": "",
                "AZURE_CLIENT_SECRET": "",
            },
        ):
            with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
                with patch("gxp_toolkit.access_control.SecretClient"):
                    provider = AzureRBACProvider()
                    assert (
                        provider._detect_auth_method()
                        == AuthenticationMethod.MANAGED_IDENTITY
                    )

    @patch("gxp_toolkit.access_control.get_config")
    def test_detect_cli_auth(self, mock_config):
        """Test detection of CLI authentication."""
        mock_config.return_value = Mock(
            azure_tenant_id=None,
            azure_subscription_id=None,
            azure_resource_group=None,
            azure_key_vault_name=None,
        )

        with patch.dict(
            os.environ,
            {
                "AZURE_CLIENT_ID": "",
                "AZURE_CLIENT_SECRET": "",
                "MSI_ENDPOINT": "",
                "IDENTITY_ENDPOINT": "",
            },
        ):
            with patch("gxp_toolkit.access_control.AuthorizationManagementClient"):
                with patch("gxp_toolkit.access_control.SecretClient"):
                    provider = AzureRBACProvider()
                    assert provider._detect_auth_method() == AuthenticationMethod.CLI

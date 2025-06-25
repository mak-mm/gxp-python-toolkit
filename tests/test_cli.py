"""
Tests for GxP toolkit CLI module.
"""

import os
import tempfile
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner

from gxp_toolkit.cli import cli
from gxp_toolkit.config import GxPConfig


@pytest.fixture
def runner():
    """Create a CLI runner."""
    return CliRunner()


@pytest.fixture
def temp_config_file():
    """Create a temporary configuration file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write('{"application_name": "Test App", "environment": "test"}')
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_cli_help(self, runner):
        """Test CLI help command."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "GxP Python Toolkit" in result.output
        assert "compliance tools" in result.output.lower()

    def test_cli_version(self, runner):
        """Test CLI version command."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower()

    def test_cli_no_command(self, runner):
        """Test CLI with no command shows info."""
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        assert "GxP Python Toolkit" in result.output


class TestConfigCommands:
    """Test configuration-related commands."""

    def test_config_show(self, runner):
        """Test config show command."""
        result = runner.invoke(cli, ["config", "show"])
        assert result.exit_code == 0
        assert (
            "GxP Configuration" in result.output or "application_name" in result.output
        )

    def test_config_show_json(self, runner):
        """Test config show with JSON format."""
        result = runner.invoke(cli, ["config", "show", "--format", "json"])
        assert result.exit_code == 0
        # Should contain JSON data
        assert "{" in result.output and "}" in result.output

    @patch("gxp_toolkit.cli.get_config")
    @patch("gxp_toolkit.cli.set_config")
    def test_config_set(self, mock_set_config, mock_get_config, runner):
        """Test config set command."""
        mock_config = Mock(spec=GxPConfig)
        mock_config.environment = "production"
        mock_get_config.return_value = mock_config

        result = runner.invoke(cli, ["config", "set", "environment", "staging"])
        assert result.exit_code == 0
        assert "Set environment = staging" in result.output

    def test_config_set_invalid_key(self, runner):
        """Test config set with invalid key."""
        result = runner.invoke(cli, ["config", "set", "invalid_key", "value"])
        assert result.exit_code == 1
        assert "Error" in result.output and "no field" in result.output

    @patch("gxp_toolkit.cli.get_config")
    def test_config_validate(self, mock_get_config, runner):
        """Test config validate command."""
        # Create a mock config with all required attributes
        mock_config = Mock(spec=GxPConfig)
        mock_config.audit_retention_days = 3000
        mock_config.password_min_length = 12
        mock_config.audit_backend = "file"
        mock_config.environment = "development"
        mock_config.azure_tenant_id = None
        mock_get_config.return_value = mock_config

        result = runner.invoke(cli, ["config", "validate"])
        # Should complete with valid configuration message
        assert (
            "Configuration is valid" in result.output
            or "Configuration validation" in result.output
        )


class TestAuditCommands:
    """Test audit trail commands."""

    def test_audit_search_no_connection(self, runner):
        """Test audit search without proper setup."""
        # Without mocking, this should fail with a configuration error
        result = runner.invoke(cli, ["audit", "search"])
        assert result.exit_code == 1
        assert "Error" in result.output

    def test_audit_stats_no_connection(self, runner):
        """Test audit stats without proper setup."""
        # Without mocking, this should fail with a configuration error
        result = runner.invoke(cli, ["audit", "stats", "--days", "7"])
        assert result.exit_code == 1
        assert "Error" in result.output


class TestAuthCommands:
    """Test authentication commands."""

    @patch("gxp_toolkit.cli.get_current_user")
    def test_auth_whoami_not_authenticated(self, mock_user, runner):
        """Test whoami when not authenticated."""
        mock_user.return_value = None

        result = runner.invoke(cli, ["auth", "whoami"])
        assert result.exit_code == 0
        assert "Not authenticated" in result.output

    @patch("gxp_toolkit.cli.get_current_user")
    def test_auth_whoami_authenticated(self, mock_user, runner):
        """Test whoami when authenticated."""
        from gxp_toolkit.access_control import AuthenticationMethod, Permission, User

        mock_user.return_value = User(
            id="test_user",
            email="test@example.com",
            name="Test User",
            roles=["Admin"],
            permissions={Permission.READ, Permission.WRITE},
            authentication_method=AuthenticationMethod.CLI,
        )

        result = runner.invoke(cli, ["auth", "whoami"])
        assert result.exit_code == 0
        assert "Test User" in result.output
        assert "test@example.com" in result.output


class TestValidateCommands:
    """Test validation commands."""

    def test_validate_database_no_connection(self, runner):
        """Test validate database without connection string."""
        result = runner.invoke(cli, ["validate", "database"])
        assert result.exit_code == 1
        assert "Database connection string required" in result.output


class TestDoctorCommand:
    """Test doctor diagnostic command."""

    def test_doctor_command(self, runner):
        """Test doctor command."""
        result = runner.invoke(cli, ["doctor"])
        assert (
            result.exit_code == 0 or result.exit_code == 1
        )  # May fail if issues detected
        assert "Running GxP Toolkit diagnostics" in result.output
        assert "Configuration" in result.output


class TestCLIErrorHandling:
    """Test CLI error handling."""

    def test_invalid_command(self, runner):
        """Test invalid command."""
        result = runner.invoke(cli, ["invalid-command"])
        assert result.exit_code != 0
        assert "Error" in result.output or "Usage" in result.output

    def test_missing_required_args(self, runner):
        """Test command with missing required arguments."""
        result = runner.invoke(cli, ["config", "set"])
        assert result.exit_code != 0
        assert "Error" in result.output or "Usage" in result.output

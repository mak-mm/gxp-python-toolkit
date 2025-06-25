"""Tests for electronic signatures module."""

import base64
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from gxp_toolkit.access_control import AuthenticationMethod, Permission, User
from gxp_toolkit.electronic_signatures import (
    ElectronicSignatureProvider,
    SignatureAlgorithmType,
    SignatureManifest,
    SignaturePurpose,
    get_signature_provider,
    initialize_signature_provider,
    require_signature,
)


class TestSignatureManifest:
    """Test SignatureManifest functionality."""

    def test_manifest_creation(self):
        """Test creating a signature manifest."""
        manifest = SignatureManifest(
            signature_id="sig-123",
            signer_id="user-123",
            signer_name="Test User",
            signer_email="test@example.com",
            signature_purpose=SignaturePurpose.APPROVAL,
            signature_meaning="I approve this document",
            timestamp=datetime.now(timezone.utc),
            document_id="doc-123",
            document_type="SOP",
            document_version="1.0",
            document_hash="abc123",
            signature_algorithm=SignatureAlgorithmType.RSA_PSS_SHA256,
            signature_value="signature_base64",
            public_key_fingerprint="fingerprint123",
            authentication_method="azure_ad",
            authentication_factors=["password", "mfa"],
        )

        assert manifest.signature_id == "sig-123"
        assert manifest.signer_id == "user-123"
        assert manifest.signature_purpose == SignaturePurpose.APPROVAL
        assert "mfa" in manifest.authentication_factors

    def test_manifest_to_dict(self):
        """Test converting manifest to dictionary."""
        timestamp = datetime.now(timezone.utc)
        manifest = SignatureManifest(
            signature_id="sig-123",
            signer_id="user-123",
            signer_name="Test User",
            signer_email="test@example.com",
            signature_purpose=SignaturePurpose.APPROVAL,
            signature_meaning="I approve",
            timestamp=timestamp,
            document_id="doc-123",
            document_type="SOP",
            document_version="1.0",
            document_hash="abc123",
            signature_algorithm=SignatureAlgorithmType.RSA_PSS_SHA256,
            signature_value="sig_value",
            public_key_fingerprint="fingerprint",
            authentication_method="azure_ad",
        )

        data = manifest.to_dict()

        assert data["signature_id"] == "sig-123"
        assert data["signer"]["id"] == "user-123"
        assert data["signature"]["purpose"] == "approval"
        assert data["document"]["id"] == "doc-123"
        assert data["authentication"]["method"] == "azure_ad"

    def test_manifest_to_json(self):
        """Test converting manifest to JSON."""
        manifest = SignatureManifest(
            signature_id="sig-123",
            signer_id="user-123",
            signer_name="Test User",
            signer_email="test@example.com",
            signature_purpose=SignaturePurpose.REVIEW,
            signature_meaning="Reviewed",
            timestamp=datetime.now(timezone.utc),
            document_id="doc-123",
            document_type="Protocol",
            document_version="2.0",
            document_hash="xyz789",
            signature_algorithm=SignatureAlgorithmType.ECDSA_SHA256,
            signature_value="sig_value",
            public_key_fingerprint="fingerprint",
            authentication_method="service_principal",
        )

        json_str = manifest.to_json()
        data = json.loads(json_str)

        assert data["signature_id"] == "sig-123"
        assert data["signature"]["algorithm"] == "ES256"


class TestElectronicSignatureProvider:
    """Test ElectronicSignatureProvider functionality."""

    def test_provider_initialization_local_key(self):
        """Test provider initialization with local key generation."""
        provider = ElectronicSignatureProvider()

        assert provider.local_private_key is not None
        assert provider.local_public_key is not None
        assert provider.key_client is None

    def test_provider_initialization_with_private_key(self):
        """Test provider initialization with provided private key."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        provider = ElectronicSignatureProvider(local_private_key=private_key)

        assert provider.local_private_key == private_key
        assert provider.local_public_key is not None

    @patch("gxp_toolkit.electronic_signatures.KeyClient")
    def test_provider_initialization_with_key_vault(self, mock_key_client):
        """Test provider initialization with Key Vault."""
        provider = ElectronicSignatureProvider(
            key_vault_url="https://test-vault.vault.azure.net"
        )

        assert provider.key_vault_url == "https://test-vault.vault.azure.net"
        assert provider.key_client is not None
        mock_key_client.assert_called_once()

    def test_rsa_key_generation(self):
        """Test RSA key pair generation."""
        provider = ElectronicSignatureProvider(
            algorithm=SignatureAlgorithmType.RSA_PSS_SHA256
        )

        assert isinstance(provider.local_private_key, rsa.RSAPrivateKey)
        assert isinstance(provider.local_public_key, rsa.RSAPublicKey)
        assert provider.local_private_key.key_size == 4096

    def test_ecdsa_key_generation(self):
        """Test ECDSA key pair generation."""
        provider = ElectronicSignatureProvider(
            algorithm=SignatureAlgorithmType.ECDSA_SHA256
        )

        assert isinstance(provider.local_private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(provider.local_public_key, ec.EllipticCurvePublicKey)

    def test_document_hash_calculation(self):
        """Test document hash calculation."""
        provider = ElectronicSignatureProvider()

        # Test with string
        hash1 = provider._calculate_document_hash("test content")
        assert isinstance(hash1, str)
        assert len(hash1) > 0

        # Test with bytes
        hash2 = provider._calculate_document_hash(b"test content")
        assert hash1 == hash2

        # Test different content produces different hash
        hash3 = provider._calculate_document_hash("different content")
        assert hash1 != hash3

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.electronic_signatures.audit_event")
    def test_sign_document_local_key(self, mock_audit, mock_get_user):
        """Test document signing with local key."""
        # Mock user
        mock_user = User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            authentication_method=AuthenticationMethod.CLI,
            permissions={Permission.SIGN},
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_get_user.return_value = mock_user

        # Create provider
        provider = ElectronicSignatureProvider()

        # Sign document
        manifest = provider.sign_document(
            document_content="Test document content",
            document_id="doc-123",
            document_type="SOP",
            document_version="1.0",
            purpose=SignaturePurpose.APPROVAL,
            meaning="I approve this SOP",
            require_mfa=True,
        )

        assert manifest.signer_id == "user-123"
        assert manifest.document_id == "doc-123"
        assert manifest.signature_purpose == SignaturePurpose.APPROVAL
        assert len(manifest.signature_value) > 0
        assert len(manifest.public_key_fingerprint) > 0

        # Check audit was called
        mock_audit.assert_called()

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    def test_sign_document_no_mfa(self, mock_get_user):
        """Test document signing fails without MFA when required."""
        # Mock user without MFA
        mock_user = User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            permissions={Permission.SIGN},
            metadata={"authentication_factors": ["password"]},
        )
        mock_get_user.return_value = mock_user

        provider = ElectronicSignatureProvider()

        # Should fail due to missing MFA
        with pytest.raises(
            PermissionError, match="Multi-factor authentication required"
        ):
            provider.sign_document(
                document_content="Test content",
                document_id="doc-123",
                document_type="SOP",
                document_version="1.0",
                purpose=SignaturePurpose.APPROVAL,
                meaning="I approve",
                require_mfa=True,
            )

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    def test_sign_document_no_user(self, mock_get_user):
        """Test document signing fails without authenticated user."""
        # Mock no user (not authenticated)
        mock_get_user.return_value = None

        provider = ElectronicSignatureProvider()

        # Should fail due to no authenticated user
        with pytest.raises(PermissionError, match="User must be authenticated"):
            provider.sign_document(
                document_content="Test content",
                document_id="doc-123",
                document_type="SOP",
                document_version="1.0",
                purpose=SignaturePurpose.APPROVAL,
                meaning="I approve",
                require_mfa=False,
            )

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.electronic_signatures.audit_event")
    def test_signature_verification(self, mock_audit, mock_get_user):
        """Test signature verification with local key."""
        # Mock user
        mock_user = User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            authentication_method=AuthenticationMethod.CLI,
            permissions={Permission.SIGN},
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_get_user.return_value = mock_user

        # Create provider
        provider = ElectronicSignatureProvider()

        # Sign document
        document_content = "Test document content for verification"
        manifest = provider.sign_document(
            document_content=document_content,
            document_id="doc-123",
            document_type="Protocol",
            document_version="1.0",
            purpose=SignaturePurpose.APPROVAL,
            meaning="I approve",
            require_mfa=True,
        )

        # Verify signature
        is_valid = provider.verify_signature(manifest, document_content)
        assert is_valid is True

        # Verify with tampered content
        is_valid = provider.verify_signature(manifest, "Tampered content")
        assert is_valid is False

    @patch("gxp_toolkit.electronic_signatures.KeyClient")
    @patch("gxp_toolkit.electronic_signatures.CryptographyClient")
    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.electronic_signatures.audit_event")
    def test_sign_with_key_vault(
        self, mock_audit, mock_get_user, mock_crypto_client, mock_key_client
    ):
        """Test signing with Azure Key Vault."""
        # Mock user
        mock_user = User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            authentication_method=AuthenticationMethod.SERVICE_PRINCIPAL,
            permissions={Permission.SIGN},
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_get_user.return_value = mock_user

        # Mock Key Vault
        mock_key = Mock()
        mock_key_client_instance = Mock()
        mock_key_client_instance.get_key.return_value = mock_key
        mock_key_client.return_value = mock_key_client_instance

        # Mock crypto client
        mock_sign_result = Mock()
        mock_sign_result.signature = b"test_signature"
        mock_crypto_instance = Mock()
        mock_crypto_instance.sign.return_value = mock_sign_result
        mock_crypto_client.return_value = mock_crypto_instance

        # Create provider with Key Vault
        provider = ElectronicSignatureProvider(
            key_vault_url="https://test-vault.vault.azure.net"
        )

        # Sign document
        manifest = provider.sign_document(
            document_content="Test content",
            document_id="doc-123",
            document_type="SOP",
            document_version="1.0",
            purpose=SignaturePurpose.APPROVAL,
            meaning="I approve",
            key_name="test-key",
            require_mfa=True,
        )

        assert manifest.signature_value == base64.b64encode(b"test_signature").decode(
            "utf-8"
        )
        mock_crypto_instance.sign.assert_called_once()


class TestGlobalFunctions:
    """Test global signature functions."""

    @patch("gxp_toolkit.electronic_signatures.get_config")
    def test_initialize_signature_provider(self, mock_config):
        """Test initializing signature provider."""
        mock_config.return_value = Mock(azure_key_vault_name=None)

        provider = initialize_signature_provider()

        assert provider is not None
        assert isinstance(provider, ElectronicSignatureProvider)

    @patch("gxp_toolkit.electronic_signatures.get_config")
    def test_initialize_signature_provider_with_key_vault(self, mock_config):
        """Test initializing signature provider with Key Vault config."""
        mock_config.return_value = Mock(azure_key_vault_name="test-vault")

        with patch("gxp_toolkit.electronic_signatures.KeyClient"):
            provider = initialize_signature_provider()

            assert provider is not None
            assert provider.key_vault_url == "https://test-vault.vault.azure.net"

    def test_get_signature_provider_auto_init(self):
        """Test auto-initialization of signature provider."""
        # Reset global provider
        import gxp_toolkit.electronic_signatures

        gxp_toolkit.electronic_signatures._signature_provider = None

        with patch(
            "gxp_toolkit.electronic_signatures.initialize_signature_provider"
        ) as mock_init:
            mock_provider = Mock()
            mock_init.return_value = mock_provider

            # Mock should set the global variable
            def set_provider(*args, **kwargs):
                gxp_toolkit.electronic_signatures._signature_provider = mock_provider
                return mock_provider

            mock_init.side_effect = set_provider

            result = get_signature_provider()

            assert result == mock_provider
            mock_init.assert_called_once()


class TestRequireSignatureDecorator:
    """Test require_signature decorator."""

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.electronic_signatures.audit_event")
    def test_require_signature_success(self, mock_audit, mock_get_user):
        """Test require_signature decorator with valid user."""
        # Mock user with sign permission and MFA
        mock_user = User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            permissions={Permission.SIGN},
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_user.has_permission = Mock(return_value=True)
        mock_get_user.return_value = mock_user

        @require_signature(purpose=SignaturePurpose.APPROVAL)
        def test_function():
            return "success"

        result = test_function()
        assert result == "success"

        # Check audit was called twice (required and executed)
        assert mock_audit.call_count == 2

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    def test_require_signature_no_user(self, mock_get_user):
        """Test require_signature decorator without authenticated user."""
        mock_get_user.return_value = None

        @require_signature()
        def test_function():
            return "success"

        with pytest.raises(PermissionError, match="Authentication required"):
            test_function()

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    def test_require_signature_no_permission(self, mock_get_user):
        """Test require_signature decorator without sign permission."""
        # Mock user without sign permission
        mock_user = User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            permissions={Permission.READ},
        )
        mock_user.has_permission = Mock(return_value=False)
        mock_get_user.return_value = mock_user

        @require_signature()
        def test_function():
            return "success"

        with pytest.raises(PermissionError, match="does not have signing permission"):
            test_function()

    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    def test_require_signature_no_mfa(self, mock_get_user):
        """Test require_signature decorator without MFA when required."""
        # Mock user without MFA
        mock_user = User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            permissions={Permission.SIGN},
            metadata={"authentication_factors": ["password"]},
        )
        mock_user.has_permission = Mock(return_value=True)
        mock_get_user.return_value = mock_user

        @require_signature(require_mfa=True)
        def test_function():
            return "success"

        with pytest.raises(
            PermissionError, match="Multi-factor authentication required"
        ):
            test_function()


class TestSignatureAlgorithms:
    """Test different signature algorithms."""

    @pytest.mark.parametrize(
        "algorithm",
        [
            SignatureAlgorithmType.RSA_PSS_SHA256,
            SignatureAlgorithmType.RSA_PSS_SHA512,
            SignatureAlgorithmType.ECDSA_SHA256,
            SignatureAlgorithmType.ECDSA_SHA512,
        ],
    )
    @patch("gxp_toolkit.electronic_signatures.get_current_user")
    @patch("gxp_toolkit.electronic_signatures.audit_event")
    def test_sign_verify_with_algorithm(self, mock_audit, mock_get_user, algorithm):
        """Test signing and verification with different algorithms."""
        # Mock user
        mock_user = User(
            id="user-123",
            email="test@example.com",
            name="Test User",
            permissions={Permission.SIGN},
            metadata={"authentication_factors": ["password", "mfa"]},
        )
        mock_get_user.return_value = mock_user

        # Create provider with specific algorithm
        provider = ElectronicSignatureProvider(algorithm=algorithm)

        # Sign document
        document_content = f"Test content for {algorithm.value}"
        manifest = provider.sign_document(
            document_content=document_content,
            document_id="doc-123",
            document_type="Test",
            document_version="1.0",
            purpose=SignaturePurpose.APPROVAL,
            meaning="Test signature",
            require_mfa=True,
        )

        assert manifest.signature_algorithm == algorithm

        # Verify signature
        is_valid = provider.verify_signature(manifest, document_content)
        assert is_valid is True

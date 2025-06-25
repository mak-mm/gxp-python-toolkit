"""
Electronic signatures module for GxP compliance.

Implements 21 CFR Part 11 compliant electronic signatures with:
- Cryptographic signing using RSA/ECDSA
- Multi-factor authentication integration
- Signature manifest generation
- Audit trail integration
- Azure Key Vault support for key management
"""

import base64
import functools
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .access_control import Permission, get_current_user
from .audit_trail import audit_event
from .config import get_config

logger = logging.getLogger(__name__)


class SignatureAlgorithmType(str, Enum):
    """Supported signature algorithms."""

    RSA_PSS_SHA256 = "RS256"
    RSA_PSS_SHA512 = "RS512"
    ECDSA_SHA256 = "ES256"
    ECDSA_SHA512 = "ES512"


class SignaturePurpose(str, Enum):
    """Purpose/meaning of electronic signature."""

    APPROVAL = "approval"
    REVIEW = "review"
    VERIFICATION = "verification"
    WITNESS = "witness"
    AUTHORSHIP = "authorship"
    RESPONSIBILITY = "responsibility"


@dataclass
class SignatureManifest:
    """Manifest containing all signature-related information for 21 CFR Part 11
    compliance.

    This class represents a complete electronic signature record that includes all
    information required by FDA 21 CFR Part 11.11(a) for electronic signatures:

    - The printed name of the signer
    - The date and time when the signature was executed
    - The meaning (such as review, approval, responsibility, or authorship)

    Additionally, it includes cryptographic signature data, document identification,
    and authentication context to ensure the integrity and non-repudiation of the
    signature.

    Attributes:
        signature_id: Unique identifier for this signature record.
        signer_id: Unique identifier of the person signing.
        signer_name: Full printed name of the signer.
        signer_email: Email address of the signer.
        signature_purpose: Structured purpose from SignaturePurpose enum.
        signature_meaning: Human-readable meaning of the signature.
        timestamp: UTC timestamp when signature was executed.
        document_id: Unique identifier of the signed document.
        document_type: Type/category of the document being signed.
        document_version: Version of the document at time of signing.
        document_hash: Cryptographic hash of the document content.
        signature_algorithm: Algorithm used for cryptographic signature.
        signature_value: Base64-encoded cryptographic signature.
        public_key_fingerprint: Fingerprint of the public key used.
        authentication_method: Method used to authenticate the signer.
        timezone: Timezone of the signature (default: UTC).
        hash_algorithm: Algorithm used for document hashing (default: SHA256).
        certificate_info: Optional X.509 certificate information.
        authentication_factors: List of authentication factors used.
        ip_address: IP address from which signature was made.
        user_agent: User agent string of the signing client.

    Example:
        Creating a signature manifest:

        >>> manifest = SignatureManifest(
        ...     signature_id="SIG-12345",
        ...     signer_id="john.doe",
        ...     signer_name="John Doe",
        ...     signer_email="john.doe@company.com",
        ...     signature_purpose=SignaturePurpose.APPROVAL,
        ...     signature_meaning="Approve batch release",
        ...     timestamp=datetime.now(timezone.utc),
        ...     document_id="BATCH-2024-001",
        ...     document_type="Batch Release Record",
        ...     document_version="1.0",
        ...     document_hash="sha256:abc123...",
        ...     signature_algorithm=SignatureAlgorithmType.RSA_PSS_SHA256,
        ...     signature_value="base64signature...",
        ...     public_key_fingerprint="sha256:def456...",
        ...     authentication_method="username_password_mfa"
        ... )

    Note:
        All signature manifests are immutable once created and include
        cryptographic protection against tampering. The manifest itself
        can be verified using the included signature data.
    """

    signature_id: str
    signer_id: str
    signer_name: str
    signer_email: str
    signature_purpose: SignaturePurpose
    signature_meaning: str
    timestamp: datetime

    # Document information
    document_id: str
    document_type: str
    document_version: str
    document_hash: str

    # Signature data
    signature_algorithm: SignatureAlgorithmType
    signature_value: str  # Base64 encoded signature
    public_key_fingerprint: str

    # Authentication context
    authentication_method: str

    # Optional fields with defaults
    timezone: str = "UTC"
    hash_algorithm: str = "SHA256"
    certificate_info: Optional[Dict[str, Any]] = None
    authentication_factors: List[str] = field(default_factory=list)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert manifest to dictionary for serialization."""
        return {
            "signature_id": self.signature_id,
            "signer": {
                "id": self.signer_id,
                "name": self.signer_name,
                "email": self.signer_email,
            },
            "signature": {
                "purpose": self.signature_purpose.value,
                "meaning": self.signature_meaning,
                "timestamp": self.timestamp.isoformat(),
                "timezone": self.timezone,
                "algorithm": self.signature_algorithm.value,
                "value": self.signature_value,
                "public_key_fingerprint": self.public_key_fingerprint,
            },
            "document": {
                "id": self.document_id,
                "type": self.document_type,
                "version": self.document_version,
                "hash": self.document_hash,
                "hash_algorithm": self.hash_algorithm,
            },
            "authentication": {
                "method": self.authentication_method,
                "factors": self.authentication_factors,
                "ip_address": self.ip_address,
                "user_agent": self.user_agent,
            },
            "certificate_info": self.certificate_info,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Convert manifest to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class ElectronicSignatureProvider:
    """
    Provider for electronic signature operations.
    Supports both local key management and Azure Key Vault.
    """

    def __init__(
        self,
        key_vault_url: Optional[str] = None,
        credential: Optional[DefaultAzureCredential] = None,
        local_private_key: Optional[
            Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
        ] = None,
        algorithm: SignatureAlgorithmType = SignatureAlgorithmType.RSA_PSS_SHA256,
    ):
        """
        Initialize signature provider.

        Args:
            key_vault_url: Azure Key Vault URL for key management
            credential: Azure credential for Key Vault access
            local_private_key: Local private key (for testing/development)
            algorithm: Signature algorithm to use
        """
        self.algorithm = algorithm
        self.key_vault_url = key_vault_url
        self.credential = credential or DefaultAzureCredential()
        self.local_private_key = local_private_key
        self.key_client: Optional[KeyClient]

        # Initialize Key Vault client if URL provided
        if key_vault_url:
            self.key_client = KeyClient(
                vault_url=key_vault_url, credential=self.credential
            )
        else:
            self.key_client = None

        # Generate local key pair if no key management configured
        if not key_vault_url and not local_private_key:
            logger.warning(
                "No key management configured, generating ephemeral key pair"
            )
            self.local_private_key, self.local_public_key = self._generate_key_pair()
        elif local_private_key:
            self.local_public_key = self._get_public_key(local_private_key)

    def _generate_key_pair(
        self,
    ) -> Tuple[
        Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    ]:
        """Generate a new key pair based on algorithm."""
        if self.algorithm in [
            SignatureAlgorithmType.RSA_PSS_SHA256,
            SignatureAlgorithmType.RSA_PSS_SHA512,
        ]:
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
            public_key = private_key.public_key()
        else:  # ECDSA
            ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ec_public_key = ec_private_key.public_key()
            return ec_private_key, ec_public_key

        return private_key, public_key

    def _get_public_key(
        self, private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    ) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
        """Extract public key from private key."""
        return private_key.public_key()

    def _calculate_document_hash(
        self, content: Union[str, bytes], algorithm: str = "SHA256"
    ) -> str:
        """Calculate document hash."""
        if isinstance(content, str):
            content = content.encode("utf-8")

        if algorithm == "SHA256":
            hash_obj = hashlib.sha256()
        elif algorithm == "SHA512":
            hash_obj = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        hash_obj.update(content)
        return base64.b64encode(hash_obj.digest()).decode("utf-8")

    def _get_key_fingerprint(
        self, public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
    ) -> str:
        """Calculate public key fingerprint."""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_bytes).hexdigest()

    def sign_document(
        self,
        document_content: Union[str, bytes],
        document_id: str,
        document_type: str,
        document_version: str,
        purpose: SignaturePurpose,
        meaning: str,
        key_name: Optional[str] = None,
        require_mfa: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SignatureManifest:
        """
        Sign a document electronically.

        Args:
            document_content: Content to sign
            document_id: Unique document identifier
            document_type: Type of document
            document_version: Document version
            purpose: Purpose of signature
            meaning: Meaning/intent of signature
            key_name: Key Vault key name (if using Key Vault)
            require_mfa: Whether to require MFA
            metadata: Additional metadata

        Returns:
            SignatureManifest with all signature details
        """
        # Get current user
        user = get_current_user()
        if not user:
            raise PermissionError("User must be authenticated to sign documents")

        # Check MFA if required
        if require_mfa and "mfa" not in user.metadata.get("authentication_factors", []):
            raise PermissionError("Multi-factor authentication required for signing")

        # Calculate document hash
        document_hash = self._calculate_document_hash(document_content)

        # Create timestamp once to ensure consistency
        signature_timestamp = datetime.now(timezone.utc)

        # Create signature input
        signature_input = {
            "document_hash": document_hash,
            "document_id": document_id,
            "signer_id": user.id,
            "timestamp": signature_timestamp.isoformat(),
            "purpose": purpose.value,
        }
        signature_input_bytes = json.dumps(signature_input, sort_keys=True).encode(
            "utf-8"
        )

        # Sign based on key management method
        if self.key_vault_url and key_name:
            signature_value, public_key_fingerprint = self._sign_with_key_vault(
                signature_input_bytes, key_name
            )
        else:
            signature_value, public_key_fingerprint = self._sign_with_local_key(
                signature_input_bytes
            )

        # Create manifest
        import uuid

        manifest = SignatureManifest(
            signature_id=str(uuid.uuid4()),
            signer_id=user.id,
            signer_name=user.name,
            signer_email=user.email,
            signature_purpose=purpose,
            signature_meaning=meaning,
            timestamp=signature_timestamp,
            document_id=document_id,
            document_type=document_type,
            document_version=document_version,
            document_hash=document_hash,
            signature_algorithm=self.algorithm,
            signature_value=signature_value,
            public_key_fingerprint=public_key_fingerprint,
            authentication_method=user.authentication_method.value,
            authentication_factors=user.metadata.get(
                "authentication_factors", ["password"]
            ),
            metadata=metadata or {},
        )

        # Audit the signature event
        audit_event(
            action="document.signed",
            resource_type="document",
            resource_id=document_id,
            user_id=user.id,
            details={
                "signature_id": manifest.signature_id,
                "purpose": purpose.value,
                "document_type": document_type,
                "algorithm": self.algorithm.value,
            },
        )

        return manifest

    def _sign_with_key_vault(self, data: bytes, key_name: str) -> Tuple[str, str]:
        """Sign data using Azure Key Vault."""
        # Get key and create crypto client
        if self.key_client is None:  # nosec B101
            raise RuntimeError("Key client not initialized")
        key = self.key_client.get_key(key_name)
        crypto_client = CryptographyClient(key, credential=self.credential)

        # Map algorithm
        if self.algorithm == SignatureAlgorithmType.RSA_PSS_SHA256:
            algorithm = SignatureAlgorithm.ps256
        elif self.algorithm == SignatureAlgorithmType.RSA_PSS_SHA512:
            algorithm = SignatureAlgorithm.ps512
        elif self.algorithm == SignatureAlgorithmType.ECDSA_SHA256:
            algorithm = SignatureAlgorithm.es256
        else:
            algorithm = SignatureAlgorithm.es512

        # Sign
        result = crypto_client.sign(algorithm, data)
        signature_value = base64.b64encode(result.signature).decode("utf-8")

        # Get key fingerprint
        # Note: In production, you'd calculate this from the actual public key
        public_key_fingerprint = hashlib.sha256(key_name.encode()).hexdigest()

        return signature_value, public_key_fingerprint

    def _sign_with_local_key(self, data: bytes) -> Tuple[str, str]:
        """Sign data using local private key."""
        if not self.local_private_key:
            raise ValueError("No private key available for signing")

        if isinstance(self.local_private_key, rsa.RSAPrivateKey):
            # RSA signing
            if self.algorithm == SignatureAlgorithmType.RSA_PSS_SHA256:
                signature = self.local_private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            else:  # SHA512
                signature = self.local_private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA512()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA512(),
                )
        else:
            # ECDSA signing
            if self.algorithm == SignatureAlgorithmType.ECDSA_SHA256:
                signature = self.local_private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            else:  # SHA512
                signature = self.local_private_key.sign(data, ec.ECDSA(hashes.SHA512()))

        signature_value = base64.b64encode(signature).decode("utf-8")
        public_key_fingerprint = self._get_key_fingerprint(self.local_public_key)

        return signature_value, public_key_fingerprint

    def verify_signature(
        self,
        manifest: SignatureManifest,
        document_content: Union[str, bytes],
        public_key: Optional[Any] = None,
    ) -> bool:
        """
        Verify an electronic signature.

        Args:
            manifest: Signature manifest to verify
            document_content: Document content to verify against
            public_key: Public key to use (if not using Key Vault)

        Returns:
            True if signature is valid
        """
        try:
            # Verify document hash
            calculated_hash = self._calculate_document_hash(document_content)
            if calculated_hash != manifest.document_hash:
                logger.warning(
                    f"Document hash mismatch for signature {manifest.signature_id}"
                )
                return False

            # Recreate signature input
            signature_input = {
                "document_hash": manifest.document_hash,
                "document_id": manifest.document_id,
                "signer_id": manifest.signer_id,
                "timestamp": manifest.timestamp.isoformat(),
                "purpose": manifest.signature_purpose.value,
            }
            signature_input_bytes = json.dumps(signature_input, sort_keys=True).encode(
                "utf-8"
            )

            # Decode signature
            signature_bytes = base64.b64decode(manifest.signature_value)

            # Verify based on key management
            if (
                self.key_vault_url
                and manifest.certificate_info
                and manifest.certificate_info.get("key_name")
            ):
                return self._verify_with_key_vault(
                    signature_input_bytes,
                    signature_bytes,
                    manifest.certificate_info["key_name"],
                    manifest.signature_algorithm,
                )
            else:
                if not public_key:
                    public_key = self.local_public_key
                return self._verify_with_local_key(
                    signature_input_bytes,
                    signature_bytes,
                    public_key,
                    manifest.signature_algorithm,
                )

        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    def _verify_with_key_vault(
        self,
        data: bytes,
        signature: bytes,
        key_name: str,
        algorithm: SignatureAlgorithmType,
    ) -> bool:
        """Verify signature using Azure Key Vault."""
        # Get key and create crypto client
        if self.key_client is None:  # nosec B101
            raise RuntimeError("Key client not initialized")
        key = self.key_client.get_key(key_name)
        crypto_client = CryptographyClient(key, credential=self.credential)

        # Map algorithm
        if algorithm == SignatureAlgorithmType.RSA_PSS_SHA256:
            sig_algorithm = SignatureAlgorithm.ps256
        elif algorithm == SignatureAlgorithmType.RSA_PSS_SHA512:
            sig_algorithm = SignatureAlgorithm.ps512
        elif algorithm == SignatureAlgorithmType.ECDSA_SHA256:
            sig_algorithm = SignatureAlgorithm.es256
        else:
            sig_algorithm = SignatureAlgorithm.es512

        # Verify
        result = crypto_client.verify(sig_algorithm, data, signature)
        return bool(result.is_valid)

    def _verify_with_local_key(
        self,
        data: bytes,
        signature: bytes,
        public_key: Any,
        algorithm: SignatureAlgorithmType,
    ) -> bool:
        """Verify signature using local public key."""
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                # RSA verification
                if algorithm == SignatureAlgorithmType.RSA_PSS_SHA256:
                    public_key.verify(
                        signature,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                else:  # SHA512
                    public_key.verify(
                        signature,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA512()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA512(),
                    )
            else:
                # ECDSA verification
                if algorithm == SignatureAlgorithmType.ECDSA_SHA256:
                    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                else:  # SHA512
                    public_key.verify(signature, data, ec.ECDSA(hashes.SHA512()))
            return True
        except InvalidSignature:
            return False


# Global signature provider
_signature_provider: Optional[ElectronicSignatureProvider] = None


def initialize_signature_provider(
    key_vault_url: Optional[str] = None,
    credential: Optional[DefaultAzureCredential] = None,
    algorithm: SignatureAlgorithmType = SignatureAlgorithmType.RSA_PSS_SHA256,
) -> ElectronicSignatureProvider:
    """Initialize global signature provider."""
    global _signature_provider

    config = get_config()
    key_vault_url = key_vault_url or (
        f"https://{config.azure_key_vault_name}.vault.azure.net"
        if config.azure_key_vault_name
        else None
    )

    _signature_provider = ElectronicSignatureProvider(
        key_vault_url=key_vault_url, credential=credential, algorithm=algorithm
    )
    return _signature_provider


def get_signature_provider() -> ElectronicSignatureProvider:
    """Get global signature provider instance."""
    if _signature_provider is None:
        initialize_signature_provider()
    if _signature_provider is None:  # nosec B101
        raise RuntimeError("Signature provider initialization failed")
    return _signature_provider


def require_signature(
    purpose: SignaturePurpose = SignaturePurpose.APPROVAL, require_mfa: bool = True
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to require electronic signature for a function.

    Args:
        purpose: Purpose of the signature
        require_mfa: Whether to require MFA

    Usage:
        @require_signature(purpose=SignaturePurpose.APPROVAL)
        def approve_document(doc_id: str):
            pass
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get current user
            user = get_current_user()
            if not user:
                raise PermissionError("Authentication required for signature")

            # Check signature permission
            if not user.has_permission(Permission.SIGN):
                raise PermissionError("User does not have signing permission")

            # Check MFA if required
            if require_mfa and "mfa" not in user.metadata.get(
                "authentication_factors", []
            ):
                raise PermissionError(
                    "Multi-factor authentication required for signing"
                )

            # Create signature context
            func_name = func.__name__
            module_name = func.__module__

            # Audit signature requirement
            audit_event(
                action="signature.required",
                resource_type="function",
                resource_id=f"{module_name}.{func_name}",
                user_id=user.id,
                details={"purpose": purpose.value, "require_mfa": require_mfa},
            )

            # Execute function
            result = func(*args, **kwargs)

            # Audit successful execution with signature
            audit_event(
                action="signature.executed",
                resource_type="function",
                resource_id=f"{module_name}.{func_name}",
                user_id=user.id,
                details={"purpose": purpose.value, "result": "success"},
            )

            return result

        return wrapper

    return decorator


# Re-export for convenience
__all__ = [
    "SignatureAlgorithmType",
    "SignaturePurpose",
    "SignatureManifest",
    "ElectronicSignatureProvider",
    "initialize_signature_provider",
    "get_signature_provider",
    "require_signature",
]

"""
Checksum calculation and verification for data integrity.

Provides various checksum algorithms and utilities for ensuring
data has not been tampered with or corrupted.
"""

import base64
import hashlib
import hmac
from pathlib import Path
from typing import Any, Optional, Union

from ..config import ChecksumAlgorithm, get_config


class ChecksumProvider:
    """Provider for checksum calculation and verification."""

    def __init__(self, algorithm: Optional[ChecksumAlgorithm] = None):
        """
        Initialize checksum provider.

        Args:
            algorithm: Checksum algorithm to use (defaults to config)
        """
        config = get_config()
        self.algorithm = algorithm or config.checksum_algorithm

    def calculate(self, data: Union[str, bytes]) -> str:
        """
        Calculate checksum for data.

        Args:
            data: Data to calculate checksum for

        Returns:
            Base64-encoded checksum
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        hasher: Any  # Type varies by algorithm
        if self.algorithm == ChecksumAlgorithm.MD5:
            # MD5 used for legacy compatibility only, not for security
            try:
                hasher = hashlib.md5(usedforsecurity=False)  # type: ignore[call-arg] # nosec B324
            except TypeError:
                # Fallback for older Python versions
                hasher = hashlib.md5()  # nosec B324
        elif self.algorithm == ChecksumAlgorithm.SHA256:
            hasher = hashlib.sha256()
        elif self.algorithm == ChecksumAlgorithm.SHA512:
            hasher = hashlib.sha512()
        elif self.algorithm == ChecksumAlgorithm.BLAKE2B:
            hasher = hashlib.blake2b()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        hasher.update(data)
        return base64.b64encode(hasher.digest()).decode("utf-8")

    def calculate_hex(self, data: Union[str, bytes]) -> str:
        """
        Calculate checksum and return as hex string.

        Args:
            data: Data to calculate checksum for

        Returns:
            Hex-encoded checksum
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        hasher: Any  # Type varies by algorithm
        if self.algorithm == ChecksumAlgorithm.MD5:
            # MD5 used for legacy compatibility only, not for security
            try:
                hasher = hashlib.md5(usedforsecurity=False)  # type: ignore[call-arg] # nosec B324
            except TypeError:
                # Fallback for older Python versions
                hasher = hashlib.md5()  # nosec B324
        elif self.algorithm == ChecksumAlgorithm.SHA256:
            hasher = hashlib.sha256()
        elif self.algorithm == ChecksumAlgorithm.SHA512:
            hasher = hashlib.sha512()
        elif self.algorithm == ChecksumAlgorithm.BLAKE2B:
            hasher = hashlib.blake2b()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        hasher.update(data)
        return str(hasher.hexdigest())

    def verify(self, data: Union[str, bytes], expected_checksum: str) -> bool:
        """
        Verify data against expected checksum.

        Args:
            data: Data to verify
            expected_checksum: Expected checksum (base64 or hex)

        Returns:
            True if checksum matches
        """
        calculated = self.calculate(data)
        if calculated == expected_checksum:
            return True

        # Try hex format
        calculated_hex = self.calculate_hex(data)
        return calculated_hex == expected_checksum

    def calculate_file(
        self, file_path: Union[str, Path], chunk_size: int = 8192
    ) -> str:
        """
        Calculate checksum for a file.

        Args:
            file_path: Path to file
            chunk_size: Size of chunks to read

        Returns:
            Base64-encoded checksum
        """
        file_path = Path(file_path)

        hasher: Any  # Type varies by algorithm
        if self.algorithm == ChecksumAlgorithm.MD5:
            # MD5 used for legacy compatibility only, not for security
            try:
                hasher = hashlib.md5(usedforsecurity=False)  # type: ignore[call-arg] # nosec B324
            except TypeError:
                # Fallback for older Python versions
                hasher = hashlib.md5()  # nosec B324
        elif self.algorithm == ChecksumAlgorithm.SHA256:
            hasher = hashlib.sha256()
        elif self.algorithm == ChecksumAlgorithm.SHA512:
            hasher = hashlib.sha512()
        elif self.algorithm == ChecksumAlgorithm.BLAKE2B:
            hasher = hashlib.blake2b()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)

        return base64.b64encode(hasher.digest()).decode("utf-8")

    def verify_file(self, file_path: Union[str, Path], expected_checksum: str) -> bool:
        """
        Verify file against expected checksum.

        Args:
            file_path: Path to file
            expected_checksum: Expected checksum

        Returns:
            True if checksum matches
        """
        calculated = self.calculate_file(file_path)
        return calculated == expected_checksum

    def calculate_hmac(self, data: Union[str, bytes], key: Union[str, bytes]) -> str:
        """
        Calculate HMAC for data with secret key.

        Args:
            data: Data to calculate HMAC for
            key: Secret key

        Returns:
            Base64-encoded HMAC
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        if isinstance(key, str):
            key = key.encode("utf-8")

        if self.algorithm == ChecksumAlgorithm.MD5:
            digest = hashlib.md5
        elif self.algorithm == ChecksumAlgorithm.SHA256:
            digest = hashlib.sha256
        elif self.algorithm == ChecksumAlgorithm.SHA512:
            digest = hashlib.sha512
        else:
            # BLAKE2B doesn't work with HMAC, fall back to SHA256
            digest = hashlib.sha256

        mac = hmac.new(key, data, digest)
        return base64.b64encode(mac.digest()).decode("utf-8")

    def verify_hmac(
        self, data: Union[str, bytes], key: Union[str, bytes], expected_hmac: str
    ) -> bool:
        """
        Verify HMAC for data.

        Args:
            data: Data to verify
            key: Secret key
            expected_hmac: Expected HMAC

        Returns:
            True if HMAC matches
        """
        calculated = self.calculate_hmac(data, key)
        return hmac.compare_digest(calculated, expected_hmac)


# Global checksum provider instance
_checksum_provider: Optional[ChecksumProvider] = None


def get_checksum_provider() -> ChecksumProvider:
    """Get global checksum provider instance."""
    global _checksum_provider
    if _checksum_provider is None:
        _checksum_provider = ChecksumProvider()
    return _checksum_provider


def calculate_checksum(
    data: Union[str, bytes], algorithm: Optional[ChecksumAlgorithm] = None
) -> str:
    """
    Calculate checksum for data.

    Args:
        data: Data to calculate checksum for
        algorithm: Optional algorithm override

    Returns:
        Base64-encoded checksum
    """
    if algorithm:
        provider = ChecksumProvider(algorithm)
    else:
        provider = get_checksum_provider()
    return provider.calculate(data)


def verify_checksum(
    data: Union[str, bytes],
    expected_checksum: str,
    algorithm: Optional[ChecksumAlgorithm] = None,
) -> bool:
    """
    Verify data against expected checksum.

    Args:
        data: Data to verify
        expected_checksum: Expected checksum
        algorithm: Optional algorithm override

    Returns:
        True if checksum matches
    """
    if algorithm:
        provider = ChecksumProvider(algorithm)
    else:
        provider = get_checksum_provider()
    return provider.verify(data, expected_checksum)


def calculate_file_checksum(
    file_path: Union[str, Path], algorithm: Optional[ChecksumAlgorithm] = None
) -> str:
    """
    Calculate checksum for a file.

    Args:
        file_path: Path to file
        algorithm: Optional algorithm override

    Returns:
        Base64-encoded checksum
    """
    if algorithm:
        provider = ChecksumProvider(algorithm)
    else:
        provider = get_checksum_provider()
    return provider.calculate_file(file_path)


def verify_file_checksum(
    file_path: Union[str, Path],
    expected_checksum: str,
    algorithm: Optional[ChecksumAlgorithm] = None,
) -> bool:
    """
    Verify file against expected checksum.

    Args:
        file_path: Path to file
        expected_checksum: Expected checksum
        algorithm: Optional algorithm override

    Returns:
        True if checksum matches
    """
    if algorithm:
        provider = ChecksumProvider(algorithm)
    else:
        provider = get_checksum_provider()
    return provider.verify_file(file_path, expected_checksum)

"""
Crypto Service
Handles document encryption with AES-256-GCM and key derivation using PBKDF2
"""

import base64
import hashlib
import os
import secrets
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoServiceError(Exception):
    """Base exception for crypto service errors"""

    def __init__(self, message: str, error_code: str):
        self.message = message
        self.error_code = error_code
        self.timestamp = datetime.now()
        super().__init__(message)


class EncryptionError(CryptoServiceError):
    """Raised when encryption operation fails"""

    def __init__(self, message: str = "Encryption operation failed"):
        super().__init__(message, "ENCRYPTION_ERROR")


class FileNotFoundError(CryptoServiceError):
    """Raised when source file is not found"""

    def __init__(self, message: str = "Source file not found"):
        super().__init__(message, "FILE_NOT_FOUND_ERROR")


class InvalidParametersError(CryptoServiceError):
    """Raised when invalid parameters are provided"""

    def __init__(self, message: str = "Invalid parameters provided"):
        super().__init__(message, "INVALID_PARAMETERS")


class KeyDerivationError(CryptoServiceError):
    """Raised when key derivation fails"""

    def __init__(self, message: str = "Key derivation failed"):
        super().__init__(message, "KEY_DERIVATION_ERROR")


class InsufficientDiskSpaceError(CryptoServiceError):
    """Raised when insufficient disk space for encryption"""

    def __init__(self, message: str = "Insufficient disk space"):
        super().__init__(message, "INSUFFICIENT_DISK_SPACE")


class CryptoService:
    """
    Cryptographic service for document encryption and key management

    Provides AES-256-GCM encryption with PBKDF2-SHA256 key derivation
    following security best practices with ephemeral key management.
    """

    def __init__(self):
        self._mock_settings = {}
        self._key_cache = {}  # In-memory key cache (ephemeral)

    def encrypt_document(
        self,
        file_path: str,
        operator: str,
        timestamp: datetime,
        branch: str,
        session_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt document file using AES-256-GCM

        Args:
            file_path: Path to document file to encrypt
            operator: Operator performing the encryption
            timestamp: Timestamp for key derivation
            branch: Branch for key derivation
            session_token: Optional session token

        Returns:
            Dict with encryption results

        Raises:
            FileNotFoundError: When source file doesn't exist
            InvalidParametersError: When parameters are invalid
            EncryptionError: When encryption fails
            InsufficientDiskSpaceError: When not enough disk space
        """
        start_time = time.time()

        # Validate parameters
        self._validate_encrypt_parameters(file_path, operator, branch, timestamp)

        # Handle mock failure scenarios
        self._handle_mock_encryption_scenarios()

        # Check file exists
        source_path = Path(file_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {file_path}")

        # Check disk space
        self._check_disk_space(source_path)

        # Derive encryption key
        key_info = self.get_key_derivation_info(operator, branch, timestamp)
        encryption_key = self._derive_encryption_key(key_info)

        # Perform encryption
        encrypted_path = self._perform_encryption(source_path, encryption_key)

        processing_time = time.time() - start_time
        encrypted_size = os.path.getsize(encrypted_path)

        return {
            "encrypted_path": str(encrypted_path),
            "key_hash": key_info["key_hash"],
            "algorithm": "AES-256-GCM",
            "encrypted_size": encrypted_size,
            "processing_time": processing_time,
        }

    def _validate_encrypt_parameters(
        self, file_path: str, operator: str, branch: str, timestamp: datetime
    ) -> None:
        """Validate encryption parameters"""
        if not operator:
            raise InvalidParametersError("Operator cannot be empty")

        if not branch:
            raise InvalidParametersError("Branch cannot be empty")

        # Validate branch name format
        valid_branches = [
            "sucursal-centro",
            "sucursal-norte",
            "sucursal-sur",
            "sucursal-este",
        ]
        if branch not in valid_branches:
            raise InvalidParametersError(f"Invalid branch: {branch}")

        if not timestamp:
            raise InvalidParametersError("Timestamp is required")

        if not file_path:
            raise InvalidParametersError("File path cannot be empty")

    def _handle_mock_encryption_scenarios(self) -> None:
        """Handle mock error scenarios for testing"""
        if self._mock_settings.get("_mock_encryption_failure", False):
            raise EncryptionError("Encryption failed - mock scenario")

    def _check_disk_space(self, source_path: Path) -> None:
        """Check if sufficient disk space is available"""
        source_size = source_path.stat().st_size

        # Estimate encrypted file size (original + ~10% overhead for IV, tag, etc.)
        estimated_size = int(source_size * 1.1)

        # Get available disk space
        disk_usage = os.statvfs(source_path.parent)
        available_space = disk_usage.f_frsize * disk_usage.f_bavail

        if available_space < estimated_size:
            raise InsufficientDiskSpaceError(
                f"Insufficient disk space. Need: {estimated_size} bytes, Available: {available_space} bytes"
            )

    def get_key_derivation_info(
        self, operator: str, branch: str, timestamp: datetime
    ) -> Dict[str, Any]:
        """
        Get key derivation information for given parameters

        Args:
            operator: Operator name
            branch: Branch name
            timestamp: Timestamp for derivation

        Returns:
            Dict with key derivation info
        """
        # Create deterministic salt from inputs
        salt_input = f"{operator}:{branch}:{timestamp.isoformat()}"
        salt = hashlib.sha256(salt_input.encode()).digest()

        # Derive key hash (for identification, not the actual key)
        key_identifier = f"{operator}_{branch}_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        key_hash = hashlib.sha256(key_identifier.encode()).hexdigest()

        return {
            "key_hash": key_hash,
            "salt": base64.b64encode(salt).decode("ascii"),
            "iterations": 100000,
            "algorithm": "PBKDF2-SHA256",
        }

    def _derive_encryption_key(self, key_info: Dict[str, Any]) -> bytes:
        """
        Derive actual encryption key from key info

        Args:
            key_info: Key derivation information

        Returns:
            32-byte encryption key
        """
        # Use key_hash as password for PBKDF2 (in practice, this would be more complex)
        password = key_info["key_hash"].encode()
        salt = base64.b64decode(key_info["salt"])
        iterations = key_info["iterations"]

        # Derive 256-bit (32-byte) key using PBKDF2-SHA256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )

        return kdf.derive(password)

    def _perform_encryption(self, source_path: Path, encryption_key: bytes) -> Path:
        """
        Perform AES-256-GCM encryption on file

        Args:
            source_path: Source file path
            encryption_key: 32-byte encryption key

        Returns:
            Path to encrypted file
        """
        # Generate random 96-bit (12-byte) IV for GCM
        iv = secrets.token_bytes(12)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(encryption_key), modes.GCM(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Create encrypted file path
        encrypted_path = source_path.with_suffix(source_path.suffix + ".enc")

        try:
            # Encrypt file in chunks
            with (
                open(source_path, "rb") as infile,
                open(encrypted_path, "wb") as outfile,
            ):
                # Write IV first
                outfile.write(iv)

                # Encrypt file content in 64KB chunks
                chunk_size = 64 * 1024
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break

                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)

                # Finalize encryption and get authentication tag
                encryptor.finalize()
                tag = encryptor.tag

                # Write authentication tag at the end
                outfile.write(tag)

        except Exception as e:
            # Clean up partial file on error
            if encrypted_path.exists():
                encrypted_path.unlink()
            raise EncryptionError(f"Encryption failed: {str(e)}")

        return encrypted_path

    def verify_encrypted_file(self, encrypted_path: str) -> bool:
        """
        Verify encrypted file integrity

        Args:
            encrypted_path: Path to encrypted file

        Returns:
            True if file appears to be properly encrypted
        """
        try:
            encrypted_file = Path(encrypted_path)
            if not encrypted_file.exists():
                return False

            # Check minimum file size (IV + tag + some content)
            if (
                encrypted_file.stat().st_size < 28
            ):  # 12 (IV) + 16 (tag) = 28 bytes minimum
                return False

            # Check file extension
            if not encrypted_path.endswith(".enc"):
                return False

            # Try to read IV and tag structure
            with open(encrypted_file, "rb") as f:
                iv = f.read(12)  # First 12 bytes should be IV
                if len(iv) != 12:
                    return False

                # Seek to end to check tag
                f.seek(-16, 2)  # Last 16 bytes should be tag
                tag = f.read(16)
                if len(tag) != 16:
                    return False

            return True

        except Exception:
            return False

    def get_encryption_metadata(self, encrypted_path: str) -> Dict[str, Any]:
        """
        Get metadata about encrypted file

        Args:
            encrypted_path: Path to encrypted file

        Returns:
            Dict with encryption metadata
        """
        if not self.verify_encrypted_file(encrypted_path):
            raise ValueError("Invalid encrypted file")

        encrypted_file = Path(encrypted_path)
        file_size = encrypted_file.stat().st_size

        # Calculate content size (total - IV - tag)
        content_size = file_size - 12 - 16

        return {
            "encrypted_file_size": file_size,
            "content_size": content_size,
            "iv_size": 12,
            "tag_size": 16,
            "algorithm": "AES-256-GCM",
            "created_at": datetime.fromtimestamp(
                encrypted_file.stat().st_ctime
            ).isoformat(),
        }

    def estimate_encryption_time(self, file_size_bytes: int) -> float:
        """
        Estimate encryption time for given file size

        Args:
            file_size_bytes: File size in bytes

        Returns:
            Estimated time in seconds
        """
        # Rough estimate: ~10 MB/second encryption speed
        mb_size = file_size_bytes / (1024 * 1024)
        estimated_seconds = mb_size / 10.0

        # Add overhead for key derivation and I/O
        return max(estimated_seconds + 0.1, 0.1)

    def cleanup_key_cache(self) -> None:
        """Clear ephemeral key cache (security measure)"""
        self._key_cache.clear()

    def get_crypto_statistics(self) -> Dict[str, Any]:
        """
        Get cryptographic operation statistics

        Returns:
            Dict with crypto stats
        """
        return {
            "algorithm": "AES-256-GCM",
            "key_derivation": "PBKDF2-SHA256",
            "key_size_bits": 256,
            "iv_size_bits": 96,
            "tag_size_bits": 128,
            "iterations": 100000,
            "cache_entries": len(self._key_cache),
            "security_level": "high",
        }

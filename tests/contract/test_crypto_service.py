"""
Contract tests for Crypto Service
Tests the crypto service API contract according to contracts/crypto_service.yaml

⚠️ TDD CRITICAL: These tests MUST FAIL before implementation exists
"""

import pytest
import tempfile
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from services.crypto_service import CryptoService
from services.crypto_service import (
    EncryptionError, 
    FileNotFoundError as CryptoFileNotFoundError,
    InvalidParametersError,
    KeyDerivationError,
    InsufficientDiskSpaceError
)


class TestCryptoServiceContract:
    """Contract tests for Crypto Service based on OpenAPI spec"""
    
    @pytest.fixture
    def crypto_service(self):
        """Fixture providing crypto service instance"""
        return CryptoService()
    
    @pytest.fixture
    def test_document_file(self):
        """Fixture providing a test document file"""
        with tempfile.NamedTemporaryFile(mode='w+b', suffix='.tiff', delete=False) as f:
            # Write some test content
            test_content = b"MOCK_SCANNED_DOCUMENT_CONTENT" * 100  # ~2.9KB
            f.write(test_content)
            f.flush()
            yield f.name
        # Cleanup
        try:
            os.unlink(f.name)
        except FileNotFoundError:
            pass
    
    def test_encrypt_document_success(self, crypto_service, test_document_file):
        """
        Test POST /crypto/encrypt - Success case
        
        Contract: Should return encrypted_path, key_hash, algorithm, 
        encrypted_size, processing_time when encryption succeeds
        """
        # Arrange
        operator = "admin"
        branch = "sucursal-centro"
        timestamp = datetime.now()
        
        # Act - This MUST FAIL because encrypt_document method doesn't exist yet
        result = crypto_service.encrypt_document(
            file_path=test_document_file,
            operator=operator,
            timestamp=timestamp,
            branch=branch
        )
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        required_fields = ["encrypted_path", "key_hash", "algorithm"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Validate encrypted_path
        encrypted_path = result["encrypted_path"]
        assert isinstance(encrypted_path, str)
        assert len(encrypted_path) > 0
        path_obj = Path(encrypted_path)
        assert path_obj.suffix == ".enc"
        # File should exist after encryption
        assert path_obj.exists()
        
        # Validate key_hash
        key_hash = result["key_hash"]
        assert isinstance(key_hash, str)
        assert len(key_hash) == 64  # SHA-256 hex digest length
        # Should be valid hex
        int(key_hash, 16)  # Will raise if not valid hex
        
        # Validate algorithm
        algorithm = result["algorithm"]
        assert algorithm == "AES-256-GCM"
        
        # Optional fields validation
        if "encrypted_size" in result:
            encrypted_size = result["encrypted_size"]
            assert isinstance(encrypted_size, int)
            assert encrypted_size > 0
            # Encrypted size should be larger than original (due to IV, tag)
            original_size = os.path.getsize(test_document_file)
            assert encrypted_size >= original_size
        
        if "processing_time" in result:
            processing_time = result["processing_time"]
            assert isinstance(processing_time, (int, float))
            assert processing_time > 0
            # Should be reasonable (< 10 seconds for test file)
            assert processing_time < 10.0
    
    def test_encrypt_document_file_not_found_error(self, crypto_service):
        """
        Test POST /crypto/encrypt - File not found error (404)
        
        Contract: Should raise CryptoFileNotFoundError when source file doesn't exist
        """
        # Arrange - Non-existent file
        nonexistent_file = "/path/to/nonexistent/file.tiff"
        operator = "admin"
        branch = "sucursal-centro"
        timestamp = datetime.now()
        
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(CryptoFileNotFoundError) as exc_info:
            crypto_service.encrypt_document(
                file_path=nonexistent_file,
                operator=operator,
                timestamp=timestamp,
                branch=branch
            )
        
        # Validate exception contract
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        
        assert error.error_code == "FILE_NOT_FOUND_ERROR"
        assert "not found" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_encrypt_document_invalid_parameters_error(self, crypto_service, test_document_file):
        """
        Test POST /crypto/encrypt - Invalid parameters error (400)
        
        Contract: Should raise InvalidParametersError for invalid input
        """
        # Test cases for invalid parameters
        invalid_test_cases = [
            # Missing operator
            {"file_path": test_document_file, "timestamp": datetime.now(), "branch": "sucursal-centro"},
            # Empty operator  
            {"file_path": test_document_file, "operator": "", "timestamp": datetime.now(), "branch": "sucursal-centro"},
            # Invalid branch
            {"file_path": test_document_file, "operator": "admin", "timestamp": datetime.now(), "branch": "invalid-branch"},
            # Missing timestamp
            {"file_path": test_document_file, "operator": "admin", "branch": "sucursal-centro"},
        ]
        
        for test_case in invalid_test_cases:
            with pytest.raises(InvalidParametersError) as exc_info:
                crypto_service.encrypt_document(**test_case)
            
            # Validate exception contract
            error = exc_info.value
            assert error.error_code == "INVALID_PARAMETERS"
            assert len(error.message) > 0
            assert isinstance(error.timestamp, datetime)
    
    def test_encrypt_document_encryption_error(self, crypto_service, test_document_file):
        """
        Test POST /crypto/encrypt - Encryption operation failed (500)
        
        Contract: Should raise EncryptionError when crypto operation fails
        """
        # Arrange - Mock encryption failure
        crypto_service._mock_encryption_failure = True
        
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(EncryptionError) as exc_info:
            crypto_service.encrypt_document(
                file_path=test_document_file,
                operator="admin",
                timestamp=datetime.now(),
                branch="sucursal-centro"
            )
        
        # Validate exception contract
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        
        assert error.error_code == "ENCRYPTION_ERROR"
        assert "encryption failed" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_get_key_derivation_info_success(self, crypto_service):
        """
        Test GET /crypto/key-info - Success case
        
        Contract: Should return key_hash, salt, iterations, algorithm
        for key derivation information
        """
        # Arrange
        operator = "admin"
        branch = "sucursal-centro"
        timestamp = datetime.now()
        
        # Act - This MUST FAIL because get_key_derivation_info method doesn't exist yet
        result = crypto_service.get_key_derivation_info(
            operator=operator,
            branch=branch,
            timestamp=timestamp
        )
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        required_fields = ["key_hash", "salt", "iterations", "algorithm"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Validate key_hash
        key_hash = result["key_hash"]
        assert isinstance(key_hash, str)
        assert len(key_hash) == 64  # SHA-256 hex digest
        
        # Validate salt
        salt = result["salt"]
        assert isinstance(salt, str)
        assert len(salt) > 0
        # Should be base64 encoded
        import base64
        base64.b64decode(salt)  # Will raise if not valid base64
        
        # Validate iterations
        iterations = result["iterations"]
        assert isinstance(iterations, int)
        assert iterations >= 100000  # PBKDF2 security minimum
        
        # Validate algorithm
        algorithm = result["algorithm"]
        assert algorithm == "PBKDF2-SHA256"
    
    def test_key_derivation_consistency(self, crypto_service):
        """
        Test that key derivation is deterministic for same inputs
        
        Contract: Same operator+branch+timestamp should produce same key_hash
        """
        # Arrange
        operator = "admin"
        branch = "sucursal-centro"
        timestamp = datetime.now()
        
        # Act - Get key info twice with same parameters
        result1 = crypto_service.get_key_derivation_info(operator, branch, timestamp)
        result2 = crypto_service.get_key_derivation_info(operator, branch, timestamp)
        
        # Assert - Should be deterministic
        assert result1["key_hash"] == result2["key_hash"]
        assert result1["salt"] == result2["salt"]
        assert result1["iterations"] == result2["iterations"]
    
    def test_key_derivation_uniqueness(self, crypto_service):
        """
        Test that different inputs produce different keys
        
        Contract: Different operator/branch/timestamp should produce different key_hash
        """
        base_timestamp = datetime.now()
        
        # Different test scenarios
        scenarios = [
            {"operator": "admin", "branch": "sucursal-centro", "timestamp": base_timestamp},
            {"operator": "operator2", "branch": "sucursal-centro", "timestamp": base_timestamp},
            {"operator": "admin", "branch": "sucursal-norte", "timestamp": base_timestamp},
            {"operator": "admin", "branch": "sucursal-centro", "timestamp": datetime(2023, 1, 1)},
        ]
        
        key_hashes = []
        for scenario in scenarios:
            result = crypto_service.get_key_derivation_info(**scenario)
            key_hashes.append(result["key_hash"])
        
        # All key hashes should be different
        assert len(set(key_hashes)) == len(key_hashes), "Key derivation should produce unique keys for different inputs"


class TestCryptoServiceContractValidation:
    """Additional contract validation tests"""
    
    def test_crypto_service_has_required_methods(self):
        """
        Validate that CryptoService implements required contract methods
        
        This MUST FAIL because CryptoService class doesn't exist yet
        """
        # This will fail with ImportError - expected in RED phase
        crypto_service = CryptoService()
        
        # Validate required methods exist
        assert hasattr(crypto_service, 'encrypt_document')
        assert callable(crypto_service.encrypt_document)
        
        assert hasattr(crypto_service, 'get_key_derivation_info')
        assert callable(crypto_service.get_key_derivation_info)
    
    def test_crypto_exceptions_exist(self):
        """
        Validate that required exception classes exist
        
        This MUST FAIL because exception classes don't exist yet
        """
        # These imports will fail - expected in RED phase
        from services.crypto_service import (
            EncryptionError, 
            CryptoFileNotFoundError,
            InvalidParametersError,
            KeyDerivationError
        )
        
        # Validate exception hierarchy
        for exc_class in [EncryptionError, CryptoFileNotFoundError, InvalidParametersError, KeyDerivationError]:
            assert issubclass(exc_class, Exception)
            
            # Validate exceptions have required attributes
            error = exc_class("test message")
            assert hasattr(error, 'error_code')
            assert hasattr(error, 'message')
            assert hasattr(error, 'timestamp')
    
    def test_encryption_output_format(self, tmp_path):
        """
        Test that encryption produces valid .enc files
        
        Contract: encrypted_path should point to valid encrypted file
        """
        crypto_service = CryptoService()
        
        # Create test file
        test_file = tmp_path / "test_document.tiff"
        test_content = b"TEST_DOCUMENT_CONTENT"
        test_file.write_bytes(test_content)
        
        # Encrypt
        result = crypto_service.encrypt_document(
            file_path=str(test_file),
            operator="admin",
            timestamp=datetime.now(),
            branch="sucursal-centro"
        )
        
        # Validate encrypted file
        encrypted_path = Path(result["encrypted_path"])
        assert encrypted_path.exists()
        assert encrypted_path.suffix == ".enc"
        
        # Encrypted content should be different from original
        encrypted_content = encrypted_path.read_bytes()
        assert encrypted_content != test_content
        assert len(encrypted_content) > len(test_content)  # Due to IV, tag, etc.


class TestCryptoServiceSecurityContract:
    """Security-focused contract tests"""
    
    def test_key_never_returned_in_plaintext(self, crypto_service):
        """
        Security Contract: Actual encryption keys should never be returned
        
        Only key_hash should be provided, never the actual key
        """
        result = crypto_service.get_key_derivation_info(
            operator="admin",
            branch="sucursal-centro", 
            timestamp=datetime.now()
        )
        
        # Should have key_hash but not actual key
        assert "key_hash" in result
        assert "key" not in result
        assert "encryption_key" not in result
        assert "derived_key" not in result
    
    def test_no_sensitive_data_in_errors(self, crypto_service):
        """
        Security Contract: Exception messages should not contain sensitive data
        
        Error messages should not leak keys, file contents, etc.
        """
        try:
            crypto_service.encrypt_document(
                file_path="/nonexistent/file.tiff",
                operator="admin",
                timestamp=datetime.now(),
                branch="sucursal-centro"
            )
        except Exception as e:
            error_message = str(e).lower()
            
            # Should not contain sensitive keywords
            sensitive_keywords = ["key", "password", "secret", "token", "hash"]
            for keyword in sensitive_keywords:
                assert keyword not in error_message, f"Error message should not contain sensitive keyword: {keyword}"
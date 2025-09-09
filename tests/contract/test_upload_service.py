"""
Contract tests for Upload Service
Tests the upload service API contract according to contracts/upload_service.yaml

⚠️ TDD CRITICAL: These tests MUST FAIL before implementation exists
"""

import pytest
import tempfile
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from services.upload_service import UploadService
from services.upload_service import (
    NetworkError,
    S3Error,
    FileNotFoundError as UploadFileNotFoundError,
    InvalidS3KeyError,
    AccessDeniedError,
    BucketNotFoundError,
    MaxRetriesExceededError,
    InvalidMetadataError
)


class TestUploadServiceContract:
    """Contract tests for Upload Service based on OpenAPI spec"""
    
    @pytest.fixture
    def upload_service(self):
        """Fixture providing upload service instance"""
        return UploadService()
    
    @pytest.fixture
    def test_encrypted_file(self):
        """Fixture providing a test encrypted file"""
        with tempfile.NamedTemporaryFile(mode='w+b', suffix='.enc', delete=False) as f:
            # Write some encrypted-like content
            test_content = b"MOCK_ENCRYPTED_CONTENT" * 50  # ~1.1KB
            f.write(test_content)
            f.flush()
            yield f.name
        # Cleanup
        try:
            os.unlink(f.name)
        except FileNotFoundError:
            pass
    
    @pytest.fixture
    def valid_s3_key(self):
        """Fixture providing a valid S3 key following naming pattern"""
        timestamp = int(datetime.now().timestamp())
        return f"2025-09-08/sucursal-centro/admin/pagare-{timestamp}.enc"
    
    @pytest.fixture
    def valid_metadata(self):
        """Fixture providing valid metadata for S3 upload"""
        return {
            "sucursal": "sucursal-centro",
            "operador": "admin", 
            "created_at": datetime.now().isoformat(),
            "document_type": "pagare",
            "encryption_algorithm": "AES-256-GCM"
        }
    
    def test_upload_to_s3_success(self, upload_service, test_encrypted_file, valid_s3_key, valid_metadata):
        """
        Test POST /upload/s3 - Success case
        
        Contract: Should return success=True, upload_time, s3_url, etag, file_size, upload_duration
        when upload succeeds
        """
        # Act - This MUST FAIL because upload_to_s3 method doesn't exist yet
        result = upload_service.upload_to_s3(
            encrypted_path=test_encrypted_file,
            s3_key=valid_s3_key,
            metadata=valid_metadata
        )
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        required_fields = ["success", "upload_time", "s3_url", "etag"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Validate success
        success = result["success"]
        assert success is True
        
        # Validate upload_time
        upload_time = result["upload_time"]
        assert isinstance(upload_time, datetime)
        # Should be recent (within last minute)
        now = datetime.now()
        time_diff = now - upload_time
        assert time_diff.total_seconds() < 60
        
        # Validate s3_url
        s3_url = result["s3_url"]
        assert isinstance(s3_url, str)
        assert s3_url.startswith("s3://")
        assert valid_s3_key in s3_url
        
        # Validate etag
        etag = result["etag"]
        assert isinstance(etag, str)
        assert len(etag) >= 32  # MD5 hash minimum length
        
        # Optional fields validation
        if "file_size" in result:
            file_size = result["file_size"]
            assert isinstance(file_size, int)
            assert file_size > 0
            # Should match actual file size
            actual_size = os.path.getsize(test_encrypted_file)
            assert file_size == actual_size
        
        if "upload_duration" in result:
            upload_duration = result["upload_duration"]
            assert isinstance(upload_duration, (int, float))
            assert upload_duration > 0
            # Should be reasonable (< 30 seconds for test file)
            assert upload_duration < 30.0
    
    def test_upload_to_s3_file_not_found_error(self, upload_service, valid_s3_key, valid_metadata):
        """
        Test POST /upload/s3 - File not found error (404)
        
        Contract: Should raise UploadFileNotFoundError when encrypted file doesn't exist
        """
        # Arrange - Non-existent file
        nonexistent_file = "/path/to/nonexistent/file.enc"
        
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(UploadFileNotFoundError) as exc_info:
            upload_service.upload_to_s3(
                encrypted_path=nonexistent_file,
                s3_key=valid_s3_key,
                metadata=valid_metadata
            )
        
        # Validate exception contract
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        
        assert error.error_code == "FILE_NOT_FOUND_ERROR"
        assert "not found" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_upload_to_s3_invalid_s3_key_error(self, upload_service, test_encrypted_file, valid_metadata):
        """
        Test POST /upload/s3 - Invalid S3 key error (400)
        
        Contract: Should raise InvalidS3KeyError for malformed S3 keys
        """
        # Test cases for invalid S3 keys
        invalid_s3_keys = [
            "invalid-key-format",
            "2025-13-40/sucursal-centro/admin/pagare-123.enc",  # Invalid date
            "2025-09-08/invalid-branch/admin/pagare-123.enc",   # Invalid branch
            "2025-09-08/sucursal-centro/admin/invalid-prefix-123.enc",  # Wrong prefix
            "2025-09-08/sucursal-centro/admin/pagare-123.txt",  # Wrong extension
        ]
        
        for invalid_key in invalid_s3_keys:
            with pytest.raises(InvalidS3KeyError) as exc_info:
                upload_service.upload_to_s3(
                    encrypted_path=test_encrypted_file,
                    s3_key=invalid_key,
                    metadata=valid_metadata
                )
            
            # Validate exception contract
            error = exc_info.value
            assert error.error_code == "INVALID_S3_KEY"
            assert "naming pattern" in error.message.lower() or "invalid" in error.message.lower()
            assert isinstance(error.timestamp, datetime)
    
    def test_upload_to_s3_network_error_retryable(self, upload_service, test_encrypted_file, valid_s3_key, valid_metadata):
        """
        Test POST /upload/s3 - Network error (503 retryable)
        
        Contract: Should raise NetworkError with retry_after for retryable network issues
        """
        # Arrange - Mock network failure
        upload_service._mock_network_failure = True
        
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(NetworkError) as exc_info:
            upload_service.upload_to_s3(
                encrypted_path=test_encrypted_file,
                s3_key=valid_s3_key,
                metadata=valid_metadata
            )
        
        # Validate exception contract
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        assert hasattr(error, 'retry_after')
        
        assert error.error_code == "NETWORK_ERROR"
        assert "network" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
        assert isinstance(error.retry_after, int)
        assert error.retry_after > 0
    
    def test_upload_to_s3_s3_service_error(self, upload_service, test_encrypted_file, valid_s3_key, valid_metadata):
        """
        Test POST /upload/s3 - S3 service error (500)
        
        Contract: Should raise S3Error for non-retryable S3 service issues
        """
        # Arrange - Mock S3 service failure
        upload_service._mock_s3_failure = True
        
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(S3Error) as exc_info:
            upload_service.upload_to_s3(
                encrypted_path=test_encrypted_file,
                s3_key=valid_s3_key,
                metadata=valid_metadata
            )
        
        # Validate exception contract
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        
        assert error.error_code == "S3_ERROR"
        assert "s3" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_retry_upload_success(self, upload_service, test_encrypted_file, valid_s3_key, valid_metadata):
        """
        Test POST /upload/retry - Success case
        
        Contract: Should return success=True, upload_time, retry_attempt when retry succeeds
        """
        # Act - This MUST FAIL because retry_upload method doesn't exist yet
        result = upload_service.retry_upload(
            encrypted_path=test_encrypted_file,
            s3_key=valid_s3_key,
            metadata=valid_metadata,
            previous_attempt=1
        )
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        required_fields = ["success", "upload_time", "retry_attempt"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Validate success
        assert result["success"] is True
        
        # Validate upload_time
        upload_time = result["upload_time"]
        assert isinstance(upload_time, datetime)
        
        # Validate retry_attempt
        retry_attempt = result["retry_attempt"]
        assert isinstance(retry_attempt, int)
        assert retry_attempt > 0
        assert retry_attempt <= 1  # Max 1 retry per spec
    
    def test_retry_upload_max_retries_exceeded(self, upload_service, test_encrypted_file, valid_s3_key, valid_metadata):
        """
        Test POST /upload/retry - Max retries exceeded (429)
        
        Contract: Should raise MaxRetriesExceededError when previous_attempt >= 1
        """
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(MaxRetriesExceededError) as exc_info:
            upload_service.retry_upload(
                encrypted_path=test_encrypted_file,
                s3_key=valid_s3_key,
                metadata=valid_metadata,
                previous_attempt=2  # Exceeds max of 1
            )
        
        # Validate exception contract
        error = exc_info.value
        assert error.error_code == "MAX_RETRIES_EXCEEDED"
        assert "maximum retry" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_validate_s3_key_valid(self, upload_service, valid_s3_key):
        """
        Test GET /upload/validate - Valid S3 key
        
        Contract: Should return valid=True, pattern, parsed_components for valid keys
        """
        # Act - This MUST FAIL because validate_s3_key method doesn't exist yet
        result = upload_service.validate_s3_key(valid_s3_key)
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        required_fields = ["valid", "pattern"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Validate valid flag
        assert result["valid"] is True
        
        # Validate pattern
        pattern = result["pattern"]
        assert isinstance(pattern, str)
        assert "YYYY-MM-DD/sucursal/operador/pagare-<epoch>.enc" in pattern
        
        # Validate parsed_components (if present)
        if "parsed_components" in result:
            components = result["parsed_components"]
            assert isinstance(components, dict)
            
            expected_components = ["date", "branch", "operator", "timestamp"]
            for component in expected_components:
                assert component in components
            
            # Validate component values
            assert components["date"] == "2025-09-08"
            assert components["branch"] == "sucursal-centro"
            assert components["operator"] == "admin"
            assert isinstance(components["timestamp"], int)
    
    def test_validate_s3_key_invalid(self, upload_service):
        """
        Test GET /upload/validate - Invalid S3 key
        
        Contract: Should return valid=False, pattern for invalid keys
        """
        invalid_key = "invalid-key-format"
        
        # Act
        result = upload_service.validate_s3_key(invalid_key)
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        assert result["valid"] is False
        assert "pattern" in result
        
        # Should not have parsed_components for invalid keys
        assert "parsed_components" not in result or result["parsed_components"] is None


class TestUploadServiceContractValidation:
    """Additional contract validation tests"""
    
    def test_upload_service_has_required_methods(self):
        """
        Validate that UploadService implements required contract methods
        
        This MUST FAIL because UploadService class doesn't exist yet
        """
        # This will fail with ImportError - expected in RED phase
        upload_service = UploadService()
        
        # Validate required methods exist
        assert hasattr(upload_service, 'upload_to_s3')
        assert callable(upload_service.upload_to_s3)
        
        assert hasattr(upload_service, 'retry_upload')
        assert callable(upload_service.retry_upload)
        
        assert hasattr(upload_service, 'validate_s3_key')
        assert callable(upload_service.validate_s3_key)
    
    def test_upload_exceptions_exist(self):
        """
        Validate that required exception classes exist
        
        This MUST FAIL because exception classes don't exist yet
        """
        # These imports will fail - expected in RED phase
        from services.upload_service import (
            NetworkError,
            S3Error,
            UploadFileNotFoundError,
            InvalidS3KeyError,
            MaxRetriesExceededError
        )
        
        # Validate exception hierarchy
        exception_classes = [NetworkError, S3Error, UploadFileNotFoundError, InvalidS3KeyError, MaxRetriesExceededError]
        for exc_class in exception_classes:
            assert issubclass(exc_class, Exception)
            
            # Validate exceptions have required attributes
            error = exc_class("test message")
            assert hasattr(error, 'error_code')
            assert hasattr(error, 'message')
            assert hasattr(error, 'timestamp')
    
    def test_s3_key_pattern_compliance(self, upload_service):
        """
        Test S3 key pattern compliance with specification
        
        Contract: All valid keys must follow YYYY-MM-DD/sucursal/operador/pagare-<epoch>.enc
        """
        # Valid test cases
        valid_keys = [
            "2025-09-08/sucursal-centro/admin/pagare-1725811822.enc",
            "2024-12-31/sucursal-norte/operator123/pagare-1703980800.enc", 
            "2025-01-01/sucursal-sur/user_test/pagare-1704067200.enc"
        ]
        
        for valid_key in valid_keys:
            result = upload_service.validate_s3_key(valid_key)
            assert result["valid"] is True, f"Key should be valid: {valid_key}"
        
        # Invalid test cases
        invalid_keys = [
            "invalid-format",
            "2025/09/08/sucursal-centro/admin/pagare-123.enc",  # Wrong date separator
            "2025-09-08/invalid_branch/admin/pagare-123.enc",   # Invalid branch
            "2025-09-08/sucursal-centro/admin/document-123.enc", # Wrong prefix
            "2025-09-08/sucursal-centro/admin/pagare-123.pdf"   # Wrong extension
        ]
        
        for invalid_key in invalid_keys:
            result = upload_service.validate_s3_key(invalid_key)
            assert result["valid"] is False, f"Key should be invalid: {invalid_key}"


class TestUploadServiceMetadataContract:
    """Contract tests for metadata handling"""
    
    def test_metadata_validation_complete(self, upload_service, test_encrypted_file, valid_s3_key):
        """
        Test that metadata validation requires all mandatory fields
        
        Contract: sucursal, operador, created_at are required
        """
        # Test missing required fields
        incomplete_metadata_cases = [
            {},  # Empty metadata
            {"sucursal": "sucursal-centro"},  # Missing operador, created_at
            {"operador": "admin"},  # Missing sucursal, created_at  
            {"created_at": datetime.now().isoformat()},  # Missing sucursal, operador
            {"sucursal": "sucursal-centro", "operador": "admin"},  # Missing created_at
        ]
        
        for incomplete_metadata in incomplete_metadata_cases:
            with pytest.raises(InvalidMetadataError) as exc_info:
                upload_service.upload_to_s3(
                    encrypted_path=test_encrypted_file,
                    s3_key=valid_s3_key,
                    metadata=incomplete_metadata
                )
            
            # Validate exception contract
            error = exc_info.value
            assert error.error_code == "INVALID_METADATA"
            assert "required" in error.message.lower()
    
    def test_metadata_format_validation(self, upload_service, test_encrypted_file, valid_s3_key):
        """
        Test metadata format validation
        
        Contract: created_at should be ISO-8601 format
        """
        # Invalid created_at formats
        invalid_metadata_cases = [
            {
                "sucursal": "sucursal-centro",
                "operador": "admin", 
                "created_at": "invalid-date-format"
            },
            {
                "sucursal": "sucursal-centro",
                "operador": "admin",
                "created_at": "2025/09/08 14:30:22"  # Wrong format
            }
        ]
        
        for invalid_metadata in invalid_metadata_cases:
            with pytest.raises(InvalidMetadataError) as exc_info:
                upload_service.upload_to_s3(
                    encrypted_path=test_encrypted_file,
                    s3_key=valid_s3_key,
                    metadata=invalid_metadata
                )
            
            # Validate exception contract
            error = exc_info.value
            assert error.error_code == "INVALID_METADATA"
            assert "format" in error.message.lower() or "iso" in error.message.lower()


class TestUploadServiceRetryContract:
    """Contract tests for retry logic"""
    
    def test_retry_logic_limits(self, upload_service, test_encrypted_file, valid_s3_key, valid_metadata):
        """
        Test retry logic follows specification limits
        
        Contract: Maximum 1 retry attempt allowed per document
        """
        # Test valid retry attempts (0 -> 1)
        result = upload_service.retry_upload(
            encrypted_path=test_encrypted_file,
            s3_key=valid_s3_key,
            metadata=valid_metadata,
            previous_attempt=1  # First retry
        )
        
        assert result["retry_attempt"] == 1
        
        # Test exceeding retry limit
        with pytest.raises(MaxRetriesExceededError):
            upload_service.retry_upload(
                encrypted_path=test_encrypted_file,
                s3_key=valid_s3_key,
                metadata=valid_metadata,
                previous_attempt=2  # Exceeds limit
            )
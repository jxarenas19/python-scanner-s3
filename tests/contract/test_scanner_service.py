"""
Contract tests for Scanner Service
Tests the scanner service API contract according to contracts/scanner_service.yaml

⚠️ TDD CRITICAL: These tests MUST FAIL before implementation exists
"""

import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from services.scanner_service import ScannerService
from services.scanner_service import NoScannerError, ScanFailedError


class TestScannerServiceContract:
    """Contract tests for Scanner Service based on OpenAPI spec"""
    
    @pytest.fixture
    def scanner_service(self):
        """Fixture providing scanner service instance"""
        return ScannerService()
    
    def test_check_scanner_availability_success(self, scanner_service):
        """
        Test GET /scanner/availability - Success case
        
        Contract: Should return available=True, scanner_name, driver_version
        when scanner hardware is detected
        """
        # Act - This MUST FAIL because ScannerService doesn't exist yet
        result = scanner_service.check_scanner_availability()
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        assert "available" in result
        assert "scanner_name" in result
        assert isinstance(result["available"], bool)
        assert isinstance(result["scanner_name"], str)
        
        # When scanner is available
        if result["available"]:
            assert len(result["scanner_name"]) > 0
            assert "driver_version" in result
            assert isinstance(result["driver_version"], str)
    
    def test_check_scanner_availability_no_scanner(self, scanner_service):
        """
        Test GET /scanner/availability - No scanner case
        
        Contract: Should return available=False when no scanner detected
        """
        # Arrange - Mock no scanner scenario
        scanner_service._mock_no_scanner = True
        
        # Act - This MUST FAIL because ScannerService doesn't exist yet
        result = scanner_service.check_scanner_availability()
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        assert result["available"] is False
        assert "scanner_name" in result
        # Scanner name should be empty or indicate no scanner
        assert result["scanner_name"] in ["", "No scanner detected"]
    
    def test_scan_document_success(self, scanner_service):
        """
        Test POST /scanner/scan - Success case
        
        Contract: Should return document_path, timestamp, file_size, format
        when document is successfully scanned
        """
        # Act - This MUST FAIL because scan_document method doesn't exist yet
        result = scanner_service.scan_document()
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        assert "document_path" in result
        assert "timestamp" in result
        assert "file_size" in result  
        assert "format" in result
        
        # Validate document_path
        document_path = result["document_path"]
        assert isinstance(document_path, str)
        assert len(document_path) > 0
        # Should be a valid file path
        path_obj = Path(document_path)
        assert path_obj.suffix in [".tiff", ".png", ".jpeg", ".pdf"]
        
        # Validate timestamp
        timestamp = result["timestamp"]
        assert isinstance(timestamp, datetime)
        # Should be recent (within last minute)
        now = datetime.now()
        time_diff = now - timestamp
        assert time_diff.total_seconds() < 60
        
        # Validate file_size
        file_size = result["file_size"]
        assert isinstance(file_size, int)
        assert file_size > 0
        
        # Validate format
        format_val = result["format"]
        assert format_val in ["TIFF", "PNG", "JPEG", "PDF"]
    
    def test_scan_document_no_scanner_error(self, scanner_service):
        """
        Test POST /scanner/scan - No scanner error (404)
        
        Contract: Should raise NoScannerError when no scanner is available
        """
        # Arrange - Mock no scanner scenario
        scanner_service._mock_no_scanner = True
        
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(NoScannerError) as exc_info:
            scanner_service.scan_document()
        
        # Validate exception message
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message') 
        assert hasattr(error, 'timestamp')
        
        assert error.error_code == "NO_SCANNER_ERROR"
        assert "no scanner device detected" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_scan_document_scan_failed_error(self, scanner_service):
        """
        Test POST /scanner/scan - Scan failed error (500)
        
        Contract: Should raise ScanFailedError when scan operation fails
        """
        # Arrange - Mock scan failure scenario  
        scanner_service._mock_scan_failure = True
        
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(ScanFailedError) as exc_info:
            scanner_service.scan_document()
        
        # Validate exception message
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        
        assert error.error_code == "SCAN_FAILED_ERROR"
        assert "scan failed" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_scan_document_device_busy_error(self, scanner_service):
        """
        Test device busy scenario
        
        Contract: Should handle device busy appropriately
        """
        # Arrange - Mock device busy scenario
        scanner_service._mock_device_busy = True
        
        # Act & Assert - This should fail gracefully or retry
        # Implementation detail: may raise exception or return error status
        try:
            result = scanner_service.scan_document()
            # If returns result, should indicate busy status
            if isinstance(result, dict) and "error" in result:
                assert "busy" in result["error"].lower()
        except Exception as e:
            # If raises exception, should be appropriate type
            assert hasattr(e, 'error_code')
            assert "DEVICE_BUSY" in str(e.error_code)


class TestScannerServiceContractValidation:
    """Additional contract validation tests"""
    
    def test_scanner_service_has_required_methods(self):
        """
        Validate that ScannerService implements required contract methods
        
        This MUST FAIL because ScannerService class doesn't exist yet
        """
        # This will fail with ImportError - expected in RED phase
        scanner_service = ScannerService()
        
        # Validate required methods exist
        assert hasattr(scanner_service, 'check_scanner_availability')
        assert callable(scanner_service.check_scanner_availability)
        
        assert hasattr(scanner_service, 'scan_document') 
        assert callable(scanner_service.scan_document)
    
    def test_scanner_exceptions_exist(self):
        """
        Validate that required exception classes exist
        
        This MUST FAIL because exception classes don't exist yet
        """
        # These imports will fail - expected in RED phase
        from services.scanner_service import NoScannerError, ScanFailedError
        
        # Validate exception hierarchy
        assert issubclass(NoScannerError, Exception)
        assert issubclass(ScanFailedError, Exception)
        
        # Validate exceptions have required attributes
        error = NoScannerError("test message")
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')


# Integration-style contract tests
class TestScannerServiceIntegration:
    """Integration tests validating full scanner service workflow"""
    
    def test_availability_check_before_scan_workflow(self):
        """
        Test the expected workflow: check availability then scan
        
        This MUST FAIL because ScannerService doesn't exist yet
        """
        scanner_service = ScannerService()
        
        # Step 1: Check availability
        availability = scanner_service.check_scanner_availability()
        
        if availability["available"]:
            # Step 2: If available, scanning should work
            scan_result = scanner_service.scan_document()
            assert scan_result is not None
            assert "document_path" in scan_result
        else:
            # Step 2: If not available, scanning should fail
            with pytest.raises(NoScannerError):
                scanner_service.scan_document()
    
    def test_scanner_service_error_format_consistency(self):
        """
        Test that all errors follow consistent format across the service
        
        This validates the ErrorResponse schema from the OpenAPI contract
        """
        scanner_service = ScannerService()
        
        # Force different error scenarios and validate format consistency
        test_scenarios = [
            ("no_scanner", NoScannerError),
            ("scan_failed", ScanFailedError)
        ]
        
        for scenario, expected_error in test_scenarios:
            setattr(scanner_service, f"_mock_{scenario}", True)
            
            try:
                scanner_service.scan_document()
                pytest.fail(f"Expected {expected_error.__name__} for scenario {scenario}")
            except expected_error as e:
                # Validate consistent error format
                assert hasattr(e, 'error_code')
                assert hasattr(e, 'message')  
                assert hasattr(e, 'timestamp')
                assert isinstance(e.message, str)
                assert len(e.message) > 0
                assert isinstance(e.timestamp, datetime)
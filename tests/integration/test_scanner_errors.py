"""
Integration tests for Scanner Errors and Recovery
Tests scanner hardware failures, device busy scenarios, and recovery mechanisms

⚠️ TDD CRITICAL: These tests MUST FAIL before implementation exists
"""

import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from pathlib import Path
import tempfile
import threading

from services.scanner_service import ScannerService
from services.scanner_service import (
    NoScannerError,
    ScanFailedError,
    DeviceBusyError,
    ScannerTimeoutError,
    HardwareError
)


class TestScannerErrorRecovery:
    """Integration tests for scanner error scenarios and recovery"""
    
    @pytest.fixture
    def scanner_service(self):
        """Fixture providing scanner service instance"""
        return ScannerService()
    
    def test_scanner_disconnection_during_scan(self, scanner_service):
        """
        Test scanner disconnection during active scan operation
        
        Contract: Should detect disconnection and provide recovery options
        """
        # Arrange - Mock scanner disconnection mid-scan
        scanner_service._mock_disconnect_during_scan = True
        
        # Act & Assert - This MUST FAIL because scan_document doesn't exist
        with pytest.raises(HardwareError) as exc_info:
            scanner_service.scan_document()
        
        # Validate exception contract
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        assert hasattr(error, 'recovery_suggestion')
        
        assert error.error_code == "SCANNER_DISCONNECTED"
        assert "disconnected" in error.message.lower()
        assert "reconnect" in error.recovery_suggestion.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_device_busy_with_automatic_retry(self, scanner_service):
        """
        Test device busy scenario with automatic retry mechanism
        
        Contract: Should retry up to 3 times with backoff when device is busy
        """
        # Arrange - Mock device busy for first 2 attempts, then success
        scanner_service._mock_device_busy_attempts = 2
        
        start_time = time.time()
        
        # Act - Should eventually succeed after retries
        result = scanner_service.scan_document()
        
        elapsed_time = time.time() - start_time
        
        # Assert - Should succeed with retry info
        assert isinstance(result, dict)
        assert "document_path" in result
        assert "retry_info" in result
        
        retry_info = result["retry_info"]
        assert retry_info["total_attempts"] == 3
        assert retry_info["device_busy_retries"] == 2
        
        # Should have taken time for retries (1s + 2s backoff)
        assert elapsed_time >= 2.5, f"Expected backoff delays, took {elapsed_time}s"
    
    def test_device_busy_exhausted_retries(self, scanner_service):
        """
        Test device busy with exhausted retry attempts
        
        Contract: Should fail with DeviceBusyError after 3 retry attempts
        """
        # Arrange - Mock persistent device busy
        scanner_service._mock_device_always_busy = True
        
        start_time = time.time()
        
        # Act & Assert - Should fail after retries
        with pytest.raises(DeviceBusyError) as exc_info:
            scanner_service.scan_document()
        
        elapsed_time = time.time() - start_time
        
        # Should have attempted retries (3 attempts with 1s, 2s, 4s backoff)
        assert elapsed_time >= 6.5, f"Expected full retry sequence, took {elapsed_time}s"
        
        # Validate exception
        error = exc_info.value
        assert error.error_code == "DEVICE_BUSY_ERROR"
        assert hasattr(error, 'retry_count')
        assert error.retry_count == 3
        assert "try again later" in error.message.lower()
    
    def test_scanner_timeout_with_progressive_timeout(self, scanner_service):
        """
        Test scanner timeout with progressive timeout extension
        
        Contract: Should extend timeout progressively (30s, 60s, 90s)
        """
        # Arrange - Mock scanner timeout scenarios
        scanner_service._mock_timeout_pattern = [True, True, False]  # Timeout, timeout, success
        
        start_time = time.time()
        
        # Act - Should eventually succeed with extended timeout
        result = scanner_service.scan_document()
        
        # Assert - Should succeed with timeout info
        assert isinstance(result, dict)
        assert "document_path" in result
        assert "timeout_extensions" in result
        
        # Should have used progressive timeouts
        timeout_extensions = result["timeout_extensions"]
        assert len(timeout_extensions) == 2
        assert timeout_extensions[0] == 60  # Extended to 60s on first retry
        assert timeout_extensions[1] == 90  # Extended to 90s on second retry
    
    def test_scanner_hardware_malfunction_detection(self, scanner_service):
        """
        Test detection of scanner hardware malfunction
        
        Contract: Should differentiate between temporary issues and hardware failure
        """
        # Arrange - Mock hardware malfunction indicators
        scanner_service._mock_hardware_malfunction = {
            "lamp_failure": True,
            "sensor_error": True,
            "calibration_failed": True
        }
        
        # Act & Assert - Should detect hardware issues
        with pytest.raises(HardwareError) as exc_info:
            scanner_service.scan_document()
        
        error = exc_info.value
        assert error.error_code == "HARDWARE_MALFUNCTION"
        assert hasattr(error, 'hardware_details')
        
        details = error.hardware_details
        assert "lamp_failure" in details
        assert "sensor_error" in details
        assert "calibration_failed" in details
        assert details["lamp_failure"] is True
    
    def test_scanner_paper_jam_recovery(self, scanner_service):
        """
        Test paper jam detection and recovery guidance
        
        Contract: Should detect paper jams and provide clear recovery instructions
        """
        # Arrange - Mock paper jam scenario
        scanner_service._mock_paper_jam = True
        
        # Act & Assert
        with pytest.raises(HardwareError) as exc_info:
            scanner_service.scan_document()
        
        error = exc_info.value
        assert error.error_code == "PAPER_JAM_ERROR"
        assert hasattr(error, 'recovery_instructions')
        
        instructions = error.recovery_instructions
        assert isinstance(instructions, list)
        assert len(instructions) > 0
        assert any("remove" in step.lower() for step in instructions)
        assert any("paper" in step.lower() for step in instructions)
    
    def test_concurrent_scan_attempt_rejection(self, scanner_service):
        """
        Test rejection of concurrent scan attempts
        
        Contract: Should reject new scan attempts while one is in progress
        """
        # Arrange - Mock long-running scan
        scanner_service._mock_long_scan_duration = 5  # 5 seconds
        
        # Start first scan in background thread
        first_scan_result = [None]
        first_scan_error = [None]
        
        def first_scan():
            try:
                result = scanner_service.scan_document()
                first_scan_result[0] = result
            except Exception as e:
                first_scan_error[0] = e
        
        scan_thread = threading.Thread(target=first_scan)
        scan_thread.start()
        
        # Wait a moment for first scan to start
        time.sleep(0.5)
        
        # Act - Attempt second concurrent scan
        with pytest.raises(DeviceBusyError) as exc_info:
            scanner_service.scan_document()
        
        # Wait for first scan to complete
        scan_thread.join(timeout=10)
        
        # Assert - Second scan should be rejected
        error = exc_info.value
        assert error.error_code == "DEVICE_BUSY_ERROR"
        assert "scan in progress" in error.message.lower()
        
        # First scan should have succeeded
        assert first_scan_result[0] is not None
        assert "document_path" in first_scan_result[0]


class TestScannerRecoveryWorkflows:
    """Integration tests for scanner recovery workflows"""
    
    @pytest.fixture
    def scanner_service(self):
        return ScannerService()
    
    def test_scanner_reconnection_workflow(self, scanner_service):
        """
        Test complete scanner reconnection workflow
        
        Contract: Should guide user through reconnection process
        """
        # Arrange - Mock disconnected scanner
        scanner_service._mock_disconnected = True
        
        # Act - Check availability (should show disconnected)
        availability = scanner_service.check_scanner_availability()
        
        # Assert - Should indicate disconnection
        assert availability["available"] is False
        assert availability["scanner_name"] == "No scanner detected"
        assert "reconnection_steps" in availability
        
        # Mock user following reconnection steps
        scanner_service._mock_reconnection_successful = True
        
        # Re-check availability
        new_availability = scanner_service.check_scanner_availability()
        
        # Should now be available
        assert new_availability["available"] is True
        assert len(new_availability["scanner_name"]) > 0
    
    def test_scanner_calibration_recovery(self, scanner_service):
        """
        Test scanner calibration failure and recovery
        
        Contract: Should detect calibration issues and guide recalibration
        """
        # Arrange - Mock calibration failure
        scanner_service._mock_calibration_failed = True
        
        # Act - Attempt scan with calibration issue
        with pytest.raises(HardwareError) as exc_info:
            scanner_service.scan_document()
        
        error = exc_info.value
        assert error.error_code == "CALIBRATION_ERROR"
        assert hasattr(error, 'calibration_steps')
        
        # Simulate recalibration
        calibration_result = scanner_service.recalibrate_scanner()
        
        # Assert - Should provide calibration guidance
        assert isinstance(calibration_result, dict)
        assert "calibration_successful" in calibration_result
        assert "calibration_data" in calibration_result
    
    def test_driver_update_detection(self, scanner_service):
        """
        Test detection of outdated scanner drivers
        
        Contract: Should detect when scanner drivers need updating
        """
        # Arrange - Mock outdated driver
        scanner_service._mock_outdated_driver = True
        
        # Act - Check availability
        availability = scanner_service.check_scanner_availability()
        
        # Assert - Should detect driver issue
        assert "driver_status" in availability
        driver_status = availability["driver_status"]
        
        assert driver_status["outdated"] is True
        assert "current_version" in driver_status
        assert "recommended_version" in driver_status
        assert "update_url" in driver_status
    
    def test_scanner_power_management_recovery(self, scanner_service):
        """
        Test recovery from scanner power save mode
        
        Contract: Should wake scanner from power save and retry scan
        """
        # Arrange - Mock scanner in power save mode
        scanner_service._mock_power_save_mode = True
        
        # Act - Attempt scan (should auto-wake scanner)
        result = scanner_service.scan_document()
        
        # Assert - Should succeed after waking scanner
        assert isinstance(result, dict)
        assert "document_path" in result
        assert "power_wake_performed" in result
        assert result["power_wake_performed"] is True


class TestScannerErrorDiagnostics:
    """Integration tests for scanner error diagnostics"""
    
    @pytest.fixture
    def scanner_service(self):
        return ScannerService()
    
    def test_comprehensive_scanner_diagnostics(self, scanner_service):
        """
        Test comprehensive scanner diagnostic report
        
        Contract: Should provide detailed diagnostic information
        """
        # Act - Run diagnostics
        diagnostics = scanner_service.run_diagnostics()
        
        # Assert - Should provide comprehensive report
        assert isinstance(diagnostics, dict)
        
        # Hardware status
        assert "hardware_status" in diagnostics
        hardware = diagnostics["hardware_status"]
        assert "connection" in hardware
        assert "lamp_status" in hardware
        assert "sensor_status" in hardware
        assert "calibration_status" in hardware
        
        # Driver information
        assert "driver_info" in diagnostics
        driver = diagnostics["driver_info"]
        assert "version" in driver
        assert "compatibility" in driver
        
        # Performance metrics
        assert "performance_metrics" in diagnostics
        perf = diagnostics["performance_metrics"]
        assert "scan_speed" in perf
        assert "quality_score" in perf
        
        # Recent errors
        assert "recent_errors" in diagnostics
        errors = diagnostics["recent_errors"]
        assert isinstance(errors, list)
    
    def test_error_pattern_analysis(self, scanner_service):
        """
        Test analysis of scanner error patterns
        
        Contract: Should identify recurring error patterns and suggest solutions
        """
        # Arrange - Mock error history
        scanner_service._mock_error_history = [
            {"error": "DEVICE_BUSY", "timestamp": datetime.now() - timedelta(minutes=5)},
            {"error": "DEVICE_BUSY", "timestamp": datetime.now() - timedelta(minutes=3)},
            {"error": "DEVICE_BUSY", "timestamp": datetime.now() - timedelta(minutes=1)},
        ]
        
        # Act - Analyze error patterns
        pattern_analysis = scanner_service.analyze_error_patterns()
        
        # Assert - Should identify patterns
        assert isinstance(pattern_analysis, dict)
        assert "frequent_errors" in pattern_analysis
        assert "pattern_detected" in pattern_analysis
        assert "recommended_actions" in pattern_analysis
        
        frequent_errors = pattern_analysis["frequent_errors"]
        assert "DEVICE_BUSY" in [error["type"] for error in frequent_errors]
        
        assert pattern_analysis["pattern_detected"] is True
        actions = pattern_analysis["recommended_actions"]
        assert isinstance(actions, list)
        assert len(actions) > 0
    
    def test_scanner_health_monitoring(self, scanner_service):
        """
        Test continuous scanner health monitoring
        
        Contract: Should maintain scanner health score and trend analysis
        """
        # Act - Get health status
        health_status = scanner_service.get_health_status()
        
        # Assert - Should provide health metrics
        assert isinstance(health_status, dict)
        assert "health_score" in health_status  # 0-100
        assert "status" in health_status  # "healthy", "warning", "critical"
        assert "uptime" in health_status
        assert "scan_success_rate" in health_status
        assert "average_scan_time" in health_status
        assert "trend" in health_status  # "improving", "stable", "declining"
        
        # Health score should be valid
        score = health_status["health_score"]
        assert 0 <= score <= 100
        
        # Success rate should be percentage
        success_rate = health_status["scan_success_rate"]
        assert 0.0 <= success_rate <= 1.0


class TestScannerErrorIntegrationWithWorkflow:
    """Integration tests combining scanner errors with document workflow"""
    
    @pytest.fixture
    def scanner_service(self):
        return ScannerService()
    
    def test_scan_error_workflow_continuation(self, scanner_service):
        """
        Test workflow continuation after scanner error resolution
        
        Contract: Should allow workflow to continue after error is resolved
        """
        # Arrange - Mock initial scan failure then success
        scanner_service._mock_initial_failure = True
        
        # First attempt should fail
        with pytest.raises(ScanFailedError):
            scanner_service.scan_document()
        
        # Resolve the issue
        scanner_service._mock_initial_failure = False
        
        # Second attempt should succeed
        result = scanner_service.scan_document()
        
        # Assert - Should succeed
        assert isinstance(result, dict)
        assert "document_path" in result
        assert "recovery_successful" in result
        assert result["recovery_successful"] is True
    
    def test_scan_quality_validation_with_retry(self, scanner_service):
        """
        Test scan quality validation with automatic retry for poor quality
        
        Contract: Should retry scan if quality is below threshold
        """
        # Arrange - Mock poor quality scan initially
        scanner_service._mock_quality_progression = [30, 45, 85]  # Poor, poor, good
        
        # Act - Scan document (should retry for quality)
        result = scanner_service.scan_document()
        
        # Assert - Should succeed with quality info
        assert isinstance(result, dict)
        assert "document_path" in result
        assert "quality_score" in result
        assert "quality_retries" in result
        
        assert result["quality_score"] >= 80  # Should meet quality threshold
        assert result["quality_retries"] == 2  # Two retries for quality
    
    def test_emergency_scan_bypass_mode(self, scanner_service):
        """
        Test emergency scan mode that bypasses some error checks
        
        Contract: Should provide emergency mode for critical documents
        """
        # Arrange - Mock conditions that would normally fail
        scanner_service._mock_minor_hardware_issues = True
        scanner_service._mock_quality_concerns = True
        
        # Act - Emergency scan mode
        result = scanner_service.scan_document(emergency_mode=True)
        
        # Assert - Should succeed despite issues
        assert isinstance(result, dict)
        assert "document_path" in result
        assert "emergency_mode_used" in result
        assert "bypassed_checks" in result
        
        assert result["emergency_mode_used"] is True
        bypassed = result["bypassed_checks"]
        assert "minor_hardware_issues" in bypassed
        assert "quality_validation" in bypassed
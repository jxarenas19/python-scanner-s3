"""
Mock Scanner Service
Simulates scanner hardware for testing and development
"""

import os
import random

# Add src to path for imports
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.settings import ScannerConfig


class MockScannerService:
    """
    Mock scanner service for development and testing

    Simulates scanner behavior without requiring physical hardware
    """

    def __init__(self):
        self._mock_settings = {}
        self._error_history: List[Dict[str, Any]] = []
        self._health_metrics = {
            "scan_count": 0,
            "success_count": 0,
            "error_count": 0,
            "total_scan_time": 0.0,
            "last_health_check": datetime.now(),
        }

        # Initialize pending documents list
        self._pending_documents: List[Dict[str, Any]] = []

        # Ensure scan output directory exists
        ScannerConfig.SCAN_OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

        print(
            f"[MockScannerService] Initialized - Output dir: {ScannerConfig.SCAN_OUTPUT_DIRECTORY}"
        )

    def check_scanner_availability(self) -> Dict[str, Any]:
        """
        Check mock scanner availability

        Returns:
            Dict with availability status and scanner information
        """
        # Mock disconnection scenario
        if self._mock_settings.get("_mock_disconnected", False):
            return {
                "available": False,
                "scanner_name": "No scanner detected",
                "mode": "mock",
                "reconnection_steps": [
                    "Check USB/network connection",
                    "Verify scanner power",
                    "Restart scanner device",
                    "Check driver installation",
                ],
            }

        # Mock no scanner scenario
        if self._mock_settings.get("_mock_no_scanner", False):
            return {
                "available": False,
                "scanner_name": "No scanner detected",
                "mode": "mock",
                "error_details": "No compatible scanner devices found",
            }

        # Default: scanner available
        result = {
            "available": True,
            "scanner_name": f"{ScannerConfig.SCANNER_NAME} (Mock)",
            "scanner_type": ScannerConfig.SCANNER_TYPE,
            "driver_version": "2.1.3",
            "mode": "mock",
        }

        if self._mock_settings.get("_mock_outdated_driver", False):
            result["driver_status"] = {
                "outdated": True,
                "current_version": "2.1.3",
                "recommended_version": "2.2.1",
                "update_url": "https://canon.com/drivers/dr-c225",
            }

        return result

    def get_pending_documents(self) -> List[Dict[str, Any]]:
        """
        Get mock pending documents

        Returns:
            List of mock document dictionaries
        """
        # Use configuration for mock settings
        mock_config = ScannerConfig.MOCK_SCANNER_CONFIG
        probability = mock_config.get("document_generation_probability", 0.3)
        min_size_kb = mock_config.get("min_file_size_kb", 50) * 1024
        max_size_kb = mock_config.get("max_file_size_kb", 500) * 1024

        # Randomly add new documents to simulate scanner activity
        if random.random() < probability:
            # Create mock document
            timestamp = datetime.now()
            filename = f"mock_doc_{timestamp.strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}.{ScannerConfig.DEFAULT_FORMAT.lower()}"
            document_path = ScannerConfig.SCAN_OUTPUT_DIRECTORY / filename

            # Create mock document file
            with open(document_path, "wb") as f:
                # Write mock content based on format
                mock_size = random.randint(min_size_kb, max_size_kb)
                format_type = ScannerConfig.DEFAULT_FORMAT.upper()

                if format_type == "PDF":
                    mock_content = b"MOCK_PDF_DOCUMENT_CONTENT" * (mock_size // 24)
                elif format_type == "TIFF":
                    mock_content = b"MOCK_TIFF_DOCUMENT_CONTENT" * (mock_size // 25)
                else:
                    mock_content = b"MOCK_DOCUMENT_CONTENT" * (mock_size // 20)

                f.write(mock_content[:mock_size])

            file_size = os.path.getsize(document_path)

            document = {
                "document_path": str(document_path),
                "filename": filename,
                "timestamp": timestamp,
                "file_size": file_size,
                "format": ScannerConfig.DEFAULT_FORMAT,
                "source": "mock_scanner",
                "mode": "mock",
            }

            self._pending_documents.append(document)
            print(
                f"[MockScannerService] Generated mock document: {filename} ({file_size:,} bytes)"
            )

        # Return and clear the pending documents (simulating they've been "received")
        pending = self._pending_documents.copy()
        self._pending_documents.clear()

        return pending

    def scan_document(
        self, session_token: Optional[str] = None, emergency_mode: bool = False
    ) -> Dict[str, Any]:
        """
        Perform mock document scan

        Args:
            session_token: Optional session token for authentication
            emergency_mode: Skip some error checks for critical documents

        Returns:
            Dict with mock scan results
        """
        start_time = time.time()

        # Handle mock scenarios for testing
        self._handle_mock_scenarios(emergency_mode)

        # Simulate scan operation
        scan_result = self._execute_mock_scan_operation(start_time)

        # Update health metrics
        self._update_health_metrics(True, time.time() - start_time)

        return scan_result

    def _handle_mock_scenarios(self, emergency_mode: bool) -> None:
        """Handle various mock error scenarios for testing"""
        # Device busy scenario
        if self._mock_settings.get("_mock_device_busy", False):
            time.sleep(0.1)  # Brief delay
            from scanner_service import DeviceBusyError

            raise DeviceBusyError("Mock device busy")

        # Hardware malfunction scenario
        if self._mock_settings.get("_mock_hardware_malfunction"):
            details = self._mock_settings["_mock_hardware_malfunction"]
            from scanner_service import HardwareError

            raise HardwareError("Mock hardware malfunction", details)

    def _execute_mock_scan_operation(self, start_time: float) -> Dict[str, Any]:
        """Execute mock scan operation and return results"""
        # Create temporary file for scanned document
        timestamp = datetime.now()
        filename = f"mock_scan_{timestamp.strftime('%Y%m%d_%H%M%S')}.{ScannerConfig.DEFAULT_FORMAT.lower()}"
        document_path = ScannerConfig.SCAN_OUTPUT_DIRECTORY / filename

        # Simulate scan by creating a file with mock content
        with open(document_path, "wb") as f:
            # Write mock content
            mock_content = b"MOCK_SCANNED_DOCUMENT_CONTENT" * 100
            f.write(mock_content)

        file_size = os.path.getsize(document_path)

        return {
            "document_path": str(document_path),
            "timestamp": timestamp,
            "file_size": file_size,
            "format": ScannerConfig.DEFAULT_FORMAT,
            "mode": "mock",
        }

    def _update_health_metrics(self, success: bool, scan_time: float) -> None:
        """Update internal health metrics"""
        self._health_metrics["scan_count"] += 1
        self._health_metrics["total_scan_time"] += scan_time

        if success:
            self._health_metrics["success_count"] += 1
        else:
            self._health_metrics["error_count"] += 1

    def get_health_status(self) -> Dict[str, Any]:
        """
        Get mock scanner health status

        Returns:
            Dict with health status information
        """
        total_scans = self._health_metrics["scan_count"]
        success_rate = (
            self._health_metrics["success_count"] / total_scans
            if total_scans > 0
            else 1.0
        )

        return {
            "health_score": int(success_rate * 100),
            "status": "healthy",
            "uptime": 3600,  # Mock 1 hour uptime
            "scan_success_rate": success_rate,
            "average_scan_time": 2.0,  # Mock 2 seconds
            "trend": "stable",
            "mode": "mock",
        }

    def run_diagnostics(self) -> Dict[str, Any]:
        """
        Run mock scanner diagnostics

        Returns:
            Dict with diagnostic information
        """
        return {
            "hardware_status": {
                "connection": "connected (mock)",
                "lamp_status": "operational (mock)",
                "sensor_status": "calibrated (mock)",
                "calibration_status": "optimal (mock)",
            },
            "driver_info": {
                "version": "2.1.3 (mock)",
                "compatibility": "fully_compatible",
            },
            "performance_metrics": {
                "scan_speed": "25 pages/minute (mock)",
                "quality_score": 95,
            },
            "mode": "mock",
        }

    # Mock control methods for testing
    def set_mock_disconnected(self, disconnected: bool = True):
        """Set mock disconnection state"""
        self._mock_settings["_mock_disconnected"] = disconnected

    def set_mock_no_scanner(self, no_scanner: bool = True):
        """Set mock no scanner state"""
        self._mock_settings["_mock_no_scanner"] = no_scanner

    def set_mock_device_busy(self, busy: bool = True):
        """Set mock device busy state"""
        self._mock_settings["_mock_device_busy"] = busy

"""
Scanner Service Factory
Creates the appropriate scanner service based on configuration
"""

import os
import sys
from typing import Any, Dict, List, Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.settings import AppConfig


class ScannerService:
    """
    Scanner Service Factory

    Creates and returns the appropriate scanner service implementation
    based on the MOCK_MODE configuration setting.
    """

    def __new__(cls):
        """
        Factory method that returns the appropriate scanner service instance

        Returns:
            MockScannerService if MOCK_MODE=True
            RealScannerService if MOCK_MODE=False
        """
        if AppConfig.MOCK_MODE:
            print(
                f"[ScannerService] Creating MockScannerService (MOCK_MODE={AppConfig.MOCK_MODE})"
            )
            from .scanner_service_mock import MockScannerService

            return MockScannerService()
        else:
            print(
                f"[ScannerService] Creating RealScannerService (MOCK_MODE={AppConfig.MOCK_MODE})"
            )
            from .scanner_service_real import RealScannerService

            return RealScannerService()


# Export exception classes for backward compatibility
class ScannerServiceError(Exception):
    """Base exception for scanner service errors"""

    def __init__(self, message: str, error_code: str):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class NoScannerError(ScannerServiceError):
    """Raised when no scanner device is detected"""

    def __init__(self, message: str = "No scanner device detected"):
        super().__init__(message, "NO_SCANNER_ERROR")


class ScanFailedError(ScannerServiceError):
    """Raised when scan operation fails"""

    def __init__(self, message: str = "Scan operation failed"):
        super().__init__(message, "SCAN_FAILED_ERROR")


class DeviceBusyError(ScannerServiceError):
    """Raised when scanner device is busy"""

    def __init__(self, message: str = "Scanner device is busy"):
        super().__init__(message, "DEVICE_BUSY_ERROR")
        self.retry_count = getattr(self, "retry_count", 0)


class HardwareError(ScannerServiceError):
    """Raised for hardware-related errors"""

    def __init__(self, message: str, hardware_details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "HARDWARE_MALFUNCTION")
        self.hardware_details = hardware_details or {}
        self.recovery_suggestion = "Check hardware connections and restart scanner"

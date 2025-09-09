"""
Configuration Settings
Contains all configuration constants for the Scanner Cifrado S3 application
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

# Load environment variables from .env file
try:
    from . import env_loader
except ImportError:
    # env_loader not available, continue without it
    pass


class AppConfig:
    """Main application configuration"""

    # Application info
    APP_NAME = "Scanner Cifrado S3"
    APP_VERSION = "1.0.0"

    # Mock mode toggle - set to False for production with real scanner
    MOCK_MODE = os.getenv("SCANNER_MOCK_MODE", True) == False

    # Environment
    ENVIRONMENT = os.getenv(
        "APP_ENVIRONMENT", "development"
    )  # development, staging, production

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE_PATH = Path("logs/scanner_app.log")

    # Session timeout (minutes)
    SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "60"))


class ScannerConfig:
    """Scanner hardware configuration"""

    # Scanner connection settings
    SCANNER_TYPE = os.getenv("SCANNER_TYPE", "TWAIN")  # TWAIN, SANE, WIA
    SCANNER_NAME = os.getenv("SCANNER_NAME", "Canon imageFORMULA DR-C225")
    SCANNER_MODEL = os.getenv("SCANNER_MODEL", "DR-C225")

    # Connection settings
    SCANNER_TIMEOUT_SECONDS = int(os.getenv("SCANNER_TIMEOUT_SECONDS", "30"))
    SCANNER_RETRY_ATTEMPTS = int(os.getenv("SCANNER_RETRY_ATTEMPTS", "3"))
    SCANNER_RETRY_DELAY_SECONDS = int(os.getenv("SCANNER_RETRY_DELAY_SECONDS", "2"))

    # Document polling settings
    DOCUMENT_POLLING_INTERVAL_SECONDS = int(os.getenv("DOCUMENT_POLLING_INTERVAL", "2"))
    MAX_DOCUMENTS_PER_BATCH = int(os.getenv("MAX_DOCUMENTS_PER_BATCH", "50"))

    # Scanner capabilities
    SUPPORTED_FORMATS = ["PDF", "TIFF", "JPEG", "PNG"]
    DEFAULT_FORMAT = os.getenv("SCANNER_DEFAULT_FORMAT", "PDF")
    DEFAULT_RESOLUTION_DPI = int(os.getenv("SCANNER_RESOLUTION", "300"))
    DEFAULT_COLOR_MODE = os.getenv(
        "SCANNER_COLOR_MODE", "Color"
    )  # Color, Grayscale, BlackWhite

    # File settings
    SCAN_OUTPUT_DIRECTORY = Path(os.getenv("SCAN_OUTPUT_DIR", "temp/scans"))
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "50"))

    # Real scanner specific settings (when MOCK_MODE=False)
    REAL_SCANNER_CONFIG = {
        "device_id": os.getenv("SCANNER_DEVICE_ID", ""),  # Specific device ID
        "driver_path": os.getenv("SCANNER_DRIVER_PATH", ""),
        "connection_type": os.getenv(
            "SCANNER_CONNECTION", "USB"
        ),  # USB, Network, Parallel
        "ip_address": os.getenv("SCANNER_IP", ""),  # For network scanners
        "port": int(os.getenv("SCANNER_PORT", "9100")),  # For network scanners
        "authentication": {
            "username": os.getenv("SCANNER_USERNAME", ""),
            "password": os.getenv("SCANNER_PASSWORD", ""),
        },
    }

    # Mock scanner settings (when MOCK_MODE=True)
    MOCK_SCANNER_CONFIG = {
        "document_generation_probability": 0.3,  # 30% chance per polling
        "min_file_size_kb": 50,
        "max_file_size_kb": 500,
        "simulated_scan_delay_seconds": 1.0,
        "error_simulation": {
            "device_busy_probability": 0.05,  # 5% chance
            "paper_jam_probability": 0.02,  # 2% chance
            "timeout_probability": 0.01,  # 1% chance
        },
    }


class S3Config:
    """AWS S3 configuration for document storage"""

    # S3 bucket settings
    BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "scanner-cifrado-docs")
    BUCKET_REGION = os.getenv("S3_BUCKET_REGION", "us-east-1")

    # AWS credentials (prefer environment variables or IAM roles)
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_PROFILE = os.getenv("AWS_PROFILE", "default")

    # S3 key structure
    S3_KEY_PREFIX = os.getenv("S3_KEY_PREFIX", "encrypted-documents")
    S3_KEY_STRUCTURE = "{prefix}/{branch}/{year}/{month}/{day}/{filename}"

    # Upload settings
    MULTIPART_THRESHOLD_MB = int(os.getenv("S3_MULTIPART_THRESHOLD", "100"))
    MAX_UPLOAD_ATTEMPTS = int(os.getenv("S3_MAX_UPLOAD_ATTEMPTS", "3"))
    UPLOAD_TIMEOUT_SECONDS = int(os.getenv("S3_UPLOAD_TIMEOUT", "300"))

    # Encryption settings
    SERVER_SIDE_ENCRYPTION = os.getenv("S3_SERVER_SIDE_ENCRYPTION", "AES256")
    KMS_KEY_ID = os.getenv("S3_KMS_KEY_ID", "")  # For SSE-KMS

    # Lifecycle and retention
    TRANSITION_TO_IA_DAYS = int(os.getenv("S3_TRANSITION_IA_DAYS", "30"))
    TRANSITION_TO_GLACIER_DAYS = int(os.getenv("S3_TRANSITION_GLACIER_DAYS", "90"))
    RETENTION_YEARS = int(os.getenv("S3_RETENTION_YEARS", "7"))


class CryptoConfig:
    """Cryptographic configuration"""

    # Encryption algorithm
    ENCRYPTION_ALGORITHM = "AES-256-GCM"
    KEY_SIZE_BITS = 256

    # Key management
    KEY_ROTATION_DAYS = int(os.getenv("CRYPTO_KEY_ROTATION_DAYS", "90"))
    USE_EPHEMERAL_KEYS = os.getenv("CRYPTO_EPHEMERAL_KEYS", "true").lower() == "true"

    # Key derivation
    PBKDF2_ITERATIONS = int(os.getenv("CRYPTO_PBKDF2_ITERATIONS", "100000"))
    SALT_SIZE_BYTES = 32

    # File encryption
    CHUNK_SIZE_BYTES = 64 * 1024  # 64KB chunks for streaming encryption
    COMPRESSION_ENABLED = os.getenv("CRYPTO_COMPRESSION", "true").lower() == "true"


class DatabaseConfig:
    """Database configuration for session and audit logging"""

    # Database type
    DB_TYPE = os.getenv("DB_TYPE", "sqlite")  # sqlite, postgresql, mysql

    # SQLite settings (default)
    SQLITE_DB_PATH = Path(os.getenv("SQLITE_DB_PATH", "data/scanner_app.db"))

    # PostgreSQL settings
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
    POSTGRES_DB = os.getenv("POSTGRES_DB", "scanner_app")
    POSTGRES_USER = os.getenv("POSTGRES_USER", "")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")

    # Connection pool settings
    DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
    DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    DB_TIMEOUT_SECONDS = int(os.getenv("DB_TIMEOUT", "30"))


class UIConfig:
    """User interface configuration"""

    # Window settings
    DEFAULT_WINDOW_WIDTH = int(os.getenv("UI_WINDOW_WIDTH", "900"))
    DEFAULT_WINDOW_HEIGHT = int(os.getenv("UI_WINDOW_HEIGHT", "600"))
    MIN_WINDOW_WIDTH = int(os.getenv("UI_MIN_WIDTH", "800"))
    MIN_WINDOW_HEIGHT = int(os.getenv("UI_MIN_HEIGHT", "500"))

    # Theme and styling
    UI_THEME = os.getenv("UI_THEME", "default")  # default, dark, light
    FONT_FAMILY = os.getenv("UI_FONT_FAMILY", "")
    FONT_SIZE = int(os.getenv("UI_FONT_SIZE", "10"))

    # Update intervals
    STATUS_UPDATE_INTERVAL_MS = int(os.getenv("UI_STATUS_UPDATE_MS", "2000"))
    LOG_REFRESH_INTERVAL_MS = int(os.getenv("UI_LOG_REFRESH_MS", "1000"))

    # Document list settings
    MAX_DOCUMENT_LIST_ITEMS = int(os.getenv("UI_MAX_DOC_LIST", "100"))
    AUTO_SCROLL_LOGS = os.getenv("UI_AUTO_SCROLL_LOGS", "true").lower() == "true"


def get_config_summary() -> Dict[str, Any]:
    """Get a summary of current configuration for debugging"""
    return {
        "app": {
            "name": AppConfig.APP_NAME,
            "version": AppConfig.APP_VERSION,
            "environment": AppConfig.ENVIRONMENT,
            "mock_mode": AppConfig.MOCK_MODE,
        },
        "scanner": {
            "type": ScannerConfig.SCANNER_TYPE,
            "name": ScannerConfig.SCANNER_NAME,
            "timeout": ScannerConfig.SCANNER_TIMEOUT_SECONDS,
            "polling_interval": ScannerConfig.DOCUMENT_POLLING_INTERVAL_SECONDS,
        },
        "s3": {
            "bucket": S3Config.BUCKET_NAME,
            "region": S3Config.BUCKET_REGION,
            "encryption": S3Config.SERVER_SIDE_ENCRYPTION,
        },
        "crypto": {
            "algorithm": CryptoConfig.ENCRYPTION_ALGORITHM,
            "ephemeral_keys": CryptoConfig.USE_EPHEMERAL_KEYS,
        },
    }


def validate_config() -> Dict[str, list]:
    """Validate configuration and return any issues"""
    issues = {"errors": [], "warnings": []}

    # Check S3 configuration
    if not S3Config.BUCKET_NAME:
        issues["errors"].append("S3_BUCKET_NAME is required")

    if not AppConfig.MOCK_MODE:
        # Check real scanner configuration
        if not ScannerConfig.REAL_SCANNER_CONFIG["device_id"]:
            issues["warnings"].append("SCANNER_DEVICE_ID not set for real scanner mode")

    # Check directories exist or can be created
    try:
        ScannerConfig.SCAN_OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        issues["errors"].append(f"Cannot create scan output directory: {e}")

    try:
        AppConfig.LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        issues["warnings"].append(f"Cannot create log directory: {e}")

    return issues


# Create directories on import if they don't exist
def _ensure_directories():
    """Ensure required directories exist"""
    directories = [
        ScannerConfig.SCAN_OUTPUT_DIRECTORY,
        AppConfig.LOG_FILE_PATH.parent,
        DatabaseConfig.SQLITE_DB_PATH.parent,
    ]

    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass  # Will be caught by validate_config()


_ensure_directories()

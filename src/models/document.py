"""
Document entity data model
Represents a scanned document with metadata and processing state
"""

import hashlib
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional


class DocumentStatus(Enum):
    """Document processing status"""

    SCANNED = "scanned"
    ENCRYPTED = "encrypted"
    UPLOADED = "uploaded"
    FAILED = "failed"


class DocumentFormat(Enum):
    """Supported document formats"""

    TIFF = "TIFF"
    PNG = "PNG"
    JPEG = "JPEG"
    PDF = "PDF"


class Document:
    """
    Document entity representing a scanned promissory note

    Attributes:
        document_id: Unique document identifier
        original_path: Path to original scanned file
        encrypted_path: Path to encrypted file (if encrypted)
        s3_url: S3 URL after upload (if uploaded)
        operator: Operator who scanned the document
        branch: Branch where document was scanned
        timestamp: When document was scanned
        format: Document format (TIFF, PNG, JPEG, PDF)
        file_size: Original file size in bytes
        encrypted_size: Encrypted file size in bytes
        status: Current processing status
        key_hash: Hash of encryption key (if encrypted)
        processing_time: Total processing time in seconds
        metadata: Additional metadata
    """

    def __init__(
        self,
        document_id: str,
        original_path: str,
        operator: str,
        branch: str,
        timestamp: datetime,
        format: DocumentFormat,
        file_size: int,
    ):
        self.document_id = document_id
        self.original_path = Path(original_path)
        self.encrypted_path: Optional[Path] = None
        self.s3_url: Optional[str] = None
        self.operator = operator
        self.branch = branch
        self.timestamp = timestamp
        self.format = format
        self.file_size = file_size
        self.encrypted_size: Optional[int] = None
        self.status = DocumentStatus.SCANNED
        self.key_hash: Optional[str] = None
        self.processing_time: Optional[float] = None
        self.metadata: Dict[str, Any] = {}

        # Validation
        self._validate()

    def _validate(self) -> None:
        """Validate document data"""
        if not self.document_id:
            raise ValueError("Document ID cannot be empty")

        if not self.original_path.exists():
            raise FileNotFoundError(f"Document file not found: {self.original_path}")

        if self.file_size <= 0:
            raise ValueError("File size must be positive")

        if not self.operator:
            raise ValueError("Operator cannot be empty")

        if not self.branch:
            raise ValueError("Branch cannot be empty")

        # Validate file format matches extension
        expected_extensions = {
            DocumentFormat.TIFF: [".tiff", ".tif"],
            DocumentFormat.PNG: [".png"],
            DocumentFormat.JPEG: [".jpeg", ".jpg"],
            DocumentFormat.PDF: [".pdf"],
        }

        file_ext = self.original_path.suffix.lower()
        if file_ext not in expected_extensions[self.format]:
            raise ValueError(
                f"File extension {file_ext} doesn't match format {self.format.value}"
            )

    @classmethod
    def from_scan_result(
        cls, scan_result: Dict[str, Any], operator: str, branch: str
    ) -> "Document":
        """
        Create Document from scanner service scan result

        Args:
            scan_result: Result dict from scanner service
            operator: Operator who performed the scan
            branch: Branch where scan was performed

        Returns:
            Document instance
        """
        document_path = scan_result["document_path"]
        timestamp = scan_result["timestamp"]
        file_size = scan_result["file_size"]
        format_str = scan_result["format"]

        # Generate document ID
        document_id = cls.generate_document_id(operator, branch, timestamp)

        # Parse format
        doc_format = DocumentFormat(format_str)

        return cls(
            document_id=document_id,
            original_path=document_path,
            operator=operator,
            branch=branch,
            timestamp=timestamp,
            format=doc_format,
            file_size=file_size,
        )

    @staticmethod
    def generate_document_id(operator: str, branch: str, timestamp: datetime) -> str:
        """
        Generate unique document ID

        Format: {branch}_{operator}_{timestamp}_{hash}

        Args:
            operator: Operator name
            branch: Branch name
            timestamp: Scan timestamp

        Returns:
            Unique document ID
        """
        # Create unique string
        unique_str = f"{branch}_{operator}_{timestamp.isoformat()}"

        # Generate hash
        hash_obj = hashlib.sha256(unique_str.encode())
        hash_suffix = hash_obj.hexdigest()[:8]

        # Format: branch_operator_YYYYMMDD_HHMMSS_hash
        formatted_timestamp = timestamp.strftime("%Y%m%d_%H%M%S")

        return f"{branch}_{operator}_{formatted_timestamp}_{hash_suffix}"

    def mark_encrypted(
        self, encrypted_path: str, key_hash: str, encrypted_size: int
    ) -> None:
        """
        Mark document as encrypted

        Args:
            encrypted_path: Path to encrypted file
            key_hash: Hash of encryption key
            encrypted_size: Size of encrypted file
        """
        self.encrypted_path = Path(encrypted_path)
        self.key_hash = key_hash
        self.encrypted_size = encrypted_size
        self.status = DocumentStatus.ENCRYPTED

        # Validate encrypted file exists
        if not self.encrypted_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {self.encrypted_path}")

    def mark_uploaded(self, s3_url: str) -> None:
        """
        Mark document as uploaded to S3

        Args:
            s3_url: S3 URL where document is stored
        """
        if not s3_url:
            raise ValueError("S3 URL cannot be empty")

        self.s3_url = s3_url
        self.status = DocumentStatus.UPLOADED

    def mark_failed(self, error_message: str) -> None:
        """
        Mark document processing as failed

        Args:
            error_message: Error description
        """
        self.status = DocumentStatus.FAILED
        self.metadata["error"] = error_message
        self.metadata["failed_at"] = datetime.now().isoformat()

    def set_processing_time(self, seconds: float) -> None:
        """
        Set total processing time

        Args:
            seconds: Processing time in seconds
        """
        if seconds < 0:
            raise ValueError("Processing time cannot be negative")
        self.processing_time = seconds

    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata entry

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value

    def get_s3_key(self) -> str:
        """
        Generate S3 object key for this document

        Format: YYYY-MM-DD/branch/operator/pagare-{epoch}.enc

        Returns:
            S3 object key
        """
        date_str = self.timestamp.strftime("%Y-%m-%d")
        epoch = int(self.timestamp.timestamp())

        return f"{date_str}/{self.branch}/{self.operator}/pagare-{epoch}.enc"

    def is_processing_complete(self) -> bool:
        """
        Check if document processing is complete

        Returns:
            True if uploaded or failed, False otherwise
        """
        return self.status in [DocumentStatus.UPLOADED, DocumentStatus.FAILED]

    def can_be_encrypted(self) -> bool:
        """
        Check if document can be encrypted

        Returns:
            True if status is SCANNED
        """
        return self.status == DocumentStatus.SCANNED

    def can_be_uploaded(self) -> bool:
        """
        Check if document can be uploaded

        Returns:
            True if status is ENCRYPTED
        """
        return self.status == DocumentStatus.ENCRYPTED

    def cleanup_files(self) -> None:
        """
        Clean up temporary files (original and encrypted)

        Note: Only removes files if document is successfully uploaded
        """
        if self.status != DocumentStatus.UPLOADED:
            return

        # Remove original file
        if self.original_path.exists():
            try:
                self.original_path.unlink()
            except OSError:
                pass  # Ignore cleanup errors

        # Remove encrypted file
        if self.encrypted_path and self.encrypted_path.exists():
            try:
                self.encrypted_path.unlink()
            except OSError:
                pass  # Ignore cleanup errors

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert document to dictionary representation

        Returns:
            Dictionary with document data
        """
        return {
            "document_id": self.document_id,
            "original_path": str(self.original_path),
            "encrypted_path": str(self.encrypted_path) if self.encrypted_path else None,
            "s3_url": self.s3_url,
            "operator": self.operator,
            "branch": self.branch,
            "timestamp": self.timestamp.isoformat(),
            "format": self.format.value,
            "file_size": self.file_size,
            "encrypted_size": self.encrypted_size,
            "status": self.status.value,
            "key_hash": self.key_hash,
            "processing_time": self.processing_time,
            "s3_key": self.get_s3_key(),
            "metadata": self.metadata.copy(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Document":
        """
        Create document from dictionary representation

        Args:
            data: Dictionary with document data

        Returns:
            Document instance
        """
        timestamp = datetime.fromisoformat(data["timestamp"])
        format_enum = DocumentFormat(data["format"])

        doc = cls(
            document_id=data["document_id"],
            original_path=data["original_path"],
            operator=data["operator"],
            branch=data["branch"],
            timestamp=timestamp,
            format=format_enum,
            file_size=data["file_size"],
        )

        # Set optional fields
        if data.get("encrypted_path"):
            doc.encrypted_path = Path(data["encrypted_path"])

        doc.s3_url = data.get("s3_url")
        doc.encrypted_size = data.get("encrypted_size")
        doc.key_hash = data.get("key_hash")
        doc.processing_time = data.get("processing_time")
        doc.status = DocumentStatus(data["status"])
        doc.metadata = data.get("metadata", {}).copy()

        return doc

    def __str__(self) -> str:
        """String representation"""
        return f"Document(id={self.document_id}, status={self.status.value}, operator={self.operator})"

    def __repr__(self) -> str:
        """Detailed string representation"""
        return (
            f"Document(document_id='{self.document_id}', "
            f"operator='{self.operator}', branch='{self.branch}', "
            f"status={self.status.value}, format={self.format.value})"
        )

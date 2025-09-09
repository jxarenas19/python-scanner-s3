"""
ScanningSession entity data model
Represents an authenticated scanning session with documents and activities
"""

import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from .document import Document


class SessionStatus(Enum):
    """Session status"""

    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"


class ActivityType(Enum):
    """Types of session activities"""

    LOGIN = "login"
    SCAN_DOCUMENT = "scan_document"
    ENCRYPT_DOCUMENT = "encrypt_document"
    UPLOAD_DOCUMENT = "upload_document"
    DOCUMENT_COMPLETE = "document_complete"
    LOGOUT = "logout"
    SESSION_REFRESH = "session_refresh"
    ERROR_OCCURRED = "error_occurred"


class SessionActivity:
    """
    Individual activity within a session
    """

    def __init__(
        self,
        activity_type: ActivityType,
        timestamp: datetime,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.activity_id = str(uuid.uuid4())
        self.activity_type = activity_type
        self.timestamp = timestamp
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert activity to dictionary"""
        return {
            "activity_id": self.activity_id,
            "activity_type": self.activity_type.value,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details.copy(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionActivity":
        """Create activity from dictionary"""
        activity = cls(
            activity_type=ActivityType(data["activity_type"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            details=data.get("details", {}),
        )
        activity.activity_id = data["activity_id"]
        return activity


class ScanningSession:
    """
    Scanning session entity representing an authenticated user session

    Attributes:
        session_id: Unique session identifier
        session_token: Authentication token
        operator: Authenticated operator
        branch: Branch where session is active
        created_at: Session creation timestamp
        expires_at: Session expiration timestamp
        last_activity_at: Last activity timestamp
        status: Current session status
        documents: List of documents processed in this session
        activities: List of session activities
        metadata: Additional session metadata
    """

    def __init__(
        self,
        session_id: str,
        session_token: str,
        operator: str,
        branch: str,
        created_at: datetime,
        expires_at: datetime,
    ):
        self.session_id = session_id
        self.session_token = session_token
        self.operator = operator
        self.branch = branch
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_activity_at = created_at
        self.status = SessionStatus.ACTIVE
        self.documents: List[Document] = []
        self.activities: List[SessionActivity] = []
        self.metadata: Dict[str, Any] = {}

        # Add login activity
        self.add_activity(ActivityType.LOGIN, {"operator": operator, "branch": branch})

        # Validation
        self._validate()

    def _validate(self) -> None:
        """Validate session data"""
        if not self.session_id:
            raise ValueError("Session ID cannot be empty")

        if not self.session_token:
            raise ValueError("Session token cannot be empty")

        if not self.operator:
            raise ValueError("Operator cannot be empty")

        if not self.branch:
            raise ValueError("Branch cannot be empty")

        if self.expires_at <= self.created_at:
            raise ValueError("Expiration time must be after creation time")

    @classmethod
    def create_new(
        cls,
        operator: str,
        branch: str,
        session_duration_minutes: int = 480,  # 8 hours default
    ) -> "ScanningSession":
        """
        Create new scanning session

        Args:
            operator: Operator name
            branch: Branch name
            session_duration_minutes: Session duration in minutes

        Returns:
            New ScanningSession instance
        """
        now = datetime.now()
        session_id = cls.generate_session_id()
        session_token = cls.generate_session_token()
        expires_at = now + timedelta(minutes=session_duration_minutes)

        return cls(
            session_id=session_id,
            session_token=session_token,
            operator=operator,
            branch=branch,
            created_at=now,
            expires_at=expires_at,
        )

    @staticmethod
    def generate_session_id() -> str:
        """Generate unique session ID"""
        return str(uuid.uuid4())

    @staticmethod
    def generate_session_token() -> str:
        """Generate secure session token"""
        # Generate cryptographically secure random token
        import base64
        import secrets

        # 32 bytes = 256 bits of entropy
        random_bytes = secrets.token_bytes(32)
        # Base64 encode for safe string representation
        token = base64.urlsafe_b64encode(random_bytes).decode("ascii")
        # Remove padding
        return token.rstrip("=")

    def is_active(self) -> bool:
        """
        Check if session is currently active

        Returns:
            True if session is active and not expired
        """
        if self.status != SessionStatus.ACTIVE:
            return False

        now = datetime.now()
        if now >= self.expires_at:
            self.status = SessionStatus.EXPIRED
            return False

        return True

    def is_expired(self) -> bool:
        """
        Check if session has expired

        Returns:
            True if session has expired
        """
        return datetime.now() >= self.expires_at or self.status == SessionStatus.EXPIRED

    def time_until_expiry(self) -> timedelta:
        """
        Get time remaining until session expires

        Returns:
            Time until expiry, or zero if already expired
        """
        if self.is_expired():
            return timedelta(0)
        return self.expires_at - datetime.now()

    def idle_duration(self) -> timedelta:
        """
        Get duration since last activity

        Returns:
            Time since last activity
        """
        return datetime.now() - self.last_activity_at

    def add_document(self, document: Document) -> None:
        """
        Add document to session

        Args:
            document: Document to add
        """
        if not self.is_active():
            raise RuntimeError("Cannot add document to inactive session")

        self.documents.append(document)
        self.add_activity(
            ActivityType.SCAN_DOCUMENT,
            {
                "document_id": document.document_id,
                "file_size": document.file_size,
                "format": document.format.value,
            },
        )

    def add_activity(
        self, activity_type: ActivityType, details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add activity to session

        Args:
            activity_type: Type of activity
            details: Activity details
        """
        now = datetime.now()
        activity = SessionActivity(activity_type, now, details)
        self.activities.append(activity)
        self.last_activity_at = now

    def extend_expiry(self, additional_minutes: int = 60) -> datetime:
        """
        Extend session expiry time

        Args:
            additional_minutes: Minutes to add to expiry

        Returns:
            New expiry time
        """
        if not self.is_active():
            raise RuntimeError("Cannot extend expired or terminated session")

        self.expires_at += timedelta(minutes=additional_minutes)
        self.add_activity(
            ActivityType.SESSION_REFRESH,
            {
                "extended_minutes": additional_minutes,
                "new_expiry": self.expires_at.isoformat(),
            },
        )

        return self.expires_at

    def refresh_token(self) -> str:
        """
        Generate new session token (for security)

        Returns:
            New session token
        """
        if not self.is_active():
            raise RuntimeError("Cannot refresh token for inactive session")

        old_token = self.session_token
        self.session_token = self.generate_session_token()

        self.add_activity(
            ActivityType.SESSION_REFRESH,
            {"token_refreshed": True, "old_token_prefix": old_token[:8] + "..."},
        )

        return self.session_token

    def terminate(self, reason: str = "logout") -> None:
        """
        Terminate session

        Args:
            reason: Termination reason
        """
        self.status = SessionStatus.TERMINATED
        self.add_activity(ActivityType.LOGOUT, {"reason": reason})

    def get_document_count(self) -> int:
        """Get number of documents in session"""
        return len(self.documents)

    def get_completed_document_count(self) -> int:
        """Get number of completed documents"""
        return len([d for d in self.documents if d.is_processing_complete()])

    def get_failed_document_count(self) -> int:
        """Get number of failed documents"""
        return len([d for d in self.documents if d.status.value == "failed"])

    def get_processing_statistics(self) -> Dict[str, Any]:
        """
        Get session processing statistics

        Returns:
            Dictionary with processing stats
        """
        total_docs = self.get_document_count()
        completed_docs = self.get_completed_document_count()
        failed_docs = self.get_failed_document_count()

        # Calculate total processing time
        total_processing_time = sum(
            d.processing_time for d in self.documents if d.processing_time is not None
        )

        # Calculate average processing time
        avg_processing_time = (
            total_processing_time / total_docs if total_docs > 0 else 0
        )

        # Calculate success rate
        success_rate = completed_docs / total_docs if total_docs > 0 else 1.0

        return {
            "total_documents": total_docs,
            "completed_documents": completed_docs,
            "failed_documents": failed_docs,
            "success_rate": success_rate,
            "total_processing_time": total_processing_time,
            "average_processing_time": avg_processing_time,
            "session_duration": (datetime.now() - self.created_at).total_seconds(),
        }

    def get_recent_activities(self, limit: int = 10) -> List[SessionActivity]:
        """
        Get recent session activities

        Args:
            limit: Maximum number of activities to return

        Returns:
            List of recent activities
        """
        return sorted(self.activities, key=lambda a: a.timestamp, reverse=True)[:limit]

    def cleanup(self) -> None:
        """
        Clean up session resources

        Removes temporary files from all documents
        """
        for document in self.documents:
            document.cleanup_files()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert session to dictionary representation

        Returns:
            Dictionary with session data
        """
        return {
            "session_id": self.session_id,
            "session_token": self.session_token,
            "operator": self.operator,
            "branch": self.branch,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_activity_at": self.last_activity_at.isoformat(),
            "status": self.status.value,
            "documents": [doc.to_dict() for doc in self.documents],
            "activities": [activity.to_dict() for activity in self.activities],
            "processing_stats": self.get_processing_statistics(),
            "metadata": self.metadata.copy(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanningSession":
        """
        Create session from dictionary representation

        Args:
            data: Dictionary with session data

        Returns:
            ScanningSession instance
        """
        created_at = datetime.fromisoformat(data["created_at"])
        expires_at = datetime.fromisoformat(data["expires_at"])
        last_activity_at = datetime.fromisoformat(data["last_activity_at"])

        session = cls(
            session_id=data["session_id"],
            session_token=data["session_token"],
            operator=data["operator"],
            branch=data["branch"],
            created_at=created_at,
            expires_at=expires_at,
        )

        # Set fields
        session.last_activity_at = last_activity_at
        session.status = SessionStatus(data["status"])
        session.metadata = data.get("metadata", {}).copy()

        # Restore documents
        session.documents = []
        for doc_data in data.get("documents", []):
            from .document import Document

            document = Document.from_dict(doc_data)
            session.documents.append(document)

        # Restore activities (skip login activity from constructor)
        session.activities = []
        for activity_data in data.get("activities", []):
            activity = SessionActivity.from_dict(activity_data)
            session.activities.append(activity)

        return session

    def __str__(self) -> str:
        """String representation"""
        return f"ScanningSession(id={self.session_id[:8]}, operator={self.operator}, status={self.status.value})"

    def __repr__(self) -> str:
        """Detailed string representation"""
        return (
            f"ScanningSession(session_id='{self.session_id}', "
            f"operator='{self.operator}', branch='{self.branch}', "
            f"status={self.status.value}, documents={len(self.documents)})"
        )

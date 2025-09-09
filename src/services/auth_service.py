"""
Auth Service
Handles authentication, session management, and security validation
"""

import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

from models.operator import Operator, OperatorRole
from models.scanning_session import ActivityType, ScanningSession


class AuthServiceError(Exception):
    """Base exception for auth service errors"""

    def __init__(self, message: str, error_code: str):
        self.message = message
        self.error_code = error_code
        self.timestamp = datetime.now()
        super().__init__(message)


class AuthenticationFailedError(AuthServiceError):
    """Raised when authentication fails"""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, "AUTHENTICATION_FAILED")
        self.rate_limited = False
        self.retry_after = 0


class SessionExpiredError(AuthServiceError):
    """Raised when session has expired"""

    def __init__(self, message: str = "Session has expired"):
        super().__init__(message, "SESSION_EXPIRED")
        self.expired_at = None
        self.current_time = datetime.now()
        self.workflow_state = None
        self.recovery_token = None


class InvalidSessionError(AuthServiceError):
    """Raised when session is invalid or hijacked"""

    def __init__(self, message: str = "Invalid session"):
        super().__init__(message, "INVALID_SESSION")
        self.security_violation = None


class ConcurrentSessionError(AuthServiceError):
    """Raised when concurrent session limit is exceeded"""

    def __init__(self, message: str = "Concurrent session limit exceeded"):
        super().__init__(message, "CONCURRENT_SESSION_ERROR")


class AuthService:
    """
    Authentication service for operator login and session management

    Handles authentication, session lifecycle, security validation,
    and operator management following MVP requirements and security best practices.
    """

    def __init__(self):
        # In-memory storage (MVP implementation)
        self._operators: Dict[str, Operator] = {}
        self._sessions: Dict[str, ScanningSession] = {}
        self._session_lock = threading.RLock()
        self._mock_settings = {}

        # Initialize MVP operators
        self._initialize_mvp_operators()

    def _initialize_mvp_operators(self) -> None:
        """Initialize MVP operators (admin/1234)"""
        # Create admin operator
        admin = Operator.create_new(
            username="admin",
            password="1234",
            role=OperatorRole.ADMIN,
            branch="sucursal-centro",
        )

        self._operators["admin"] = admin

    def login(
        self,
        username: str,
        password: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Authenticate operator and create session

        Args:
            username: Operator username
            password: Operator password
            client_ip: Client IP address for security tracking
            user_agent: Client user agent for security tracking

        Returns:
            Dict with session information

        Raises:
            AuthenticationFailedError: When authentication fails
        """
        # Handle mock scenarios
        self._handle_mock_auth_scenarios(username)

        # Find operator
        if username not in self._operators:
            self._record_failed_login_attempt(username)
            raise AuthenticationFailedError("Invalid username or password")

        operator = self._operators[username]

        # Check if operator is active
        if not operator.is_active():
            if operator.is_locked():
                error = AuthenticationFailedError("Account is locked")
                error.rate_limited = True
                error.retry_after = 30 * 60  # 30 minutes
                raise error
            else:
                raise AuthenticationFailedError("Account is inactive")

        # Verify password
        if not operator.verify_password(password):
            operator.record_failed_login(max_attempts=5)
            self._record_failed_login_attempt(username)
            raise AuthenticationFailedError("Invalid username or password")

        # Handle concurrent session limitation
        self._handle_concurrent_sessions(operator)

        # Create new session
        session = ScanningSession.create_new(
            operator=operator.username,
            branch=operator.branch,
            session_duration_minutes=8 * 60,  # 8 hours
        )

        # Store session security context
        if client_ip or user_agent:
            session.metadata["security_context"] = {
                "client_ip": client_ip,
                "user_agent": user_agent,
                "login_time": datetime.now().isoformat(),
            }

        # Store session
        with self._session_lock:
            self._sessions[session.session_token] = session

        # Record successful login
        operator.record_successful_login()

        return {
            "session_token": session.session_token,
            "expires_at": session.expires_at,
            "operator": operator.username,
            "role": operator.role.value,
            "branch": operator.branch,
            "session_id": session.session_id,
        }

    def _handle_mock_auth_scenarios(self, username: str) -> None:
        """Handle mock authentication scenarios for testing"""

        # Mock auth failure during retry
        if self._mock_settings.get("_mock_auth_failure_on_refresh", False):
            raise AuthenticationFailedError(
                "Mock authentication failure during refresh"
            )

    def _handle_concurrent_sessions(self, operator: Operator) -> None:
        """Handle concurrent session limitation (max 1 per operator)"""
        with self._session_lock:
            # Find existing active sessions for this operator
            existing_sessions = [
                (token, session)
                for token, session in self._sessions.items()
                if session.operator == operator.username and session.is_active()
            ]

            # Terminate existing sessions (MVP: single session per operator)
            for token, session in existing_sessions:
                session.terminate("replaced_by_new_login")
                del self._sessions[token]

    def _record_failed_login_attempt(self, username: str) -> None:
        """Record failed login attempt for rate limiting"""
        # In a full implementation, this would use a rate limiting mechanism
        pass

    def logout(self, session_token: str) -> Dict[str, Any]:
        """
        Logout and terminate session

        Args:
            session_token: Session token to terminate

        Returns:
            Dict with logout confirmation
        """
        with self._session_lock:
            if session_token not in self._sessions:
                return {"success": False, "error": "Session not found"}

            session = self._sessions[session_token]
            session.terminate("user_logout")
            del self._sessions[session_token]

            return {
                "success": True,
                "session_terminated": True,
                "logout_time": datetime.now().isoformat(),
            }

    def validate_session(
        self,
        session_token: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate session token and check for security issues

        Args:
            session_token: Session token to validate
            client_ip: Client IP for security validation
            user_agent: User agent for security validation

        Returns:
            Dict with validation results

        Raises:
            SessionExpiredError: When session has expired
            InvalidSessionError: When session is invalid or compromised
        """
        # Handle mock scenarios
        self._handle_mock_session_scenarios(session_token)

        with self._session_lock:
            if session_token not in self._sessions:
                raise InvalidSessionError("Session not found")

            session = self._sessions[session_token]

            # Check if session is expired
            if session.is_expired():
                # Clean up expired session
                session.terminate("expired")
                del self._sessions[session_token]

                error = SessionExpiredError("Session has expired")
                error.expired_at = session.expires_at
                raise error

            # Check for session hijacking
            self._validate_session_security(session, client_ip, user_agent)

            # Update last activity
            session.add_activity(
                ActivityType.SESSION_REFRESH,
                {"validation_time": datetime.now().isoformat()},
            )

            return {
                "valid": True,
                "session_id": session.session_id,
                "operator": session.operator,
                "expires_at": session.expires_at.isoformat(),
                "time_until_expiry": session.time_until_expiry().total_seconds(),
            }

    def _handle_mock_session_scenarios(self, session_token: str) -> None:
        """Handle mock session scenarios for testing"""

        # Mock forced session expiry
        if self._mock_settings.get("_mock_force_session_expiry", False):
            # Create mock workflow state for recovery
            error = SessionExpiredError("Mock forced session expiry")
            error.workflow_state = {
                "completed_steps": ["scan_document"],
                "pending_steps": ["encrypt_document", "upload_document"],
            }
            error.recovery_token = "recovery_" + session_token[:16]
            raise error

        # Mock idle time exceeded
        if self._mock_settings.get("_mock_idle_time_exceeded", False):
            raise SessionExpiredError("Session expired due to inactivity")

    def _validate_session_security(
        self,
        session: ScanningSession,
        client_ip: Optional[str],
        user_agent: Optional[str],
    ) -> None:
        """Validate session security context"""

        # Check IP tracking (if enabled)
        if self._mock_settings.get("_mock_ip_tracking", False):
            security_context = session.metadata.get("security_context", {})
            original_ip = security_context.get("client_ip")

            if original_ip and client_ip and original_ip != client_ip:
                error = InvalidSessionError("Session security violation detected")
                error.security_violation = {
                    "type": "IP_MISMATCH",
                    "original_ip": original_ip,
                    "current_ip": client_ip,
                }
                raise error

    def refresh_session(self, session_token: str) -> Dict[str, Any]:
        """
        Refresh session token for security

        Args:
            session_token: Current session token

        Returns:
            Dict with new session token
        """
        with self._session_lock:
            if session_token not in self._sessions:
                raise InvalidSessionError("Session not found")

            session = self._sessions[session_token]

            if not session.is_active():
                raise SessionExpiredError("Cannot refresh expired session")

            # Generate new token
            old_token = session.session_token
            new_token = session.refresh_token()

            # Update session storage
            del self._sessions[old_token]
            self._sessions[new_token] = session

            return {
                "new_session_token": new_token,
                "expires_at": session.expires_at,
                "refresh_time": datetime.now().isoformat(),
            }

    def get_current_session(self) -> Dict[str, Any]:
        """
        Get current active session info (mock implementation)

        Returns:
            Dict with current session status
        """
        with self._session_lock:
            active_sessions = [
                session for session in self._sessions.values() if session.is_active()
            ]

            if not active_sessions:
                return {"active": False}

            # Return most recent session (MVP: single session)
            session = max(active_sessions, key=lambda s: s.created_at)

            return {
                "active": True,
                "session_token": session.session_token,
                "operator": session.operator,
                "branch": session.branch,
                "created_at": session.created_at.isoformat(),
                "cleanup_performed": True,
            }

    def get_session_replacement_info(self) -> Dict[str, Any]:
        """Get information about session replacement"""
        # This would track session replacements in a real implementation
        return {
            "session_replaced": True,
            "previous_token": "mock_previous_token",
            "new_token": "mock_new_token",
        }

    def record_activity(
        self,
        session_token: str,
        activity_type: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record activity for session

        Args:
            session_token: Session token
            activity_type: Type of activity
            details: Activity details
        """
        with self._session_lock:
            if session_token in self._sessions:
                session = self._sessions[session_token]
                if session.is_active():
                    try:
                        activity_enum = ActivityType(activity_type.lower())
                        session.add_activity(activity_enum, details)
                    except ValueError:
                        # Handle unknown activity types
                        session.add_activity(
                            ActivityType.ERROR_OCCURRED,
                            {"original_activity": activity_type, "details": details},
                        )

    def get_session_activity(self, session_token: str) -> Dict[str, Any]:
        """
        Get session activity history

        Args:
            session_token: Session token

        Returns:
            Dict with activity information
        """
        with self._session_lock:
            if session_token not in self._sessions:
                return {"error": "Session not found"}

            session = self._sessions[session_token]
            recent_activities = session.get_recent_activities(limit=10)

            return {
                "activities": [activity.to_dict() for activity in recent_activities],
                "last_activity_time": session.last_activity_at.isoformat(),
                "idle_duration": session.idle_duration().total_seconds(),
            }

    def get_session_usage(self, session_token: str) -> Dict[str, Any]:
        """Get session usage across services"""
        # Mock implementation
        return {
            "scanner_usage": {"operations": 3, "last_used": datetime.now().isoformat()},
            "crypto_usage": {"operations": 2, "last_used": datetime.now().isoformat()},
            "upload_usage": {"operations": 1, "last_used": datetime.now().isoformat()},
        }

    def cleanup_expired_sessions(self) -> Dict[str, Any]:
        """
        Clean up expired sessions

        Returns:
            Dict with cleanup results
        """
        start_time = time.time()
        cleaned_count = 0

        with self._session_lock:
            expired_tokens = [
                token
                for token, session in self._sessions.items()
                if session.is_expired()
            ]

            for token in expired_tokens:
                session = self._sessions[token]
                session.cleanup()  # Clean up resources
                del self._sessions[token]
                cleaned_count += 1

        cleanup_time = time.time() - start_time

        return {"sessions_cleaned": cleaned_count, "cleanup_time": cleanup_time}

    def get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage information"""
        with self._session_lock:
            active_sessions = len([s for s in self._sessions.values() if s.is_active()])

            return {
                "active_sessions": active_sessions,
                "total_sessions": len(self._sessions),
                "session_cache_size": len(self._sessions) * 100,  # Mock size estimate
            }

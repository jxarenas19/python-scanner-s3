"""
Integration tests for Session Management
Tests authentication sessions, timeouts, token refresh, and concurrent sessions

⚠️ TDD CRITICAL: These tests MUST FAIL before implementation exists
"""

import pytest
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from pathlib import Path

from services.auth_service import AuthService
from services.scanner_service import ScannerService
from services.crypto_service import CryptoService
from services.upload_service import UploadService
from services.auth_service import (
    AuthenticationFailedError,
    SessionExpiredError,
    InvalidSessionError,
    ConcurrentSessionError
)


class TestSessionLifecycleManagement:
    """Integration tests for complete session lifecycle"""
    
    @pytest.fixture
    def auth_service(self):
        """Fixture providing auth service instance"""
        return AuthService()
    
    @pytest.fixture
    def scanner_service(self):
        return ScannerService()
    
    @pytest.fixture
    def crypto_service(self):
        return CryptoService()
    
    @pytest.fixture
    def upload_service(self):
        return UploadService()
    
    def test_complete_session_lifecycle(self, auth_service):
        """
        Test complete session lifecycle: login → activity → timeout → refresh → logout
        
        Contract: Should manage full session lifecycle correctly
        """
        # Act 1: Login - This MUST FAIL because login method doesn't exist
        login_result = auth_service.login("admin", "1234")
        
        # Assert: Successful login
        assert isinstance(login_result, dict)
        assert "session_token" in login_result
        assert "expires_at" in login_result
        assert "operator" in login_result
        
        token = login_result["session_token"]
        assert len(token) > 0
        assert isinstance(login_result["expires_at"], datetime)
        assert login_result["operator"] == "admin"
        
        # Act 2: Session activity
        session_info = auth_service.get_current_session()
        
        # Assert: Active session
        assert session_info["active"] is True
        assert session_info["session_token"] == token
        
        # Act 3: Mock session near expiry
        auth_service._mock_session_near_expiry = True
        
        # Act 4: Refresh session
        refresh_result = auth_service.refresh_session(token)
        
        # Assert: Successful refresh
        assert isinstance(refresh_result, dict)
        assert "new_session_token" in refresh_result
        assert "expires_at" in refresh_result
        
        new_token = refresh_result["new_session_token"]
        assert new_token != token  # Should be new token
        
        # Act 5: Logout
        logout_result = auth_service.logout(new_token)
        
        # Assert: Successful logout
        assert logout_result["success"] is True
        assert logout_result["session_terminated"] is True
        
        # Session should no longer be active
        final_session = auth_service.get_current_session()
        assert final_session["active"] is False
    
    def test_session_timeout_handling(self, auth_service):
        """
        Test automatic session timeout and cleanup
        
        Contract: Should automatically invalidate expired sessions
        """
        # Arrange - Mock short session timeout (5 minutes)
        auth_service._mock_session_timeout = 300  # 5 minutes
        
        # Act 1: Login
        login_result = auth_service.login("admin", "1234")
        token = login_result["session_token"]
        
        # Act 2: Mock time advancement past expiry
        auth_service._mock_time_advance = 400  # 6+ minutes
        
        # Act 3: Try to use expired session
        with pytest.raises(SessionExpiredError) as exc_info:
            auth_service.validate_session(token)
        
        # Assert: Should detect expired session
        error = exc_info.value
        assert error.error_code == "SESSION_EXPIRED"
        assert hasattr(error, 'expired_at')
        assert hasattr(error, 'current_time')
        
        # Session should be automatically cleaned up
        session_info = auth_service.get_current_session()
        assert session_info["active"] is False
        assert session_info.get("cleanup_performed") is True
    
    def test_concurrent_session_limitation(self, auth_service):
        """
        Test concurrent session limitation (max 1 per operator)
        
        Contract: Should enforce single active session per operator
        """
        # Act 1: First login
        first_login = auth_service.login("admin", "1234")
        first_token = first_login["session_token"]
        
        # Verify first session is active
        assert auth_service.validate_session(first_token)["valid"] is True
        
        # Act 2: Second login attempt (should invalidate first)
        second_login = auth_service.login("admin", "1234")
        second_token = second_login["session_token"]
        
        # Assert: Second session should be active, first should be invalid
        assert second_token != first_token
        assert auth_service.validate_session(second_token)["valid"] is True
        
        # First token should now be invalid
        with pytest.raises(InvalidSessionError):
            auth_service.validate_session(first_token)
        
        # Should have session replacement info
        replacement_info = auth_service.get_session_replacement_info()
        assert replacement_info["session_replaced"] is True
        assert replacement_info["previous_token"] == first_token
        assert replacement_info["new_token"] == second_token
    
    def test_session_activity_tracking(self, auth_service):
        """
        Test session activity tracking and idle timeout
        
        Contract: Should track activity and handle idle timeouts
        """
        # Arrange
        auth_service._mock_idle_timeout = 600  # 10 minutes idle
        
        # Act 1: Login
        login_result = auth_service.login("admin", "1234")
        token = login_result["session_token"]
        
        # Act 2: Record activity
        auth_service.record_activity(token, "SCAN_DOCUMENT")
        auth_service.record_activity(token, "ENCRYPT_DOCUMENT")
        
        # Act 3: Get activity history
        activity = auth_service.get_session_activity(token)
        
        # Assert: Should track activities
        assert isinstance(activity, dict)
        assert "activities" in activity
        assert "last_activity_time" in activity
        assert "idle_duration" in activity
        
        activities = activity["activities"]
        assert len(activities) >= 2
        assert any(act["action"] == "SCAN_DOCUMENT" for act in activities)
        assert any(act["action"] == "ENCRYPT_DOCUMENT" for act in activities)
        
        # Mock idle time exceeded
        auth_service._mock_idle_time_exceeded = True
        
        # Should detect idle timeout
        with pytest.raises(SessionExpiredError) as exc_info:
            auth_service.validate_session(token)
        
        error = exc_info.value
        assert "idle" in error.message.lower()


class TestSessionIntegrationWithServices:
    """Integration tests for sessions across all services"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    @pytest.fixture  
    def scanner_service(self):
        return ScannerService()
    
    @pytest.fixture
    def crypto_service(self):
        return CryptoService()
    
    @pytest.fixture
    def upload_service(self):
        return UploadService()
    
    def test_cross_service_session_validation(self, auth_service, scanner_service, crypto_service, upload_service):
        """
        Test session validation across all services
        
        Contract: All services should validate sessions consistently
        """
        # Act 1: Login
        login_result = auth_service.login("admin", "1234")
        token = login_result["session_token"]
        
        # Act 2: Use session across services
        # Scanner service should validate session
        scan_result = scanner_service.scan_document(session_token=token)
        assert isinstance(scan_result, dict)
        assert "document_path" in scan_result
        
        # Crypto service should validate session
        crypto_result = crypto_service.encrypt_document(
            file_path=scan_result["document_path"],
            operator="admin",
            timestamp=datetime.now(),
            branch="sucursal-centro",
            session_token=token
        )
        assert isinstance(crypto_result, dict)
        assert "encrypted_path" in crypto_result
        
        # Upload service should validate session
        upload_result = upload_service.upload_encrypted_document(
            encrypted_file_path=crypto_result["encrypted_path"],
            operator="admin",
            branch="sucursal-centro",
            timestamp=datetime.now(),
            session_token=token
        )
        assert isinstance(upload_result, dict)
        assert "s3_url" in upload_result
        
        # All services should record the same session usage
        session_usage = auth_service.get_session_usage(token)
        assert "scanner_usage" in session_usage
        assert "crypto_usage" in session_usage  
        assert "upload_usage" in session_usage
    
    def test_session_expiry_during_workflow(self, auth_service, scanner_service, crypto_service):
        """
        Test session expiry during multi-step workflow
        
        Contract: Should handle mid-workflow session expiry gracefully
        """
        # Arrange - Short session timeout
        auth_service._mock_session_timeout = 10  # 10 seconds
        
        # Act 1: Login
        login_result = auth_service.login("admin", "1234")
        token = login_result["session_token"]
        
        # Act 2: Scan document (should work)
        scan_result = scanner_service.scan_document(session_token=token)
        
        # Act 3: Mock session expiry
        auth_service._mock_force_session_expiry = True
        
        # Act 4: Try crypto operation (should fail with session expired)
        with pytest.raises(SessionExpiredError) as exc_info:
            crypto_service.encrypt_document(
                file_path=scan_result["document_path"],
                operator="admin",
                timestamp=datetime.now(),
                branch="sucursal-centro",
                session_token=token
            )
        
        # Assert: Should provide workflow recovery info
        error = exc_info.value
        assert hasattr(error, 'workflow_state')
        assert hasattr(error, 'recovery_token')
        
        workflow_state = error.workflow_state
        assert "completed_steps" in workflow_state
        assert "pending_steps" in workflow_state
        assert "scan_document" in workflow_state["completed_steps"]
        assert "encrypt_document" in workflow_state["pending_steps"]
    
    def test_automatic_session_renewal_during_workflow(self, auth_service, scanner_service, crypto_service):
        """
        Test automatic session renewal during long workflows
        
        Contract: Should automatically renew sessions during active workflows
        """
        # Arrange - Enable automatic renewal
        auth_service._mock_auto_renewal_enabled = True
        auth_service._mock_session_timeout = 30  # 30 seconds
        
        # Act 1: Login
        login_result = auth_service.login("admin", "1234")
        initial_token = login_result["session_token"]
        
        # Act 2: Long workflow simulation
        scan_result = scanner_service.scan_document(session_token=initial_token)
        
        # Mock time advancement to trigger renewal
        auth_service._mock_time_advance = 25  # Near expiry
        
        # Act 3: Continue workflow (should auto-renew)
        crypto_result = crypto_service.encrypt_document(
            file_path=scan_result["document_path"],
            operator="admin",
            timestamp=datetime.now(),
            branch="sucursal-centro",
            session_token=initial_token
        )
        
        # Assert: Should succeed with renewed session
        assert isinstance(crypto_result, dict)
        assert "session_renewed" in crypto_result
        assert crypto_result["session_renewed"] is True
        
        # Should have new token info
        current_session = auth_service.get_current_session()
        assert current_session["session_token"] != initial_token
        assert current_session["renewal_count"] == 1


class TestSessionSecurityValidation:
    """Integration tests for session security aspects"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    def test_session_token_security_validation(self, auth_service):
        """
        Test session token security characteristics
        
        Contract: Session tokens should meet security requirements
        """
        # Act: Generate multiple sessions
        tokens = []
        for _ in range(5):
            login_result = auth_service.login("admin", "1234")
            tokens.append(login_result["session_token"])
        
        # Assert: Token security properties
        for token in tokens:
            # Should be sufficiently long
            assert len(token) >= 32, f"Token too short: {len(token)} chars"
            
            # Should contain mixed characters (entropy check)
            assert any(c.isupper() for c in token), "No uppercase chars"
            assert any(c.islower() for c in token), "No lowercase chars"
            assert any(c.isdigit() for c in token), "No digits"
            
            # Should not contain operator info
            assert "admin" not in token.lower()
        
        # All tokens should be unique
        assert len(set(tokens)) == len(tokens), "Non-unique tokens generated"
    
    def test_session_hijacking_protection(self, auth_service):
        """
        Test protection against session hijacking attempts
        
        Contract: Should detect and prevent session hijacking
        """
        # Arrange
        auth_service._mock_ip_tracking = True
        auth_service._mock_user_agent_tracking = True
        
        # Act 1: Normal login
        login_result = auth_service.login("admin", "1234", 
                                        client_ip="192.168.1.100",
                                        user_agent="ScannerApp/1.0")
        token = login_result["session_token"]
        
        # Act 2: Validate from same context (should work)
        validation1 = auth_service.validate_session(token,
                                                  client_ip="192.168.1.100",
                                                  user_agent="ScannerApp/1.0")
        assert validation1["valid"] is True
        
        # Act 3: Validate from different IP (should fail)
        with pytest.raises(InvalidSessionError) as exc_info:
            auth_service.validate_session(token,
                                        client_ip="192.168.1.200",  # Different IP
                                        user_agent="ScannerApp/1.0")
        
        error = exc_info.value
        assert error.error_code == "SESSION_HIJACK_DETECTED"
        assert hasattr(error, 'security_violation')
        assert error.security_violation["type"] == "IP_MISMATCH"
    
    def test_brute_force_protection(self, auth_service):
        """
        Test protection against brute force login attempts
        
        Contract: Should implement rate limiting and account lockout
        """
        # Act: Multiple failed login attempts
        failed_attempts = 0
        for attempt in range(10):
            try:
                auth_service.login("admin", f"wrong_password_{attempt}")
            except AuthenticationFailedError as e:
                failed_attempts += 1
                
                # After 5 attempts, should get rate limiting
                if failed_attempts >= 5:
                    assert hasattr(e, 'rate_limited')
                    assert e.rate_limited is True
                    assert hasattr(e, 'retry_after')
                    assert e.retry_after > 0
        
        # Account should be temporarily locked
        with pytest.raises(AuthenticationFailedError) as exc_info:
            auth_service.login("admin", "1234")  # Correct password
        
        error = exc_info.value
        assert "account locked" in error.message.lower()
        assert hasattr(error, 'lockout_expires_at')


class TestSessionPerformanceAndScaling:
    """Performance tests for session management"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    def test_concurrent_session_operations_performance(self, auth_service):
        """
        Test performance of concurrent session operations
        
        Contract: Should handle multiple concurrent sessions efficiently
        """
        # Arrange
        num_concurrent_operations = 20
        results = []
        
        def session_operation(operation_id):
            try:
                # Login
                login_result = auth_service.login(f"operator{operation_id}", "1234")
                token = login_result["session_token"]
                
                # Multiple validations
                for _ in range(5):
                    auth_service.validate_session(token)
                    auth_service.record_activity(token, "TEST_OPERATION")
                
                # Logout
                auth_service.logout(token)
                results.append(("success", operation_id))
                
            except Exception as e:
                results.append(("failed", operation_id, e))
        
        # Act: Run concurrent operations
        start_time = time.time()
        
        threads = []
        for i in range(num_concurrent_operations):
            thread = threading.Thread(target=session_operation, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join(timeout=30)
        
        elapsed_time = time.time() - start_time
        
        # Assert: Performance requirements
        assert elapsed_time < 10, f"Concurrent operations too slow: {elapsed_time}s"
        
        # All operations should succeed
        successful_ops = [r for r in results if r[0] == "success"]
        assert len(successful_ops) == num_concurrent_operations
        
        # No failed operations
        failed_ops = [r for r in results if r[0] == "failed"]
        assert len(failed_ops) == 0, f"Failed operations: {failed_ops}"
    
    def test_session_cleanup_performance(self, auth_service):
        """
        Test performance of session cleanup operations
        
        Contract: Should efficiently clean up expired sessions
        """
        # Arrange: Create many expired sessions
        auth_service._mock_session_timeout = 1  # 1 second timeout
        
        # Create 100 sessions
        for i in range(100):
            auth_service.login(f"temp_operator{i}", "1234")
        
        # Wait for expiry
        time.sleep(2)
        
        # Act: Trigger cleanup
        start_time = time.time()
        cleanup_result = auth_service.cleanup_expired_sessions()
        elapsed_time = time.time() - start_time
        
        # Assert: Should be efficient
        assert elapsed_time < 5, f"Cleanup too slow: {elapsed_time}s"
        assert cleanup_result["sessions_cleaned"] == 100
        assert cleanup_result["cleanup_time"] < 5
        
        # Memory usage should be reduced
        memory_usage = auth_service.get_memory_usage()
        assert memory_usage["active_sessions"] == 0
        assert memory_usage["session_cache_size"] < 1000  # Reasonable cache size
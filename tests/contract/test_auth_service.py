"""
Contract tests for Auth Service
Tests the auth service API contract according to contracts/auth_service.yaml

⚠️ TDD CRITICAL: These tests MUST FAIL before implementation exists
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock

from services.auth_service import AuthService
from services.auth_service import (
    InvalidCredentialsError,
    SessionExpiredError,
    TooManyAttemptsError,
    UnauthorizedError,
    SessionNotFoundError
)


class TestAuthServiceContract:
    """Contract tests for Auth Service based on OpenAPI spec"""
    
    @pytest.fixture
    def auth_service(self):
        """Fixture providing auth service instance"""
        return AuthService()
    
    @pytest.fixture
    def valid_credentials(self):
        """Fixture providing valid MVP credentials"""
        return {
            "username": "admin",
            "password": "1234"
        }
    
    @pytest.fixture
    def invalid_credentials(self):
        """Fixture providing invalid credentials"""
        return {
            "username": "invalid_user",
            "password": "wrong_password"
        }
    
    def test_authenticate_operator_success(self, auth_service, valid_credentials):
        """
        Test POST /auth/login - Success case
        
        Contract: Should return success=True, operator details, login_time
        when authentication succeeds with valid MVP credentials
        """
        # Act - This MUST FAIL because authenticate_operator method doesn't exist yet
        result = auth_service.authenticate_operator(
            username=valid_credentials["username"],
            password=valid_credentials["password"]
        )
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        required_fields = ["success", "operator", "login_time"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Validate success
        success = result["success"]
        assert success is True
        
        # Validate operator object
        operator = result["operator"]
        assert isinstance(operator, dict)
        
        operator_required_fields = ["username", "display_name", "branch_access", "session_expires"]
        for field in operator_required_fields:
            assert field in operator, f"Missing operator field: {field}"
        
        # Validate operator fields
        assert operator["username"] == "admin"
        assert isinstance(operator["display_name"], str)
        assert len(operator["display_name"]) > 0
        
        # Validate branch_access
        branch_access = operator["branch_access"]
        assert isinstance(branch_access, list)
        expected_branches = ["sucursal-centro", "sucursal-norte", "sucursal-sur"]
        for branch in expected_branches:
            assert branch in branch_access
        
        # Validate session_expires
        session_expires = operator["session_expires"]
        assert isinstance(session_expires, datetime)
        # Should expire 8 hours from login
        now = datetime.now()
        time_diff = session_expires - now
        assert 7.5 * 3600 <= time_diff.total_seconds() <= 8.5 * 3600  # Allow some margin
        
        # Validate login_time
        login_time = result["login_time"]
        assert isinstance(login_time, datetime)
        # Should be recent (within last minute)
        time_diff = now - login_time
        assert time_diff.total_seconds() < 60
    
    def test_authenticate_operator_invalid_credentials(self, auth_service, invalid_credentials):
        """
        Test POST /auth/login - Invalid credentials error (401)
        
        Contract: Should raise InvalidCredentialsError for wrong username/password
        """
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(InvalidCredentialsError) as exc_info:
            auth_service.authenticate_operator(
                username=invalid_credentials["username"],
                password=invalid_credentials["password"]
            )
        
        # Validate exception contract
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        
        assert error.error_code == "INVALID_CREDENTIALS"
        assert "invalid" in error.message.lower()
        assert "username" in error.message.lower() or "password" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
    
    def test_authenticate_operator_too_many_attempts(self, auth_service):
        """
        Test POST /auth/login - Too many attempts error (429)
        
        Contract: Should raise TooManyAttemptsError after multiple failed attempts
        """
        # Arrange - Mock too many failed attempts scenario
        auth_service._mock_too_many_attempts = True
        
        # Act & Assert - This MUST FAIL because exception classes don't exist yet
        with pytest.raises(TooManyAttemptsError) as exc_info:
            auth_service.authenticate_operator(
                username="admin",
                password="wrong_password"
            )
        
        # Validate exception contract
        error = exc_info.value
        assert hasattr(error, 'error_code')
        assert hasattr(error, 'message')
        assert hasattr(error, 'timestamp')
        assert hasattr(error, 'retry_after')
        
        assert error.error_code == "TOO_MANY_ATTEMPTS"
        assert "too many" in error.message.lower()
        assert isinstance(error.timestamp, datetime)
        assert isinstance(error.retry_after, int)
        assert error.retry_after > 0  # Should specify wait time
    
    def test_check_session_status_valid(self, auth_service, valid_credentials):
        """
        Test GET /auth/session - Valid session
        
        Contract: Should return valid=True, operator details, expires_at, time_remaining
        for active sessions
        """
        # Arrange - First authenticate to create a session
        auth_result = auth_service.authenticate_operator(**valid_credentials)
        
        # Act - This MUST FAIL because check_session_status method doesn't exist yet
        result = auth_service.check_session_status()
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        required_fields = ["valid", "expires_at"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Validate valid flag
        assert result["valid"] is True
        
        # Validate expires_at
        expires_at = result["expires_at"]
        assert isinstance(expires_at, datetime)
        # Should match the session_expires from login
        expected_expires = auth_result["operator"]["session_expires"]
        assert abs((expires_at - expected_expires).total_seconds()) < 10  # Allow small margin
        
        # Optional fields validation
        if "operator" in result:
            operator = result["operator"]
            assert operator["username"] == "admin"
        
        if "time_remaining" in result:
            time_remaining = result["time_remaining"]
            assert isinstance(time_remaining, int)
            assert time_remaining > 0
            # Should be reasonable (close to 8 hours in minutes)
            assert 450 <= time_remaining <= 480  # 7.5-8 hours in minutes
    
    def test_check_session_status_expired(self, auth_service):
        """
        Test GET /auth/session - Expired session
        
        Contract: Should return valid=False for expired sessions
        """
        # Arrange - Mock expired session
        auth_service._mock_expired_session = True
        
        # Act
        result = auth_service.check_session_status()
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        assert result["valid"] is False
        
        # Should still have expires_at for expired sessions
        assert "expires_at" in result
        expires_at = result["expires_at"]
        assert isinstance(expires_at, datetime)
        # Should be in the past
        assert expires_at < datetime.now()
    
    def test_logout_operator_success(self, auth_service, valid_credentials):
        """
        Test POST /auth/logout - Success case
        
        Contract: Should return success=True, logout_time when logout succeeds
        """
        # Arrange - First authenticate
        auth_service.authenticate_operator(**valid_credentials)
        
        # Act - This MUST FAIL because logout_operator method doesn't exist yet
        result = auth_service.logout_operator()
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        required_fields = ["success", "logout_time"]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Validate success
        assert result["success"] is True
        
        # Validate logout_time
        logout_time = result["logout_time"]
        assert isinstance(logout_time, datetime)
        # Should be recent
        now = datetime.now()
        time_diff = now - logout_time
        assert time_diff.total_seconds() < 10
    
    def test_get_available_branches_success(self, auth_service, valid_credentials):
        """
        Test GET /auth/branches - Success case
        
        Contract: Should return branches list for authenticated operator
        """
        # Arrange - First authenticate
        auth_service.authenticate_operator(**valid_credentials)
        
        # Act - This MUST FAIL because get_available_branches method doesn't exist yet
        result = auth_service.get_available_branches()
        
        # Assert - Contract validation
        assert isinstance(result, dict)
        
        # Required fields from contract
        assert "branches" in result
        
        # Validate branches
        branches = result["branches"]
        assert isinstance(branches, list)
        assert len(branches) == 3  # MVP has 3 branches
        
        # Validate branch structure
        expected_branches = [
            {"code": "centro", "display_name": "Sucursal Centro", "s3_path_segment": "sucursal-centro"},
            {"code": "norte", "display_name": "Sucursal Norte", "s3_path_segment": "sucursal-norte"},
            {"code": "sur", "display_name": "Sucursal Sur", "s3_path_segment": "sucursal-sur"}
        ]
        
        for expected_branch in expected_branches:
            # Find matching branch in result
            matching_branch = next(
                (b for b in branches if b["code"] == expected_branch["code"]), 
                None
            )
            assert matching_branch is not None, f"Missing branch: {expected_branch['code']}"
            
            # Validate branch fields
            branch_required_fields = ["code", "display_name", "s3_path_segment"]
            for field in branch_required_fields:
                assert field in matching_branch, f"Missing branch field: {field}"
            
            assert matching_branch["display_name"] == expected_branch["display_name"]
            assert matching_branch["s3_path_segment"] == expected_branch["s3_path_segment"]
    
    def test_get_available_branches_unauthorized(self, auth_service):
        """
        Test GET /auth/branches - Unauthorized error (401)
        
        Contract: Should raise UnauthorizedError when not authenticated
        """
        # Act & Assert - No authentication, should fail
        with pytest.raises(UnauthorizedError) as exc_info:
            auth_service.get_available_branches()
        
        # Validate exception contract
        error = exc_info.value
        assert error.error_code == "UNAUTHORIZED"
        assert "not authenticated" in error.message.lower() or "unauthorized" in error.message.lower()
        assert isinstance(error.timestamp, datetime)


class TestAuthServiceContractValidation:
    """Additional contract validation tests"""
    
    def test_auth_service_has_required_methods(self):
        """
        Validate that AuthService implements required contract methods
        
        This MUST FAIL because AuthService class doesn't exist yet
        """
        # This will fail with ImportError - expected in RED phase
        auth_service = AuthService()
        
        # Validate required methods exist
        required_methods = [
            'authenticate_operator',
            'check_session_status', 
            'logout_operator',
            'get_available_branches'
        ]
        
        for method_name in required_methods:
            assert hasattr(auth_service, method_name), f"Missing method: {method_name}"
            assert callable(getattr(auth_service, method_name))
    
    def test_auth_exceptions_exist(self):
        """
        Validate that required exception classes exist
        
        This MUST FAIL because exception classes don't exist yet
        """
        # These imports will fail - expected in RED phase
        from services.auth_service import (
            InvalidCredentialsError,
            SessionExpiredError,
            TooManyAttemptsError,
            UnauthorizedError,
            SessionNotFoundError
        )
        
        # Validate exception hierarchy
        exception_classes = [
            InvalidCredentialsError, 
            SessionExpiredError, 
            TooManyAttemptsError,
            UnauthorizedError, 
            SessionNotFoundError
        ]
        
        for exc_class in exception_classes:
            assert issubclass(exc_class, Exception)
            
            # Validate exceptions have required attributes
            error = exc_class("test message")
            assert hasattr(error, 'error_code')
            assert hasattr(error, 'message')
            assert hasattr(error, 'timestamp')
    
    def test_mvp_credential_validation(self, auth_service):
        """
        Test MVP credential validation
        
        Contract: Only "admin/1234" should be valid in MVP
        """
        # Valid MVP credentials
        result = auth_service.authenticate_operator("admin", "1234")
        assert result["success"] is True
        
        # Invalid credentials should fail
        invalid_cases = [
            ("admin", "wrong_password"),
            ("wrong_user", "1234"), 
            ("", ""),
            ("admin", ""),
            ("", "1234")
        ]
        
        for username, password in invalid_cases:
            with pytest.raises(InvalidCredentialsError):
                auth_service.authenticate_operator(username, password)


class TestAuthServiceSessionContract:
    """Session management contract tests"""
    
    def test_session_lifecycle(self, auth_service, valid_credentials):
        """
        Test complete session lifecycle: login → check → logout
        
        Contract: Session should be valid after login, invalid after logout
        """
        # Step 1: Login
        login_result = auth_service.authenticate_operator(**valid_credentials)
        assert login_result["success"] is True
        
        # Step 2: Check session (should be valid)
        session_result = auth_service.check_session_status()
        assert session_result["valid"] is True
        
        # Step 3: Logout
        logout_result = auth_service.logout_operator()
        assert logout_result["success"] is True
        
        # Step 4: Check session after logout (should be invalid)
        post_logout_session = auth_service.check_session_status()
        assert post_logout_session["valid"] is False
    
    def test_session_expiration_time(self, auth_service, valid_credentials):
        """
        Test session expiration follows 8-hour rule
        
        Contract: Sessions should expire exactly 8 hours after login
        """
        login_time = datetime.now()
        
        # Login
        result = auth_service.authenticate_operator(**valid_credentials)
        session_expires = result["operator"]["session_expires"]
        
        # Validate expiration time
        expected_expiry = login_time + timedelta(hours=8)
        time_diff = abs((session_expires - expected_expiry).total_seconds())
        assert time_diff < 60, "Session expiration should be 8 hours from login"
    
    def test_concurrent_session_handling(self, auth_service, valid_credentials):
        """
        Test behavior with multiple login attempts
        
        Contract: How should multiple logins be handled for same user?
        """
        # First login
        result1 = auth_service.authenticate_operator(**valid_credentials)
        first_expires = result1["operator"]["session_expires"]
        
        # Second login (should this extend session or create new one?)
        result2 = auth_service.authenticate_operator(**valid_credentials)
        second_expires = result2["operator"]["session_expires"]
        
        # Contract decision: Second login should extend/refresh session
        assert second_expires >= first_expires, "Subsequent login should not reduce session time"


class TestAuthServiceBranchAccessContract:
    """Branch access control contract tests"""
    
    def test_branch_access_consistency(self, auth_service, valid_credentials):
        """
        Test that branch access is consistent across endpoints
        
        Contract: Branch list should match operator.branch_access
        """
        # Login
        login_result = auth_service.authenticate_operator(**valid_credentials)
        operator_branches = set(login_result["operator"]["branch_access"])
        
        # Get branches
        branches_result = auth_service.get_available_branches()
        available_branches = set(b["s3_path_segment"] for b in branches_result["branches"])
        
        # Should be identical
        assert operator_branches == available_branches, "Operator branch access should match available branches"
    
    def test_branch_data_format(self, auth_service, valid_credentials):
        """
        Test branch data format matches specification
        
        Contract: Each branch should have code, display_name, s3_path_segment
        """
        # Authenticate and get branches
        auth_service.authenticate_operator(**valid_credentials)
        result = auth_service.get_available_branches()
        
        # Validate each branch
        for branch in result["branches"]:
            # Required fields
            assert "code" in branch
            assert "display_name" in branch
            assert "s3_path_segment" in branch
            
            # Field types and formats
            assert isinstance(branch["code"], str)
            assert isinstance(branch["display_name"], str)
            assert isinstance(branch["s3_path_segment"], str)
            
            # Display name should contain "Sucursal"
            assert "Sucursal" in branch["display_name"]
            
            # S3 path segment should follow pattern
            assert branch["s3_path_segment"].startswith("sucursal-")
            assert " " not in branch["s3_path_segment"]  # No spaces in S3 path


class TestAuthServiceSecurityContract:
    """Security-focused contract tests"""
    
    def test_no_password_in_responses(self, auth_service, valid_credentials):
        """
        Security Contract: Passwords should never appear in responses
        
        All responses should be free of password data
        """
        result = auth_service.authenticate_operator(**valid_credentials)
        
        # Convert entire response to string and check
        response_str = str(result).lower()
        
        # Should not contain password-related keywords
        sensitive_keywords = ["password", "1234", "secret", "key"]
        for keyword in sensitive_keywords:
            assert keyword not in response_str, f"Response should not contain sensitive keyword: {keyword}"
    
    def test_session_token_security(self, auth_service, valid_credentials):
        """
        Security Contract: Session management should be secure
        
        No session tokens or sensitive data should be exposed
        """
        # Login
        result = auth_service.authenticate_operator(**valid_credentials)
        
        # Check for potential session tokens in response
        response_str = str(result).lower()
        
        # Should not contain token-like keywords
        token_keywords = ["token", "jwt", "session_id", "auth_token"]
        for keyword in token_keywords:
            assert keyword not in response_str, f"Response should not expose internal tokens: {keyword}"
    
    def test_error_message_security(self, auth_service):
        """
        Security Contract: Error messages should not leak sensitive information
        
        Failed authentication should not reveal whether username or password was wrong
        """
        try:
            auth_service.authenticate_operator("nonexistent_user", "wrong_password")
        except InvalidCredentialsError as e:
            error_message = e.message.lower()
            
            # Should not reveal which part was wrong
            revealing_phrases = ["username not found", "user does not exist", "password incorrect"]
            for phrase in revealing_phrases:
                assert phrase not in error_message, f"Error message should not reveal: {phrase}"
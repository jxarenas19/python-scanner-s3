"""
Integration tests for Complete Document Processing Workflow
Tests the end-to-end document processing from login to S3 upload

⚠️ TDD CRITICAL: These tests MUST FAIL before implementation exists
Based on Quickstart Scenario 1: Complete Document Processing Workflow
"""

import pytest
import tempfile
import os
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from services.auth_service import AuthService
from services.scanner_service import ScannerService 
from services.crypto_service import CryptoService
from services.upload_service import UploadService
from services.document_processor import DocumentProcessor
from models.document import Document, DocumentStatus
from models.scanning_session import ScanningSession


class TestCompleteDocumentWorkflow:
    """Integration tests for complete document processing workflow"""
    
    @pytest.fixture
    def auth_service(self):
        """Fixture providing authenticated auth service"""
        return AuthService()
    
    @pytest.fixture
    def scanner_service(self):
        """Fixture providing scanner service"""
        return ScannerService()
    
    @pytest.fixture
    def crypto_service(self):
        """Fixture providing crypto service"""
        return CryptoService()
    
    @pytest.fixture
    def upload_service(self):
        """Fixture providing upload service"""
        return UploadService()
    
    @pytest.fixture  
    def document_processor(self, auth_service, scanner_service, crypto_service, upload_service):
        """Fixture providing document processor that coordinates all services"""
        return DocumentProcessor(
            auth_service=auth_service,
            scanner_service=scanner_service,
            crypto_service=crypto_service,
            upload_service=upload_service
        )
    
    @pytest.fixture
    def test_credentials(self):
        """Fixture providing valid MVP credentials"""
        return {"username": "admin", "password": "1234"}
    
    @pytest.fixture
    def test_branch(self):
        """Fixture providing valid branch selection"""
        return "sucursal-centro"
    
    def test_complete_workflow_success(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Complete successful document processing workflow
        
        Validates Quickstart Scenario 1 - Primary user journey:
        1. Login with admin/1234
        2. Select Sucursal Centro  
        3. Start scanning session
        4. Scan document → encrypt → upload to S3
        5. End session with summary
        
        This MUST FAIL because DocumentProcessor doesn't exist yet
        """
        # Step 1: Authentication
        # Expected: Login screen → credentials → main interface
        auth_result = document_processor.authenticate_operator(**test_credentials)
        
        assert auth_result["success"] is True
        assert auth_result["operator"]["username"] == "admin"
        assert len(auth_result["operator"]["branch_access"]) == 3
        
        # Step 2: Branch Selection  
        # Expected: Branch dropdown → selection → scanning controls enabled
        session = document_processor.start_scanning_session(
            operator="admin",
            branch=test_branch
        )
        
        assert isinstance(session, ScanningSession)
        assert session.operator == "admin"
        assert session.branch == test_branch
        assert session.is_active is True
        assert session.documents_processed == 0
        
        # Step 3: Document Processing Pipeline
        # Expected: Scan → "Cifrado OK" → "Subido OK" → counter increment
        document_result = document_processor.process_single_document(
            session_id=session.id
        )
        
        # Validate document was created and processed
        assert isinstance(document_result, Document)
        assert document_result.operator == "admin"
        assert document_result.branch == test_branch
        assert document_result.status == DocumentStatus.UPLOADED
        
        # Validate S3 key follows naming pattern
        expected_pattern = f"{datetime.now().strftime('%Y-%m-%d')}/sucursal-centro/admin/pagare-"
        assert document_result.s3_key.startswith(expected_pattern)
        assert document_result.s3_key.endswith(".enc")
        
        # Validate file cleanup (no unencrypted data persists)
        if document_result.file_path:
            assert not Path(document_result.file_path).exists()
        if document_result.encrypted_path:
            assert not Path(document_result.encrypted_path).exists()
        
        # Step 4: Session Statistics Update
        updated_session = document_processor.get_session_status(session.id)
        assert updated_session.documents_processed == 1
        assert updated_session.documents_uploaded == 1
        assert updated_session.documents_failed == 0
        
        # Step 5: End Session with Summary
        summary = document_processor.end_scanning_session(session.id)
        
        assert summary["session_ended"] is True
        assert summary["documents_processed"] == 1
        assert summary["documents_uploaded"] == 1  
        assert summary["documents_failed"] == 0
        assert summary["success_rate"] == 100.0
        
        # Validate session is no longer active
        final_session = document_processor.get_session_status(session.id)
        assert final_session.is_active is False
        assert final_session.end_time is not None
    
    def test_multiple_documents_workflow(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Processing multiple documents in single session
        
        Validates processing 3 documents in one session with statistics tracking
        """
        # Setup session
        document_processor.authenticate_operator(**test_credentials)
        session = document_processor.start_scanning_session("admin", test_branch)
        
        # Process multiple documents
        documents = []
        for i in range(3):
            doc = document_processor.process_single_document(session.id)
            documents.append(doc)
        
        # Validate each document processed correctly
        for i, doc in enumerate(documents):
            assert doc.status == DocumentStatus.UPLOADED
            assert doc.operator == "admin"
            assert doc.branch == test_branch
            # Each document should have unique S3 key (different timestamps)
            if i > 0:
                assert doc.s3_key != documents[i-1].s3_key
        
        # Validate session statistics
        final_session = document_processor.get_session_status(session.id)
        assert final_session.documents_processed == 3
        assert final_session.documents_uploaded == 3
        assert final_session.documents_failed == 0
        
        # End session summary
        summary = document_processor.end_scanning_session(session.id)
        assert summary["documents_processed"] == 3
        assert summary["success_rate"] == 100.0
    
    def test_workflow_performance_requirements(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Performance requirements validation
        
        Validates FR-013: ≤3 seconds per document processing
        """
        # Setup
        document_processor.authenticate_operator(**test_credentials)
        session = document_processor.start_scanning_session("admin", test_branch)
        
        # Measure processing time
        start_time = datetime.now()
        document = document_processor.process_single_document(session.id)
        end_time = datetime.now()
        
        # Validate performance requirement
        processing_time = (end_time - start_time).total_seconds()
        assert processing_time <= 3.0, f"Document processing took {processing_time}s, should be ≤3s"
        
        # Validate document was successfully processed despite performance constraint
        assert document.status == DocumentStatus.UPLOADED
    
    def test_workflow_security_compliance(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Security compliance validation
        
        Validates security requirements: no unencrypted data persistence,
        memory-only key management, proper cleanup
        """
        # Setup
        document_processor.authenticate_operator(**test_credentials)
        session = document_processor.start_scanning_session("admin", test_branch)
        
        # Process document and capture file paths
        document = document_processor.process_single_document(session.id)
        
        # Security validations
        
        # 1. No unencrypted files should persist
        if document.file_path:
            assert not Path(document.file_path).exists(), "Unencrypted file should not persist"
        
        # 2. Encrypted temp files should be cleaned up after upload
        if document.encrypted_path:
            assert not Path(document.encrypted_path).exists(), "Encrypted temp file should be cleaned up"
        
        # 3. S3 object should exist and be encrypted
        # (This would require actual S3 connection in real test)
        assert document.s3_key is not None
        assert document.s3_key.endswith(".enc")
        
        # 4. Document metadata should not contain sensitive data
        assert "key" not in str(document.__dict__).lower()
        assert "password" not in str(document.__dict__).lower()
        assert "secret" not in str(document.__dict__).lower()
    
    def test_workflow_with_session_expiration(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Session expiration handling during workflow
        
        Validates behavior when session expires during document processing
        """
        # Setup with session
        document_processor.authenticate_operator(**test_credentials)
        session = document_processor.start_scanning_session("admin", test_branch)
        
        # Mock session expiration
        document_processor._mock_session_expired = True
        
        # Attempt to process document with expired session
        with pytest.raises(Exception) as exc_info:
            document_processor.process_single_document(session.id)
        
        # Should handle session expiration gracefully
        assert "session" in str(exc_info.value).lower() or "expired" in str(exc_info.value).lower()


class TestWorkflowErrorHandling:
    """Integration tests for workflow error handling scenarios"""
    
    @pytest.fixture
    def document_processor_with_mocks(self):
        """Fixture providing document processor with mock services for error testing"""
        auth_service = Mock(spec=AuthService)
        scanner_service = Mock(spec=ScannerService)
        crypto_service = Mock(spec=CryptoService)
        upload_service = Mock(spec=UploadService)
        
        return DocumentProcessor(
            auth_service=auth_service,
            scanner_service=scanner_service,
            crypto_service=crypto_service,
            upload_service=upload_service
        )
    
    def test_workflow_scanner_failure_handling(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Scanner hardware failure during workflow
        
        Validates graceful handling when scanner becomes unavailable
        """
        # Setup successful session
        document_processor.authenticate_operator(**test_credentials)
        session = document_processor.start_scanning_session("admin", test_branch)
        
        # Mock scanner failure
        document_processor._mock_scanner_failure = True
        
        # Attempt document processing
        with pytest.raises(Exception) as exc_info:
            document_processor.process_single_document(session.id)
        
        # Should handle scanner failure gracefully
        error_message = str(exc_info.value).lower()
        assert any(keyword in error_message for keyword in ["scanner", "device", "hardware"])
        
        # Session should remain active for retry
        session_status = document_processor.get_session_status(session.id)
        assert session_status.is_active is True
        assert session_status.documents_failed == 1
    
    def test_workflow_encryption_failure_handling(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Encryption failure during workflow
        
        Validates handling when encryption step fails
        """
        # Setup
        document_processor.authenticate_operator(**test_credentials)
        session = document_processor.start_scanning_session("admin", test_branch)
        
        # Mock encryption failure
        document_processor._mock_encryption_failure = True
        
        # Process should handle encryption failure
        with pytest.raises(Exception) as exc_info:
            document_processor.process_single_document(session.id)
        
        # Validate error handling
        error_message = str(exc_info.value).lower()
        assert "encryption" in error_message or "crypto" in error_message
        
        # Session statistics should reflect failure
        session_status = document_processor.get_session_status(session.id)
        assert session_status.documents_failed == 1
        assert session_status.documents_uploaded == 0


class TestWorkflowStateManagement:
    """Integration tests for workflow state management"""
    
    def test_document_state_transitions(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Document state transitions during processing
        
        Validates state flow: scanned → encrypted → uploaded
        """
        # Setup
        document_processor.authenticate_operator(**test_credentials)  
        session = document_processor.start_scanning_session("admin", test_branch)
        
        # Mock step-by-step processing to observe state transitions
        document_processor._enable_state_tracking = True
        
        document = document_processor.process_single_document(session.id)
        
        # Validate final state
        assert document.status == DocumentStatus.UPLOADED
        
        # Validate state history was tracked (if implementation supports it)
        if hasattr(document, 'state_history'):
            states = [entry['status'] for entry in document.state_history]
            expected_sequence = [DocumentStatus.SCANNED, DocumentStatus.ENCRYPTED, DocumentStatus.UPLOADED]
            assert states == expected_sequence
    
    def test_concurrent_session_handling(self, document_processor, test_credentials):
        """
        Integration Test: Concurrent session handling
        
        Validates system behavior with multiple active sessions
        (Though MVP spec mentions single operator, test system limits)
        """
        # Setup first session
        document_processor.authenticate_operator(**test_credentials)
        session1 = document_processor.start_scanning_session("admin", "sucursal-centro")
        
        # Attempt second session for same operator
        with pytest.raises(Exception) as exc_info:
            session2 = document_processor.start_scanning_session("admin", "sucursal-norte")
        
        # Should enforce single active session per operator
        error_message = str(exc_info.value).lower()
        assert "session" in error_message or "active" in error_message
        
        # First session should remain valid
        session_status = document_processor.get_session_status(session1.id)
        assert session_status.is_active is True
    
    def test_session_recovery_after_interruption(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Session recovery after system interruption
        
        Validates behavior when session is interrupted and restarted
        """
        # Start session and process some documents
        document_processor.authenticate_operator(**test_credentials)
        session = document_processor.start_scanning_session("admin", test_branch)
        
        # Process first document
        doc1 = document_processor.process_single_document(session.id)
        assert doc1.status == DocumentStatus.UPLOADED
        
        # Simulate interruption (mock restart)
        document_processor._simulate_restart = True
        
        # Session recovery should handle gracefully
        # (In real implementation, this might require persistence)
        try:
            session_status = document_processor.get_session_status(session.id)
            # If session persists, should maintain state
            assert session_status.documents_uploaded >= 1
        except Exception:
            # If session doesn't persist, should handle gracefully
            # (Depends on implementation choice for MVP)
            pass


class TestWorkflowIntegrationValidation:
    """Validation tests for workflow integration requirements"""
    
    def test_workflow_service_integration(self):
        """
        Integration Test: All required services integrate correctly
        
        This MUST FAIL because services don't exist yet
        """
        # This will fail with ImportError - expected in RED phase
        from services.document_processor import DocumentProcessor
        from services.auth_service import AuthService
        from services.scanner_service import ScannerService
        from services.crypto_service import CryptoService
        from services.upload_service import UploadService
        
        # All services should integrate without conflicts
        processor = DocumentProcessor(
            auth_service=AuthService(),
            scanner_service=ScannerService(),
            crypto_service=CryptoService(), 
            upload_service=UploadService()
        )
        
        assert processor is not None
        assert hasattr(processor, 'process_single_document')
        assert hasattr(processor, 'start_scanning_session')
        assert hasattr(processor, 'end_scanning_session')
    
    def test_workflow_data_model_integration(self):
        """
        Integration Test: Data models integrate correctly with workflow
        
        This MUST FAIL because models don't exist yet
        """
        from models.document import Document, DocumentStatus
        from models.scanning_session import ScanningSession
        
        # Models should be compatible with workflow requirements
        document = Document(
            operator="admin",
            branch="sucursal-centro", 
            scan_timestamp=datetime.now()
        )
        
        session = ScanningSession(
            operator="admin",
            branch="sucursal-centro"
        )
        
        assert document.status == DocumentStatus.SCANNED  # Default state
        assert session.is_active is True  # Default state
        
        # Models should support state transitions
        document.status = DocumentStatus.ENCRYPTED
        assert document.status == DocumentStatus.ENCRYPTED
        
        document.status = DocumentStatus.UPLOADED
        assert document.status == DocumentStatus.UPLOADED
    
    def test_workflow_meets_quickstart_requirements(self, document_processor, test_credentials, test_branch):
        """
        Integration Test: Workflow meets all quickstart scenario requirements
        
        Validates against quickstart.md Scenario 1 acceptance criteria
        """
        # This comprehensive test validates the entire quickstart scenario
        
        # Quickstart Step 1: Launch Application → Login screen
        # (Handled by authentication test)
        
        # Quickstart Step 2: Authenticate admin/1234 → Main interface
        auth_result = document_processor.authenticate_operator(**test_credentials)
        assert auth_result["success"] is True
        
        # Quickstart Step 3: Select "Sucursal Centro" → Controls enabled
        session = document_processor.start_scanning_session("admin", test_branch)
        assert session.branch == "sucursal-centro"
        
        # Quickstart Step 4: Click "Iniciar Proceso" → Status "Escuchando..."
        # (Handled by session start)
        assert session.is_active is True
        
        # Quickstart Step 5: Scan document → Status updates → Counter increments
        document = document_processor.process_single_document(session.id)
        assert document.status == DocumentStatus.UPLOADED
        
        # Quickstart Step 6: Verify S3 Upload → Correct naming pattern
        assert document.s3_key.startswith("2025-")
        assert "/sucursal-centro/admin/pagare-" in document.s3_key
        assert document.s3_key.endswith(".enc")
        
        # Quickstart Step 7: End session → Summary display
        summary = document_processor.end_scanning_session(session.id)
        assert summary["documents_processed"] == 1
        assert summary["documents_uploaded"] == 1
        assert summary["documents_failed"] == 0
        
        # Success Criteria: 100% documents uploaded with correct naming
        assert summary["success_rate"] == 100.0
        # Success Criteria: Zero blocking on stop
        assert summary["session_ended"] is True
        # Success Criteria: Operator completes without assistance
        # (Demonstrated by successful automated test completion)
"""
Login Dialog
PyQt6 dialog for user authentication and session management
"""

import os
import sys
from typing import Any, Dict, Optional

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from services.auth_service import AuthenticationFailedError, AuthService


class LoginWorker(QThread):
    """Worker thread for login operations to prevent UI blocking"""

    login_completed = pyqtSignal(dict)
    login_failed = pyqtSignal(str, dict)

    def __init__(self, auth_service: AuthService, username: str, password: str):
        super().__init__()
        self.auth_service = auth_service
        self.username = username
        self.password = password

    def run(self):
        """Perform login in background thread"""
        try:
            result = self.auth_service.login(
                username=self.username,
                password=self.password,
                client_ip="127.0.0.1",
                user_agent="Scanner-GUI/1.0",
            )
            self.login_completed.emit(result)
        except AuthenticationFailedError as e:
            error_info = {
                "error_code": e.error_code,
                "rate_limited": getattr(e, "rate_limited", False),
                "retry_after": getattr(e, "retry_after", 0),
            }
            self.login_failed.emit(str(e), error_info)
        except Exception as e:
            self.login_failed.emit(f"Unexpected error: {e}", {})


class LoginDialog(QDialog):
    """
    Login dialog for user authentication

    Provides a user-friendly interface for entering credentials
    and handling authentication with proper error handling and security features.
    """

    def __init__(self, auth_service: AuthService, parent=None):
        super().__init__(parent)
        self.auth_service = auth_service
        self.session_info: Optional[Dict[str, Any]] = None
        self.login_worker: Optional[LoginWorker] = None

        self.init_ui()
        self.setup_connections()

        # Set focus to username field
        self.username_edit.setFocus()

    def init_ui(self):
        """Initialize the dialog UI"""
        self.setWindowTitle("Login - Scanner Cifrado S3")
        self.setMinimumSize(480, 420)
        self.setModal(True)

        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(5, 5, 5, 5)

        # Header section
        self.create_header_section(main_layout)

        # Login form section
        self.create_login_form(main_layout)

        # Options section
        self.create_options_section(main_layout)

        # Button section
        self.create_button_section(main_layout)

        # Status section
        self.create_status_section(main_layout)

        # Apply styling
        self.apply_styling()

    def create_header_section(self, layout):
        """Create header with logo and title"""
        header_frame = QFrame()
        header_layout = QVBoxLayout(header_frame)
        header_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Application title
        title_label = QLabel("Scanner Cifrado S3")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 5px;")
        header_layout.addWidget(title_label)

        # Subtitle
        subtitle_label = QLabel("Document Processing System")
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 10px;")
        header_layout.addWidget(subtitle_label)

        layout.addWidget(header_frame)

    def create_login_form(self, layout):
        """Create login form with username, password and branch fields"""
        form_group = QGroupBox("Authentication")
        form_layout = QGridLayout(form_group)
        form_layout.setContentsMargins(12, 12, 12, 12)
        form_layout.setHorizontalSpacing(12)
        form_layout.setVerticalSpacing(10)

        # Username field
        username_label = QLabel("Username:")
        username_label.setFont(QFont("", 11, QFont.Weight.Bold))
        form_layout.addWidget(username_label, 0, 0)

        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Enter your username")
        self.username_edit.setText("admin")  # Pre-fill MVP username
        self.username_edit.setMinimumHeight(35)
        form_layout.addWidget(self.username_edit, 0, 1)

        # Password field
        password_label = QLabel("Password:")
        password_label.setFont(QFont("", 11, QFont.Weight.Bold))
        form_layout.addWidget(password_label, 1, 0)

        password_container = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter your password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setMinimumHeight(35)
        password_container.addWidget(self.password_edit)

        # Show password checkbox
        self.show_password_check = QCheckBox("Show")
        self.show_password_check.setToolTip("Show/Hide password")
        self.show_password_check.toggled.connect(self.toggle_password_visibility)
        password_container.addWidget(self.show_password_check)

        password_widget = QFrame()
        password_widget.setLayout(password_container)
        form_layout.addWidget(password_widget, 1, 1)

        # Branch selection field
        branch_label = QLabel("Branch:")
        branch_label.setFont(QFont("", 11, QFont.Weight.Bold))
        form_layout.addWidget(branch_label, 2, 0)

        self.branch_combo = QComboBox()
        self.branch_combo.setMinimumHeight(35)
        self.branch_combo.addItems(
            [
                "Sucursal Centro",
                "Sucursal Norte",
                "Sucursal Sur",
                "Sucursal Este",
                "Sucursal Oeste",
            ]
        )
        form_layout.addWidget(self.branch_combo, 2, 1)

        layout.addWidget(form_group)

    def create_options_section(self, layout):
        """Create options section"""
        options_layout = QHBoxLayout()

        # Remember me checkbox
        self.remember_check = QCheckBox("Remember username")
        self.remember_check.setChecked(True)
        options_layout.addWidget(self.remember_check)

        options_layout.addStretch()

        layout.addLayout(options_layout)

    def create_button_section(self, layout):
        """Create button section"""
        button_layout = QHBoxLayout()

        # Spacer
        button_layout.addStretch()

        # Login button
        self.login_btn = QPushButton("Login")
        self.login_btn.setMinimumHeight(40)
        self.login_btn.setMinimumWidth(100)
        self.login_btn.clicked.connect(self.perform_login)
        self.login_btn.setDefault(True)
        button_layout.addWidget(self.login_btn)

        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(40)
        self.cancel_btn.setMinimumWidth(100)
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

    def create_status_section(self, layout):
        """Create status display section"""
        status_frame = QFrame()
        status_layout = QVBoxLayout(status_frame)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(
            "QProgressBar{ text-align:center; height:16px; }"
        )
        status_layout.addWidget(self.progress_bar)

        # Status message
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setMinimumHeight(30)
        status_layout.addWidget(self.status_label)

        layout.addWidget(status_frame)

    def apply_styling(self):
        """Apply dialog styling (minimal, native-friendly)"""
        self.setStyleSheet(
            """
            QDialog { }
            QGroupBox { font-weight: 600; border: 1px solid #d0d0d0; border-radius: 6px; margin-top: 10px; padding-top: 10px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
            QLabel { font-size: 10.5pt; }
            QLineEdit, QComboBox { padding: 6px; font-size: 10.5pt; }
            QPushButton { padding: 8px 14px; }
            QCheckBox { font-size: 10pt; }
            """
        )

    def setup_connections(self):
        """Setup signal connections"""
        # Enter key handling
        self.username_edit.returnPressed.connect(self.password_edit.setFocus)
        self.password_edit.returnPressed.connect(self.perform_login)

        self.setTabOrder(self.username_edit, self.password_edit)
        self.setTabOrder(self.password_edit, self.branch_combo)
        self.setTabOrder(self.branch_combo, self.login_btn)

    def toggle_password_visibility(self, checked):
        """Toggle password field visibility"""
        if checked:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)

    def perform_login(self):
        """Perform login operation"""
        username = self.username_edit.text().strip()
        password = self.password_edit.text()

        # Validate inputs
        if not username:
            self.show_error("Please enter a username")
            self.username_edit.setFocus()
            return

        if not password:
            self.show_error("Please enter a password")
            self.password_edit.setFocus()
            return

        # Disable UI during login
        self.set_login_state(True)

        # Start progress animation
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText("Authenticating...")

        # Create and start login worker
        self.login_worker = LoginWorker(self.auth_service, username, password)
        self.login_worker.login_completed.connect(self.handle_login_success)
        self.login_worker.login_failed.connect(self.handle_login_failure)
        self.login_worker.start()

    def handle_login_success(self, result):
        """Handle successful login"""
        self.session_info = result

        # Update UI
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"✅ Welcome, {result['operator']}!")
        self.status_label.setStyleSheet("color: #27ae60; font-weight: bold;")

        # Brief delay before closing dialog
        QTimer.singleShot(1000, self.accept)

    def handle_login_failure(self, error_message, error_info):
        """Handle login failure"""
        self.set_login_state(False)
        self.progress_bar.setVisible(False)

        # Show error message
        if error_info.get("rate_limited", False):
            retry_after = error_info.get("retry_after", 0)
            error_text = f"Account temporarily locked.\nPlease try again in {retry_after} seconds."
            self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")

            # Start countdown timer
            self.start_lockout_countdown(retry_after)
        else:
            error_text = f"❌ {error_message}"
            self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")

        self.status_label.setText(error_text)

        # Clear password field
        self.password_edit.clear()
        self.password_edit.setFocus()

        # Show detailed error dialog for debugging
        if error_info:
            QMessageBox.warning(
                self,
                "Authentication Failed",
                f"Login failed: {error_message}\n\n"
                f"Error Code: {error_info.get('error_code', 'Unknown')}",
            )

    def start_lockout_countdown(self, seconds):
        """Start countdown timer for account lockout"""
        self.lockout_timer = QTimer()
        self.lockout_remaining = seconds

        def update_countdown():
            if self.lockout_remaining > 0:
                self.status_label.setText(
                    f"Account locked. Try again in {self.lockout_remaining}s"
                )
                self.lockout_remaining -= 1
            else:
                self.lockout_timer.stop()
                self.status_label.setText("You may now try logging in again")
                self.status_label.setStyleSheet("color: #2c3e50;")
                self.set_login_state(False)

        self.lockout_timer.timeout.connect(update_countdown)
        self.lockout_timer.start(1000)  # Update every second

    def set_login_state(self, logging_in):
        """Set UI state during login process"""
        self.username_edit.setEnabled(not logging_in)
        self.password_edit.setEnabled(not logging_in)
        self.branch_combo.setEnabled(not logging_in)
        self.login_btn.setEnabled(not logging_in)
        self.show_password_check.setEnabled(not logging_in)
        self.remember_check.setEnabled(not logging_in)

        if logging_in:
            self.login_btn.setText("Signing in...")
        else:
            self.login_btn.setText("Login")

    def show_error(self, message):
        """Show error message to user"""
        self.status_label.setText(f"❌ {message}")
        self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")

    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """Get session information from successful login"""
        return self.session_info

    def closeEvent(self, event):
        """Handle dialog close event"""
        # Stop any running login worker
        if self.login_worker and self.login_worker.isRunning():
            self.login_worker.terminate()
            self.login_worker.wait()

        # Stop countdown timer
        if hasattr(self, "lockout_timer") and self.lockout_timer.isActive():
            self.lockout_timer.stop()

        event.accept()

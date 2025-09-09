#!/usr/bin/env python3
"""
Main GUI Application
PyQt6-based desktop application for document scanner system
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PyQt6.QtCore import QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# Import configuration first to load environment variables
from config.settings import AppConfig, ScannerConfig
from gui.login_dialog import LoginDialog
from services.auth_service import AuthService
from services.crypto_service import CryptoService
from services.scanner_service import ScannerService
from services.upload_service import UploadService


class ScannerWorker(QThread):
    """Worker thread for scanner operations"""

    document_received = pyqtSignal(dict)
    scanner_status_changed = pyqtSignal(bool, str)

    def __init__(self, scanner_service):
        super().__init__()
        self.scanner_service = scanner_service
        self.running = False

    def run(self):
        """Monitor scanner for new documents"""
        self.running = True
        while self.running:
            try:
                # Check scanner connection
                availability = self.scanner_service.check_scanner_availability()
                self.scanner_status_changed.emit(
                    availability["available"],
                    availability.get("scanner_name", "Unknown Scanner"),
                )

                # Check for new documents
                if availability["available"]:
                    documents = self.scanner_service.get_pending_documents()
                    for doc in documents:
                        self.document_received.emit(doc)

                self.msleep(2000)  # Check every 2 seconds

            except Exception as e:
                self.scanner_status_changed.emit(False, f"Error: {str(e)}")
                self.msleep(5000)  # Wait longer on error

    def stop(self):
        """Stop the worker thread"""
        self.running = False
        self.quit()
        self.wait()


class DocumentScannerApp(QMainWindow):
    """
    Simplified document scanner application

    Connects to a pre-configured scanner, receives documents automatically,
    and provides a simple interface to batch process and upload to S3.
    """

    def __init__(self):
        super().__init__()

        # Initialize services
        self.auth_service = AuthService()
        self.scanner_service = ScannerService()
        self.crypto_service = CryptoService()
        self.upload_service = UploadService()

        # Application state
        self.current_token: Optional[str] = None
        self.operator_name: str = ""
        self.branch_name: str = ""
        self.received_documents: List[Dict] = []
        self.scanner_worker: Optional[ScannerWorker] = None
        self.scanner_connected: bool = False

        # Initialize UI
        self.init_ui()
        self.init_statusbar()

        # Show login dialog on startup
        self.show_login_dialog()

    def init_ui(self):
        """Initialize the main user interface"""
        self.setWindowTitle("Scanner Cifrado S3 - Document Processing System")
        self.setGeometry(100, 100, 900, 600)
        self.setMinimumSize(QSize(800, 500))

        # Create central widget with splitter layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # Create control panel (left side)
        self.create_control_panel(splitter)

        # Create document area (right side)
        self.create_document_area(splitter)

        # Set splitter proportions
        splitter.setSizes([300, 600])

        # Apply styling
        self.apply_styling()

    def create_control_panel(self, parent):
        """Create the left control panel"""
        control_widget = QWidget()
        control_layout = QVBoxLayout(control_widget)

        # Session info
        self.create_session_info(control_layout)

        # Scanner controls
        self.create_scanner_controls(control_layout)

        # Process controls
        self.create_process_controls(control_layout)

        # Add stretch to push everything to top
        control_layout.addStretch()

        parent.addWidget(control_widget)

    def create_session_info(self, layout):
        """Create session information group"""
        group = QGroupBox("Session Information")
        group_layout = QGridLayout(group)

        # Session status
        group_layout.addWidget(QLabel("Status:"), 0, 0)
        self.session_status_label = QLabel("Not logged in")
        self.session_status_label.setStyleSheet("color: red; font-weight: bold;")
        group_layout.addWidget(self.session_status_label, 0, 1)

        # Operator info
        group_layout.addWidget(QLabel("Operator:"), 1, 0)
        self.operator_label = QLabel("-")
        group_layout.addWidget(self.operator_label, 1, 1)

        # Branch info
        group_layout.addWidget(QLabel("Branch:"), 2, 0)
        self.branch_label = QLabel("-")
        group_layout.addWidget(self.branch_label, 2, 1)

        # Logout button
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.clicked.connect(self.logout)
        self.logout_btn.setEnabled(False)
        group_layout.addWidget(self.logout_btn, 3, 0, 1, 2)

        layout.addWidget(group)

    def create_scanner_controls(self, layout):
        """Create scanner control group"""
        group = QGroupBox("Scanner Controls")
        group_layout = QVBoxLayout(group)

        # Scanner connection status
        connection_layout = QHBoxLayout()
        connection_layout.addWidget(QLabel("Scanner:"))
        self.scanner_connection_label = QLabel("Disconnected")
        self.scanner_connection_label.setStyleSheet("color: red; font-weight: bold;")
        connection_layout.addWidget(self.scanner_connection_label)
        connection_layout.addStretch()
        group_layout.addLayout(connection_layout)

        # Scanner name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Device:"))
        self.scanner_name_label = QLabel("-")
        name_layout.addWidget(self.scanner_name_label)
        name_layout.addStretch()
        group_layout.addLayout(name_layout)

        # Documents received counter
        docs_layout = QHBoxLayout()
        docs_layout.addWidget(QLabel("Documents:"))
        self.docs_count_label = QLabel("0")
        self.docs_count_label.setStyleSheet("font-weight: bold; color: #2e7d32;")
        docs_layout.addWidget(self.docs_count_label)
        docs_layout.addStretch()
        group_layout.addLayout(docs_layout)

        layout.addWidget(group)

    def create_process_controls(self, layout):
        """Create document processing controls"""
        group = QGroupBox("Document Processing")
        group_layout = QVBoxLayout(group)

        # Processing progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        group_layout.addWidget(self.progress_bar)

        # Process status
        self.process_status_label = QLabel("Waiting for documents...")
        group_layout.addWidget(self.process_status_label)

        # Finish Process button
        self.finish_process_btn = QPushButton("🔐 Finish Process & Upload to S3")
        self.finish_process_btn.setMinimumHeight(50)
        self.finish_process_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #1976d2;
                color: white;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #1565c0;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """
        )
        self.finish_process_btn.clicked.connect(self.finish_process)
        self.finish_process_btn.setEnabled(False)
        group_layout.addWidget(self.finish_process_btn)

        layout.addWidget(group)

    def create_document_area(self, parent):
        """Create the main document area"""
        document_widget = QWidget()
        document_layout = QVBoxLayout(document_widget)

        # Documents received section
        docs_group = QGroupBox("Received Documents")
        docs_layout = QVBoxLayout(docs_group)

        # Document list
        self.document_list = QListWidget()
        self.document_list.setMinimumHeight(200)
        docs_layout.addWidget(self.document_list)

        document_layout.addWidget(docs_group)

        # System logs section
        logs_group = QGroupBox("System Logs")
        logs_layout = QVBoxLayout(logs_group)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 9))
        self.log_text.setMaximumHeight(200)
        logs_layout.addWidget(self.log_text)

        # Clear logs button
        clear_btn = QPushButton("Clear Logs")
        clear_btn.clicked.connect(lambda: self.log_text.clear())
        logs_layout.addWidget(clear_btn)

        document_layout.addWidget(logs_group)

        parent.addWidget(document_widget)

    def init_statusbar(self):
        """Initialize status bar"""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")

    def apply_styling(self):
        """Apply application styling"""
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #f5f5f5;
            }

            QGroupBox {
                font-weight: bold;
                border: 2px solid #ccc;
                border-radius: 5px;
                margin: 5px;
                padding-top: 10px;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }

            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #45a049;
            }

            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }

            QListWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
            }

            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #eee;
            }

            QListWidget::item:selected {
                background-color: #e3f2fd;
            }
        """
        )

    def show_login_dialog(self):
        """Show login dialog"""
        dialog = LoginDialog(self.auth_service, self)
        if dialog.exec():
            session_info = dialog.get_session_info()
            self.handle_successful_login(session_info)
        else:
            self.close()

    def handle_successful_login(self, session_info):
        """Handle successful login"""
        self.current_token = session_info["session_token"]
        self.operator_name = session_info["operator"]
        self.branch_name = session_info["branch"]

        # Update UI
        self.session_status_label.setText("Active")
        self.session_status_label.setStyleSheet("color: green; font-weight: bold;")
        self.operator_label.setText(self.operator_name)
        self.branch_label.setText(self.branch_name)
        self.logout_btn.setEnabled(True)

        self.add_log_entry(
            f"User {self.operator_name} logged in to branch {self.branch_name}"
        )
        self.statusbar.showMessage(f"Logged in as {self.operator_name}")

        # Start scanner monitoring
        self.start_scanner_monitoring()

    def start_scanner_monitoring(self):
        """Start monitoring the scanner for new documents"""
        self.scanner_worker = ScannerWorker(self.scanner_service)
        self.scanner_worker.document_received.connect(self.on_document_received)
        self.scanner_worker.scanner_status_changed.connect(
            self.on_scanner_status_changed
        )
        self.scanner_worker.start()

        self.add_log_entry("Scanner monitoring started")

    def on_scanner_status_changed(self, connected: bool, scanner_name: str):
        """Handle scanner connection status changes"""
        self.scanner_connected = connected

        if connected:
            self.scanner_connection_label.setText("Connected")
            self.scanner_connection_label.setStyleSheet(
                "color: green; font-weight: bold;"
            )
            self.scanner_name_label.setText(scanner_name)
            if not hasattr(self, "_scanner_connected_logged"):
                self.add_log_entry(f"Scanner connected: {scanner_name}")
                self._scanner_connected_logged = True
        else:
            self.scanner_connection_label.setText("Disconnected")
            self.scanner_connection_label.setStyleSheet(
                "color: red; font-weight: bold;"
            )
            self.scanner_name_label.setText(scanner_name)
            if hasattr(self, "_scanner_connected_logged"):
                self.add_log_entry(f"Scanner disconnected: {scanner_name}")
                delattr(self, "_scanner_connected_logged")

    def on_document_received(self, document_info: Dict):
        """Handle new document received from scanner"""
        # Add to received documents list
        self.received_documents.append(document_info)

        # Update UI
        self.update_document_list()
        self.update_document_count()

        # Enable finish process button
        self.finish_process_btn.setEnabled(True)

        filename = Path(document_info.get("document_path", "unknown")).name
        self.add_log_entry(f"Document received: {filename}")

        # Update status
        count = len(self.received_documents)
        self.process_status_label.setText(
            f"Ready to process {count} document{'s' if count != 1 else ''}"
        )

    def update_document_list(self):
        """Update the document list display"""
        self.document_list.clear()

        for i, doc in enumerate(self.received_documents, 1):
            filename = Path(doc.get("document_path", "unknown")).name
            file_size = doc.get("file_size", 0)
            timestamp = doc.get("timestamp", datetime.now())

            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except:
                    timestamp = datetime.now()

            item_text = f"{i}. {filename}"
            item_detail = (
                f"   Size: {file_size:,} bytes | {timestamp.strftime('%H:%M:%S')}"
            )

            item = QListWidgetItem(f"{item_text}\n{item_detail}")
            item.setData(Qt.ItemDataRole.UserRole, doc)
            self.document_list.addItem(item)

    def update_document_count(self):
        """Update the document count display"""
        count = len(self.received_documents)
        self.docs_count_label.setText(str(count))

    def finish_process(self):
        """Process all received documents and upload to S3"""
        if not self.received_documents:
            QMessageBox.information(self, "No Documents", "No documents to process.")
            return

        if not self.current_token:
            QMessageBox.warning(self, "Error", "Please log in first")
            return

        # Confirm action
        count = len(self.received_documents)
        reply = QMessageBox.question(
            self,
            "Confirm Process",
            f'Process and upload {count} document{"s" if count != 1 else ""} to S3?\n\n'
            "All documents will be encrypted and uploaded.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Start processing
        self.process_all_documents()

    def process_all_documents(self):
        """Process all documents: encrypt and upload to S3"""
        total_docs = len(self.received_documents)
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(total_docs * 2)  # encrypt + upload for each doc
        self.finish_process_btn.setEnabled(False)

        processed_count = 0
        upload_results = []

        self.add_log_entry(f"Starting batch processing of {total_docs} documents")

        for i, doc_info in enumerate(self.received_documents):
            try:
                filename = Path(doc_info["document_path"]).name

                # Step 1: Encrypt document
                self.progress_bar.setValue(i * 2 + 1)
                self.process_status_label.setText(f"Encrypting {filename}...")
                QApplication.processEvents()

                encrypt_result = self.crypto_service.encrypt_document(
                    file_path=doc_info["document_path"],
                    operator=self.operator_name,
                    timestamp=datetime.now(),
                    branch=self.branch_name,
                )

                self.add_log_entry(f"Encrypted: {filename}")

                # Step 2: Upload to S3
                self.progress_bar.setValue(i * 2 + 2)
                self.process_status_label.setText(f"Uploading {filename}...")
                QApplication.processEvents()

                upload_result = self.upload_service.upload_encrypted_document(
                    encrypted_file_path=encrypt_result["encrypted_path"],
                    operator=self.operator_name,
                    branch=self.branch_name,
                    timestamp=datetime.now(),
                    session_token=self.current_token,
                )

                upload_results.append(
                    {
                        "filename": filename,
                        "s3_url": upload_result["s3_url"],
                        "s3_key": upload_result["s3_key"],
                    }
                )

                processed_count += 1
                self.add_log_entry(f"Uploaded: {filename} -> {upload_result['s3_key']}")

            except Exception as e:
                self.add_log_entry(f"Error processing {filename}: {str(e)}", "ERROR")
                continue

        # Process complete
        self.progress_bar.setVisible(False)
        self.finish_process_btn.setEnabled(False)

        # Show results
        if processed_count > 0:
            result_text = f"Successfully processed {processed_count} of {total_docs} documents.\n\nUploaded files:\n"
            for result in upload_results:
                result_text += f"• {result['filename']} -> {result['s3_key']}\n"

            QMessageBox.information(self, "Process Complete", result_text)
            self.add_log_entry(
                f"Batch processing completed: {processed_count}/{total_docs} successful"
            )

            # Clear processed documents
            self.received_documents.clear()
            self.update_document_list()
            self.update_document_count()
            self.process_status_label.setText("Waiting for documents...")

        else:
            QMessageBox.critical(
                self, "Process Failed", "No documents were processed successfully."
            )

    def logout(self):
        """Handle logout"""
        if self.scanner_worker:
            self.scanner_worker.stop()
            self.scanner_worker = None

        if self.current_token:
            try:
                self.auth_service.logout(self.current_token)
                self.add_log_entry("User logged out")
            except Exception as e:
                self.add_log_entry(f"Logout error: {e}", "WARNING")

        # Reset UI
        self.current_token = None
        self.session_status_label.setText("Not logged in")
        self.session_status_label.setStyleSheet("color: red; font-weight: bold;")
        self.operator_label.setText("-")
        self.branch_label.setText("-")
        self.logout_btn.setEnabled(False)
        self.finish_process_btn.setEnabled(False)

        # Clear documents and status
        self.received_documents.clear()
        self.update_document_list()
        self.update_document_count()

        self.scanner_connection_label.setText("Disconnected")
        self.scanner_connection_label.setStyleSheet("color: red; font-weight: bold;")
        self.scanner_name_label.setText("-")

        self.statusbar.showMessage("Logged out")
        QApplication.instance().quit()

    def add_log_entry(self, message, level="INFO"):
        """Add entry to system logs"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}"
        self.log_text.append(log_entry)

    def closeEvent(self, event):
        """Handle application close"""
        if self.scanner_worker:
            self.scanner_worker.stop()

        if self.current_token:
            reply = QMessageBox.question(
                self,
                "Exit Application",
                "You are currently logged in. Do you want to logout and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.logout()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    """Main entry point for the GUI application"""
    app = QApplication(sys.argv)
    app.setApplicationName("Scanner Cifrado S3")
    app.setApplicationVersion("1.0")

    window = DocumentScannerApp()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

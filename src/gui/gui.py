"""
FolderLocker GUI Module

Provides the complete graphical interface:
  SetupScreen   → first launch password creation
  LoginScreen   → password entry on every launch
  RecoveryScreen → password reset via recovery key
  Dashboard     → main lock/unlock interface
  MainWindow    → root window hosting all screens
  LockWorker    → background thread for operations

PyQt6 concepts used:
  QMainWindow   → the root application window
  QWidget       → a generic UI panel
  QStackedWidget → holds multiple screens, shows one
  QThread       → runs operations in background
  pyqtSignal    → sends messages between components
  QSystemTrayIcon → the tray icon in the taskbar
"""

import sys
from pathlib import Path
from datetime import datetime

# QApplication is the core PyQt6 application object.
# Every PyQt6 app must create exactly one QApplication
# before creating any windows or widgets.
# It manages the event loop — the cycle that keeps
# the app running and responding to user input.
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QFileDialog,
    QMessageBox,
    QFrame,
    QStackedWidget,
    QProgressBar,
    QTextEdit,
    QInputDialog,
)

# Qt provides core constants like alignment flags.
# QThread is PyQt6's thread class — safer than plain
# Python threads for GUI apps because it integrates
# with the Qt event loop.
# pyqtSignal defines custom signals — messages that
# one widget can send to another.
# QTimer runs a function repeatedly on an interval.
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer

# QFont controls text appearance.
from PyQt6.QtGui import QFont

# Our application modules
from src.auth.auth import (
    is_password_set,
    set_master_password,
    verify_master_password,
    recover_with_key,
)
from src.manager.manager import lock, unlock, is_locked
from src.tray.tray import TrayManager


# ─────────────────────────────────────────────
# LockWorker
#
# Runs lock and unlock operations in a background
# thread so the GUI never freezes.
#
# Why a background thread?
#   Encrypting a large folder with thousands of
#   files can take many seconds. If we ran this
#   on the main thread the entire GUI would freeze —
#   no progress bar movement, no button response,
#   the window would appear crashed to the user.
#   Running on a background thread keeps the GUI
#   alive and responsive while work happens.
#
# pyqtSignal is used to send results back to the
# main thread safely. Qt requires that all GUI
# updates happen on the main thread. Signals
# automatically marshal data across thread boundaries.
# ─────────────────────────────────────────────

class LockWorker(QThread):
    # finished signal carries the result dictionary
    # back to the main thread when the operation completes
    finished = pyqtSignal(dict)

    # error signal carries an error message string
    # if an unexpected exception occurs
    error = pyqtSignal(str)

    # progress signal carries status message strings
    # to update the activity log during the operation
    progress = pyqtSignal(str)

    def __init__(
        self,
        operation: str,
        folder_path: str,
        password: str,
        mode: str = "full"
    ):
        """
        operation
            Either "lock" or "unlock".
            Determines which manager function to call.

        folder_path
            String path to the folder to process.
            Passed as string because Qt signals work
            better with primitive types than Path objects.

        password
            The master password already verified by the GUI.
            Passed to the manager for encryption operations.

        mode
            The lock mode: full, soft, or smart.
            Only used for lock operations.
            Unlock reads mode from the saved state file.
        """
        # super().__init__() calls QThread's __init__
        # which sets up the thread infrastructure.
        # We must call this before using any QThread features.
        super().__init__()
        self.operation = operation
        self.folder_path = folder_path
        self.password = password
        self.mode = mode

    def run(self):
        """
        This method runs in the background thread.
        Qt calls this automatically when start() is called.

        We wrap everything in try/except because any
        unhandled exception in a thread would crash
        silently without this protection.
        The error signal sends the message back to
        the main thread where the GUI can display it.
        """
        try:
            self.progress.emit(
                f"Starting {self.operation} on "
                f"{self.folder_path}..."
            )

            if self.operation == "lock":
                # Call manager.lock() in background thread
                result = lock(
                    Path(self.folder_path),
                    self.password,
                    self.mode
                )
            else:
                # Call manager.unlock() in background thread
                result = unlock(
                    Path(self.folder_path),
                    self.password
                )

            # Send result back to main thread via signal
            self.finished.emit(result)

        except Exception as e:
            # Send error message back to main thread
            self.error.emit(str(e))


# ─────────────────────────────────────────────
# SetupScreen
#
# Shown only on first launch when no master
# password has been configured yet.
# Creates the password and shows the recovery key.
# ─────────────────────────────────────────────

class SetupScreen(QWidget):
    # setup_complete is emitted when the user
    # acknowledges saving their recovery key.
    # MainWindow connects this to _show_login().
    setup_complete = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        """
        Build the setup screen layout.

        QVBoxLayout arranges widgets vertically
        top to bottom. setSpacing controls the
        gap between widgets. setContentsMargins
        sets the padding around the edges.
        """
        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(40, 40, 40, 40)

        # Title label
        # QFont("Segoe UI", 20, QFont.Weight.Bold) sets
        # the font family, size in points, and weight.
        title = QLabel("Welcome to FolderLocker")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel(
            "Create a master password to get started."
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(
            "color: #666666; font-size: 13px;"
        )

        # Password rules hint box
        # Shown so the user knows what the rules are
        # before they try and get rejected.
        rules_label = QLabel(
            "Password must be 8+ characters with uppercase, "
            "lowercase, number and special character. "
            "No spaces allowed."
        )
        rules_label.setWordWrap(True)
        rules_label.setStyleSheet("""
            color: #6b7280;
            font-size: 11px;
            background-color: #f3f4f6;
            border-radius: 6px;
            padding: 8px;
        """)

        # QLineEdit is a single line text input.
        # EchoMode.Password replaces typed characters
        # with dots so the password is not visible.
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(
            "Enter master password"
        )
        self.password_input.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        self.password_input.setMinimumHeight(40)

        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText(
            "Confirm master password"
        )
        self.confirm_input.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        self.confirm_input.setMinimumHeight(40)

        # Status label shows error messages in red
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.status_label.setStyleSheet(
            "color: #cc0000; font-size: 12px;"
        )

        create_btn = QPushButton("Create Password")
        create_btn.setMinimumHeight(42)
        create_btn.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: white;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:pressed { background-color: #1e40af; }
        """)
        # clicked.connect wires the button click event
        # to our handler method. When the button is
        # clicked Qt calls _handle_create automatically.
        create_btn.clicked.connect(self._handle_create)

        # addStretch() adds empty flexible space that
        # pushes content toward the center of the screen.
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(10)
        layout.addWidget(rules_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_input)
        layout.addWidget(self.status_label)
        layout.addWidget(create_btn)
        layout.addStretch()

        self.setLayout(layout)

    def _handle_create(self):
        """
        Called when the user clicks Create Password.
        Validates inputs, sets the password, shows
        the recovery key screen.
        """
        password = self.password_input.text()
        confirm = self.confirm_input.text()

        if not password or not confirm:
            self.status_label.setText(
                "Please fill in both fields."
            )
            return

        if password != confirm:
            self.status_label.setText(
                "Passwords do not match."
            )
            return

        try:
            # set_master_password validates strength,
            # hashes with PBKDF2, stores in keyring,
            # generates and stores recovery key hash,
            # and returns the plaintext recovery key.
            recovery_key = set_master_password(password)
            self._show_recovery_key(recovery_key)
        except ValueError as e:
            self.status_label.setText(str(e))

    def _show_recovery_key(self, recovery_key: str):
        """
        Replace the setup form with the recovery key display.
        The user must click confirm before they can proceed.
        The recovery key is shown exactly once here.
        It is never stored in plaintext anywhere on disk.
        """
        # Clear all widgets from the current layout
        while self.layout().count():
            item = self.layout().takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        layout = self.layout()
        layout.setSpacing(16)
        layout.setContentsMargins(40, 40, 40, 40)

        title = QLabel("Save your recovery key")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        warning = QLabel(
            "This key is shown ONCE and never stored in "
            "plaintext. If you forget your password this "
            "is your only way back in. Write it down and "
            "store it somewhere safe offline."
        )
        warning.setWordWrap(True)
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning.setStyleSheet("""
            color: #92400e;
            font-size: 12px;
            background-color: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 10px;
        """)

        # Display the recovery key in a styled box.
        # TextSelectableByMouse allows the user to
        # click and drag to select and copy the key.
        key_display = QLabel(recovery_key)
        key_display.setFont(
            QFont("Consolas", 18, QFont.Weight.Bold)
        )
        key_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        key_display.setStyleSheet("""
            color: #1e40af;
            background-color: #eff6ff;
            border: 2px solid #3b82f6;
            border-radius: 8px;
            padding: 16px;
            letter-spacing: 2px;
        """)
        key_display.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        confirm_btn = QPushButton(
            "I have saved my recovery key — Continue"
        )
        confirm_btn.setMinimumHeight(42)
        confirm_btn.setStyleSheet("""
            QPushButton {
                background-color: #16a34a;
                color: white;
                border-radius: 6px;
                font-size: 13px;
            }
            QPushButton:hover { background-color: #15803d; }
            QPushButton:pressed { background-color: #166534; }
        """)
        # Emit setup_complete signal when user confirms.
        # MainWindow listens for this and switches
        # to the login screen.
        confirm_btn.clicked.connect(self.setup_complete.emit)

        layout.addStretch()
        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addWidget(warning)
        layout.addSpacing(10)
        layout.addWidget(key_display)
        layout.addSpacing(10)
        layout.addWidget(confirm_btn)
        layout.addStretch()


# ─────────────────────────────────────────────
# LoginScreen
#
# Shown on every launch after setup is complete.
# Verifies the master password before showing
# the dashboard.
# ─────────────────────────────────────────────

class LoginScreen(QWidget):
    # login_success carries the verified password
    # to the dashboard so it can use it for operations.
    login_success = pyqtSignal(str)

    # forgot_password signals MainWindow to show
    # the recovery screen instead of login.
    forgot_password = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(40, 40, 40, 40)

        title = QLabel("FolderLocker")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel(
            "Enter your master password to continue."
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(
            "color: #666666; font-size: 13px;"
        )

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(
            "Master password"
        )
        self.password_input.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        self.password_input.setMinimumHeight(40)
        # returnPressed fires when the user presses Enter.
        # This lets the user submit with Enter instead of
        # having to click the button.
        self.password_input.returnPressed.connect(
            self._handle_login
        )

        self.status_label = QLabel("")
        self.status_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.status_label.setStyleSheet(
            "color: #cc0000; font-size: 12px;"
        )

        login_btn = QPushButton("Unlock App")
        login_btn.setMinimumHeight(42)
        login_btn.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: white;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:pressed { background-color: #1e40af; }
        """)
        login_btn.clicked.connect(self._handle_login)

        forgot_btn = QPushButton("Forgot password?")
        forgot_btn.setMinimumHeight(32)
        forgot_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #6b7280;
                border: none;
                font-size: 12px;
            }
            QPushButton:hover { color: #374151; }
        """)
        forgot_btn.clicked.connect(self.forgot_password.emit)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(20)
        layout.addWidget(self.password_input)
        layout.addWidget(self.status_label)
        layout.addWidget(login_btn)
        layout.addWidget(forgot_btn)
        layout.addStretch()

        self.setLayout(layout)

    def _handle_login(self):
        """
        Called when user clicks Unlock App or presses Enter.
        Verifies the password and emits login_success
        with the verified password if correct.
        """
        password = self.password_input.text()

        if not password:
            self.status_label.setText(
                "Please enter your password."
            )
            return

        try:
            if verify_master_password(password):
                # Emit the signal carrying the password.
                # MainWindow connects this to _show_dashboard
                # which passes the password to Dashboard.
                self.login_success.emit(password)
            else:
                self.status_label.setText(
                    "Incorrect password. Try again."
                )
                self.password_input.clear()
        except RuntimeError as e:
            self.status_label.setText(str(e))


# ─────────────────────────────────────────────
# RecoveryScreen
#
# Shown when user clicks Forgot Password.
# Accepts the recovery key and a new password.
# Resets the master password if key is correct.
# ─────────────────────────────────────────────

class RecoveryScreen(QWidget):
    # Carries the new password after successful reset
    recovery_complete = pyqtSignal(str)

    # Signals user wants to go back to login
    back_to_login = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(40, 40, 40, 40)

        title = QLabel("Recover access")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel(
            "Enter your recovery key and choose a new password."
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(
            "color: #666666; font-size: 13px;"
        )

        # Monospace font makes the recovery key
        # easier to read and type character by character.
        self.recovery_input = QLineEdit()
        self.recovery_input.setPlaceholderText(
            "Recovery key (XXXX-XXXX-XXXX-XXXX-XXXX)"
        )
        self.recovery_input.setMinimumHeight(40)
        self.recovery_input.setStyleSheet("""
            font-family: 'Consolas';
            font-size: 14px;
            letter-spacing: 1px;
        """)

        self.new_password_input = QLineEdit()
        self.new_password_input.setPlaceholderText(
            "New master password"
        )
        self.new_password_input.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        self.new_password_input.setMinimumHeight(40)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText(
            "Confirm new master password"
        )
        self.confirm_password_input.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        self.confirm_password_input.setMinimumHeight(40)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        self.status_label.setStyleSheet(
            "color: #cc0000; font-size: 12px;"
        )

        recover_btn = QPushButton("Reset Password")
        recover_btn.setMinimumHeight(42)
        recover_btn.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: white;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:pressed { background-color: #1e40af; }
        """)
        recover_btn.clicked.connect(self._handle_recovery)

        back_btn = QPushButton("Back to login")
        back_btn.setMinimumHeight(32)
        back_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #6b7280;
                border: none;
                font-size: 12px;
            }
            QPushButton:hover { color: #374151; }
        """)
        back_btn.clicked.connect(self.back_to_login.emit)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(10)
        layout.addWidget(self.recovery_input)
        layout.addWidget(self.new_password_input)
        layout.addWidget(self.confirm_password_input)
        layout.addWidget(self.status_label)
        layout.addWidget(recover_btn)
        layout.addWidget(back_btn)
        layout.addStretch()

        self.setLayout(layout)

    def _handle_recovery(self):
        """
        Called when user clicks Reset Password.
        Verifies recovery key, validates new password,
        resets and shows new recovery key.
        """
        recovery_key = self.recovery_input.text().strip()
        new_password = self.new_password_input.text()
        confirm = self.confirm_password_input.text()

        if not recovery_key:
            self.status_label.setText(
                "Please enter your recovery key."
            )
            return

        if not new_password or not confirm:
            self.status_label.setText(
                "Please fill in both password fields."
            )
            return

        if new_password != confirm:
            self.status_label.setText(
                "Passwords do not match."
            )
            return

        try:
            # recover_with_key verifies the recovery key,
            # validates the new password strength,
            # stores the new password hash,
            # generates and stores a new recovery key hash,
            # returns the new plaintext recovery key.
            new_recovery = recover_with_key(
                recovery_key,
                new_password
            )
            self._show_new_recovery_key(
                new_password,
                new_recovery
            )
        except ValueError as e:
            self.status_label.setText(str(e))
        except RuntimeError as e:
            self.status_label.setText(str(e))

    def _show_new_recovery_key(
        self,
        new_password: str,
        new_recovery_key: str
    ):
        """
        Show the new recovery key after successful reset.
        Old recovery key is now permanently invalid.
        User must save new key before continuing.
        """
        while self.layout().count():
            item = self.layout().takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        layout = self.layout()
        layout.setSpacing(16)
        layout.setContentsMargins(40, 40, 40, 40)

        title = QLabel("Password reset successful")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        warning = QLabel(
            "Your old recovery key is now invalid. "
            "Save this new recovery key immediately "
            "before continuing."
        )
        warning.setWordWrap(True)
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning.setStyleSheet("""
            color: #92400e;
            font-size: 12px;
            background-color: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 10px;
        """)

        key_display = QLabel(new_recovery_key)
        key_display.setFont(
            QFont("Consolas", 18, QFont.Weight.Bold)
        )
        key_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        key_display.setStyleSheet("""
            color: #1e40af;
            background-color: #eff6ff;
            border: 2px solid #3b82f6;
            border-radius: 8px;
            padding: 16px;
            letter-spacing: 2px;
        """)
        key_display.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        confirm_btn = QPushButton(
            "I have saved my recovery key — Continue"
        )
        confirm_btn.setMinimumHeight(42)
        confirm_btn.setStyleSheet("""
            QPushButton {
                background-color: #16a34a;
                color: white;
                border-radius: 6px;
                font-size: 13px;
            }
            QPushButton:hover { background-color: #15803d; }
            QPushButton:pressed { background-color: #166534; }
        """)
        confirm_btn.clicked.connect(
            lambda: self.recovery_complete.emit(new_password)
        )

        layout.addStretch()
        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addWidget(warning)
        layout.addSpacing(10)
        layout.addWidget(key_display)
        layout.addSpacing(10)
        layout.addWidget(confirm_btn)
        layout.addStretch()


# ─────────────────────────────────────────────
# Dashboard
#
# The main screen after login.
# Folder picker, mode selection, lock/unlock,
# progress bar, and activity log.
# ─────────────────────────────────────────────

class Dashboard(QWidget):
    def __init__(self, password: str, main_window=None):
        """
        password
            The verified master password from login.
            Stored in memory for use in lock/unlock.
            Never written to disk from here.

        main_window
            Reference to MainWindow so we can access
            the tray manager for icon updates and
            balloon notifications.
        """
        super().__init__()
        self.password = password
        self.main_window = main_window
        self.folder_path = None
        self.worker = None
        self.selected_mode = "full"

        # QTimer drives the progress bar pulse animation.
        # It fires every 30ms calling _pulse_progress.
        self._pulse_timer = QTimer()
        self._pulse_value = 0
        self._pulse_direction = 1

        self._build_ui()

    def _build_ui(self):
        """
        Build the dashboard layout.
        All widgets are created and arranged here.
        """
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(30, 24, 30, 24)

        title = QLabel("FolderLocker")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))

        subtitle = QLabel("Select a folder to lock or unlock.")
        subtitle.setStyleSheet(
            "color: #666666; font-size: 13px;"
        )

        # ── Folder picker ──────────────────────────────
        # QHBoxLayout arranges widgets horizontally
        # side by side left to right.
        folder_row = QHBoxLayout()

        # This label shows the selected folder path.
        # It starts with placeholder text.
        self.folder_label = QLabel("No folder selected")
        self.folder_label.setStyleSheet("""
            background-color: #f3f4f6;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            padding: 8px 12px;
            color: #374151;
            font-size: 13px;
        """)
        self.folder_label.setMinimumHeight(40)

        browse_btn = QPushButton("Browse")
        browse_btn.setMinimumHeight(40)
        browse_btn.setMinimumWidth(90)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #f9fafb;
                border: 1px solid #d1d5db;
                border-radius: 6px;
                font-size: 13px;
                padding: 0 12px;
            }
            QPushButton:hover { background-color: #f3f4f6; }
        """)
        browse_btn.clicked.connect(self._browse_folder)

        folder_row.addWidget(self.folder_label)
        folder_row.addWidget(browse_btn)

        # ── Status indicator ───────────────────────────
        # Shows whether the selected folder is locked
        # or unlocked with a colored dot and text.
        self.status_frame = QFrame()
        self.status_frame.setMinimumHeight(44)
        self.status_frame.setStyleSheet("""
            QFrame {
                background-color: #f3f4f6;
                border-radius: 6px;
                border: 1px solid #d1d5db;
            }
        """)
        status_layout = QHBoxLayout(self.status_frame)

        # The colored dot — gray, red, or green
        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(
            "color: #9ca3af; font-size: 16px;"
        )

        self.status_text = QLabel(
            "Select a folder to see its status"
        )
        self.status_text.setStyleSheet(
            "color: #6b7280; font-size: 13px;"
        )
        status_layout.addWidget(self.status_dot)
        status_layout.addWidget(self.status_text)
        status_layout.addStretch()

        # ── Mode selection ─────────────────────────────
        # Three checkable buttons — only one active at a time.
        # setCheckable(True) makes the button stay pressed
        # when clicked, like a toggle button.
        mode_label = QLabel("Lock mode")
        mode_label.setStyleSheet(
            "color: #374151; font-size: 13px; "
            "font-weight: 500;"
        )

        self.mode_full = QPushButton("Full")
        self.mode_full.setCheckable(True)
        self.mode_full.setChecked(True)
        self.mode_full.setToolTip(
            "ACL lock + encrypt everything.\n"
            "Best for personal files, photos, documents."
        )

        self.mode_soft = QPushButton("Soft")
        self.mode_soft.setCheckable(True)
        self.mode_soft.setToolTip(
            "ACL lock only, no encryption.\n"
            "Best for program folders that must keep running."
        )

        self.mode_smart = QPushButton("Smart")
        self.mode_smart.setCheckable(True)
        self.mode_smart.setToolTip(
            "ACL lock on all files.\n"
            "Encrypts data files only, skips executables.\n"
            "Best for store or business software protection."
        )

        # Shared style for all three mode buttons.
        # :checked selector applies when the button
        # is in its pressed/selected state.
        # :hover:!checked means hover but only when
        # not currently checked — prevents hover style
        # overriding the checked blue background.
        mode_btn_style = """
            QPushButton {
                border: 1px solid #d1d5db;
                border-radius: 6px;
                font-size: 13px;
                padding: 6px 16px;
                background-color: #f9fafb;
                color: #374151;
            }
            QPushButton:checked {
                background-color: #2563eb;
                color: white;
                border: 1px solid #2563eb;
            }
            QPushButton:hover:!checked {
                background-color: #f3f4f6;
            }
        """
        self.mode_full.setStyleSheet(mode_btn_style)
        self.mode_soft.setStyleSheet(mode_btn_style)
        self.mode_smart.setStyleSheet(mode_btn_style)

        # lambda creates a small anonymous function.
        # We use it here to pass the mode string
        # to _select_mode when the button is clicked.
        # Without lambda all three buttons would share
        # the same variable reference and all pass "smart".
        self.mode_full.clicked.connect(
            lambda: self._select_mode("full")
        )
        self.mode_soft.clicked.connect(
            lambda: self._select_mode("soft")
        )
        self.mode_smart.clicked.connect(
            lambda: self._select_mode("smart")
        )

        mode_row = QHBoxLayout()
        mode_row.setSpacing(8)
        mode_row.addWidget(mode_label)
        mode_row.addWidget(self.mode_full)
        mode_row.addWidget(self.mode_soft)
        mode_row.addWidget(self.mode_smart)
        mode_row.addStretch()

        # Description of the currently selected mode
        self.mode_desc = QLabel(
            "Full lock — ACL + encrypt everything"
        )
        self.mode_desc.setStyleSheet(
            "color: #6b7280; font-size: 12px; padding: 2px 0;"
        )

        # ── Progress bar ───────────────────────────────
        # Shown during lock/unlock operations.
        # Pulses back and forth because we do not know
        # exactly how long the operation will take.
        # Hidden by default — shown only during operations.
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(8)
        self.progress_bar.setMaximumHeight(8)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #f3f4f6;
                border-radius: 4px;
                border: none;
            }
            QProgressBar::chunk {
                background-color: #2563eb;
                border-radius: 4px;
            }
        """)
        self.progress_bar.hide()

        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet(
            "color: #6b7280; font-size: 12px;"
        )
        self.progress_label.hide()

        # ── Divider ────────────────────────────────────
        # A horizontal line separating sections.
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("color: #e5e7eb;")

        # ── Action buttons ─────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.lock_btn = QPushButton("Lock Folder")
        self.lock_btn.setMinimumHeight(44)
        # Disabled until a folder is selected.
        # setEnabled(False) grays out the button
        # and prevents click events.
        self.lock_btn.setEnabled(False)
        self.lock_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc2626;
                color: white;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #b91c1c; }
            QPushButton:pressed { background-color: #991b1b; }
            QPushButton:disabled {
                background-color: #fca5a5;
                color: white;
            }
        """)
        self.lock_btn.clicked.connect(self._handle_lock)

        self.unlock_btn = QPushButton("Unlock Folder")
        self.unlock_btn.setMinimumHeight(44)
        self.unlock_btn.setEnabled(False)
        self.unlock_btn.setStyleSheet("""
            QPushButton {
                background-color: #16a34a;
                color: white;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #15803d; }
            QPushButton:pressed { background-color: #166534; }
            QPushButton:disabled {
                background-color: #86efac;
                color: white;
            }
        """)
        self.unlock_btn.clicked.connect(self._handle_unlock)

        btn_row.addWidget(self.lock_btn)
        btn_row.addWidget(self.unlock_btn)

        # ── Activity log ───────────────────────────────
        # A dark terminal-style panel showing timestamped
        # log entries of all operations.
        # Read-only — users can read but not edit.
        log_header_row = QHBoxLayout()

        log_label = QLabel("Activity log")
        log_label.setStyleSheet(
            "color: #374151; font-size: 13px; "
            "font-weight: 500;"
        )

        self.clear_log_btn = QPushButton("Clear")
        self.clear_log_btn.setMaximumWidth(60)
        self.clear_log_btn.setMaximumHeight(26)
        self.clear_log_btn.setStyleSheet("""
            QPushButton {
                background-color: #f9fafb;
                border: 1px solid #d1d5db;
                border-radius: 4px;
                font-size: 12px;
                color: #6b7280;
            }
            QPushButton:hover { background-color: #f3f4f6; }
        """)
        self.clear_log_btn.clicked.connect(self._clear_log)

        log_header_row.addWidget(log_label)
        log_header_row.addStretch()
        log_header_row.addWidget(self.clear_log_btn)

        # QTextEdit is a multi-line text widget.
        # setReadOnly(True) prevents editing.
        # We use HTML formatting for colored text.
        self.log_panel = QTextEdit()
        self.log_panel.setReadOnly(True)
        self.log_panel.setMinimumHeight(140)
        self.log_panel.setMaximumHeight(140)
        self.log_panel.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #94a3b8;
                border-radius: 6px;
                border: 1px solid #1e293b;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        self.log_panel.setPlaceholderText(
            "Activity will appear here after each operation..."
        )

        # Add all widgets to the main layout
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(6)
        layout.addLayout(folder_row)
        layout.addWidget(self.status_frame)
        layout.addLayout(mode_row)
        layout.addWidget(self.mode_desc)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.progress_label)
        layout.addWidget(divider)
        layout.addLayout(btn_row)
        layout.addSpacing(4)
        layout.addLayout(log_header_row)
        layout.addWidget(self.log_panel)

        self.setLayout(layout)

        # Connect the pulse timer to the animation method.
        # timeout signal fires every N milliseconds.
        # We set the interval in _start_progress.
        self._pulse_timer.timeout.connect(self._pulse_progress)

    # ── Logging ───────────────────────────────────────────

    def _log(self, message: str, level: str = "info"):
        """
        Write a timestamped colored entry to the log panel.

        level controls the text color:
          info    → gray   (neutral activity)
          success → green  (operation completed)
          error   → red    (something failed)
          warning → amber  (partial success)

        We use HTML span tags with inline color styles
        because QTextEdit supports rich HTML formatting.
        The timestamp is always shown in a muted gray
        regardless of the log level.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "info":    "#94a3b8",
            "success": "#4ade80",
            "error":   "#f87171",
            "warning": "#fbbf24",
        }
        color = colors.get(level, "#94a3b8")
        self.log_panel.append(
            f'<span style="color:#475569">[{timestamp}]</span> '
            f'<span style="color:{color}">{message}</span>'
        )
        # Auto scroll to bottom so the latest entry
        # is always visible without manual scrolling.
        self.log_panel.verticalScrollBar().setValue(
            self.log_panel.verticalScrollBar().maximum()
        )

    def _clear_log(self):
        """Clear all entries from the activity log."""
        self.log_panel.clear()

    # ── Progress bar animation ────────────────────────────

    def _start_progress(self, message: str):
        """
        Show the progress bar and start the pulse animation.
        Called at the start of every lock/unlock operation.
        """
        self.progress_bar.show()
        self.progress_label.show()
        self.progress_label.setText(message)
        self._pulse_value = 0
        self._pulse_direction = 1
        # Start the timer — fires every 30 milliseconds
        self._pulse_timer.start(30)

    def _stop_progress(self):
        """
        Hide the progress bar and stop the animation.
        Called when the operation completes or fails.
        """
        self._pulse_timer.stop()
        self.progress_bar.setValue(0)
        self.progress_bar.hide()
        self.progress_label.hide()
        self.progress_label.setText("")

    def _pulse_progress(self):
        """
        Called every 30ms by the timer.
        Moves the progress bar value up and down
        creating a smooth back-and-forth animation.

        We use a pulse instead of a real percentage
        because we do not know exactly how long the
        operation will take — it depends on how many
        files are in the folder.
        A pulse tells the user something is happening
        without pretending we know the exact progress.
        """
        self._pulse_value += self._pulse_direction * 2
        if self._pulse_value >= 100:
            self._pulse_direction = -1
        elif self._pulse_value <= 0:
            self._pulse_direction = 1
        self.progress_bar.setValue(self._pulse_value)

    # ── Mode selection ────────────────────────────────────

    def _select_mode(self, mode: str):
        """
        Called when a mode button is clicked.
        Ensures only one mode button is checked at a time
        and updates the description label to match.

        setChecked(True/False) sets the visual checked
        state of each button — only the selected one
        stays pressed, the others pop back out.
        """
        self.mode_full.setChecked(mode == "full")
        self.mode_soft.setChecked(mode == "soft")
        self.mode_smart.setChecked(mode == "smart")
        self.selected_mode = mode

        descriptions = {
            "full":  "Full lock — ACL + encrypt everything",
            "soft":  "Soft lock — ACL only, no encryption",
            "smart": "Smart lock — ACL on all, "
                     "encrypt data files only",
        }
        self.mode_desc.setText(descriptions[mode])

    # ── Folder selection ──────────────────────────────────

    def _browse_folder(self):
        """
        Open a folder picker dialog and store the
        selected path.

        QFileDialog.getExistingDirectory shows the
        standard Windows folder picker dialog.
        Returns the selected path as a string,
        or empty string if user cancelled.
        """
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder to Lock/Unlock",
            str(Path.home())
        )
        if folder:
            self.folder_path = folder
            self.folder_label.setText(folder)
            self._update_status()
            self._log(f"Selected folder: {folder}")

            # Notify the tray so the tooltip updates
            # to show the selected folder name.
            if (
                self.main_window is not None
                and self.main_window.tray is not None
            ):
                self.main_window.tray.set_folder(folder)

    # ── Status display ────────────────────────────────────

    def _update_status(self):
        """
        Check whether the selected folder is locked
        and update the status indicator accordingly.

        Red dot + "locked" text → folder is locked
        Green dot + "unlocked" text → folder is unlocked

        Also enables or disables the Lock/Unlock buttons
        based on current state — you cannot lock an
        already locked folder or unlock an unlocked one.
        """
        if not self.folder_path:
            return

        locked = is_locked(Path(self.folder_path))

        if locked:
            self.status_dot.setStyleSheet(
                "color: #dc2626; font-size: 16px;"
            )
            self.status_text.setText("This folder is locked")
            # Disable Lock (already locked)
            # Enable Unlock (can unlock)
            self.lock_btn.setEnabled(False)
            self.unlock_btn.setEnabled(True)
        else:
            self.status_dot.setStyleSheet(
                "color: #16a34a; font-size: 16px;"
            )
            self.status_text.setText("This folder is unlocked")
            # Enable Lock (can lock)
            # Disable Unlock (already unlocked)
            self.lock_btn.setEnabled(True)
            self.unlock_btn.setEnabled(False)

    def _set_buttons_enabled(self, enabled: bool):
        """
        Enable or disable both action buttons together.
        Called during operations to prevent double clicks.
        """
        self.lock_btn.setEnabled(enabled)
        self.unlock_btn.setEnabled(enabled)

    # ── Lock ──────────────────────────────────────────────

    def _handle_lock(self):
        """
        Called when user clicks Lock Folder.
        Starts the lock operation in a background thread.
        No password prompt needed here — the user already
        proved their identity at login. Locking does not
        require re-verification because it is a protective
        action, not an access action.
        """
        if not self.folder_path:
            return

        self._log(
            f"Locking [{self.selected_mode} mode]: "
            f"{self.folder_path}"
        )
        self._start_progress(
            f"Locking in {self.selected_mode} mode..."
        )
        self.lock_btn.setText("Locking...")
        self.unlock_btn.setText("Please wait...")
        self._set_buttons_enabled(False)

        # Create and start the background worker thread
        self.worker = LockWorker(
            "lock",
            self.folder_path,
            self.password,
            self.selected_mode
        )
        self.worker.finished.connect(self._on_lock_done)
        self.worker.error.connect(self._on_error)
        self.worker.progress.connect(
            lambda msg: self._log(msg)
        )
        self.worker.start()

    # ── Unlock ────────────────────────────────────────────

    def _handle_unlock(self):
        """
        Called when user clicks Unlock Folder.

        Unlike lock, unlock requires re-entering the
        master password. This is the second factor of
        presence verification:

        Why ask again even though they logged in?
            Login proves you knew the password when
            you opened the app — possibly hours ago.
            The app may have been left open and
            unattended since then.
            Anyone who walks up to the open screen
            could click Unlock without this check.
            Asking again proves the person at the
            keyboard right now knows the password —
            not just the person who opened the app.

        QInputDialog.getText shows a simple dialog
        with a password field and OK/Cancel buttons.
        It returns a tuple: (text, ok_clicked).
        ok is False if the user cancelled.
        """
        if not self.folder_path:
            return

        # Show password confirmation dialog
        password, ok = QInputDialog.getText(
            self,
            "Confirm your identity",
            "Enter master password to unlock:",
            QLineEdit.EchoMode.Password,
            ""
        )

        # User cancelled or left it empty — do nothing
        if not ok or not password:
            return

        # Verify the entered password before proceeding
        try:
            if not verify_master_password(password):
                self._log(
                    "Unlock denied — incorrect password.",
                    "error"
                )
                return
        except Exception as e:
            self._log(
                f"Password verification error: {e}",
                "error"
            )
            return

        # Password correct — proceed with unlock
        self._log(f"Unlocking: {self.folder_path}")
        self._start_progress("Unlocking folder...")
        self.lock_btn.setText("Please wait...")
        self.unlock_btn.setText("Unlocking...")
        self._set_buttons_enabled(False)

        # Use the re-entered password for the operation
        # not the stored self.password — this ensures
        # the password used for decryption is the one
        # the user just proved they know right now.
        self.worker = LockWorker(
            "unlock",
            self.folder_path,
            password,
            self.selected_mode
        )
        self.worker.finished.connect(self._on_unlock_done)
        self.worker.error.connect(self._on_error)
        self.worker.progress.connect(
            lambda msg: self._log(msg)
        )
        self.worker.start()

    # ── Operation completion handlers ─────────────────────

    def _on_lock_done(self, result: dict):
        """
        Called by LockWorker.finished signal when
        the lock operation completes.
        Runs on the main thread — safe to update GUI.
        """
        self._stop_progress()
        self.lock_btn.setText("Lock Folder")
        self.unlock_btn.setText("Unlock Folder")

        if result["success"]:
            self._log(
                f"Lock successful — mode: {result['mode']} — "
                f"{result['encrypted_files']} file(s) encrypted.",
                "success"
            )
            self._log(
                f"Folder: {result['folder']}", "success"
            )

            # Update tray icon to red locked state
            if (
                self.main_window is not None
                and self.main_window.tray is not None
            ):
                self.main_window.tray.set_locked(True)
                self.main_window.tray.notify(
                    "Folder Locked",
                    f"{Path(result['folder']).name} "
                    f"is now locked."
                )
        else:
            self._log(
                f"Lock failed: {result['error']}", "error"
            )
            if "details" in result:
                for item in result["details"]:
                    self._log(
                        f"  Failed: {item['file']} — "
                        f"{item['error']}",
                        "error"
                    )

        self._update_status()

    def _on_unlock_done(self, result: dict):
        """
        Called by LockWorker.finished signal when
        the unlock operation completes.
        Runs on the main thread — safe to update GUI.
        """
        self._stop_progress()
        self.lock_btn.setText("Lock Folder")
        self.unlock_btn.setText("Unlock Folder")

        if result["success"]:
            self._log(
                f"Unlock successful — mode: {result['mode']} — "
                f"{result['decrypted_files']} file(s) decrypted.",
                "success"
            )
            self._log(
                f"Folder: {result['folder']}", "success"
            )
            self._log(
                "Explorer monitor active — close the "
                "folder window to auto relock.",
                "info"
            )

            # Update tray icon to green unlocked state
            if (
                self.main_window is not None
                and self.main_window.tray is not None
            ):
                self.main_window.tray.set_locked(False)
                self.main_window.tray.notify(
                    "Folder Unlocked",
                    f"{Path(result['folder']).name} "
                    f"is now unlocked. Close the Explorer "
                    f"window to auto relock."
                )
        else:
            self._log(
                f"Unlock failed: {result['error']}", "error"
            )
            if "details" in result:
                for item in result["details"]:
                    self._log(
                        f"  Failed: {item['file']} — "
                        f"{item['error']}",
                        "error"
                    )

        self._update_status()

    def _on_error(self, error_message: str):
        """
        Called by LockWorker.error signal when an
        unexpected exception occurs in the background thread.
        """
        self._stop_progress()
        self.lock_btn.setText("Lock Folder")
        self.unlock_btn.setText("Unlock Folder")
        self._log(f"Error: {error_message}", "error")
        self._update_status()


# ─────────────────────────────────────────────
# MainWindow
#
# The root window that hosts all screens.
# Uses QStackedWidget to switch between screens
# without opening new windows.
# Only one screen is visible at a time.
# ─────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FolderLocker")
        self.setMinimumSize(520, 700)
        self.setMaximumSize(520, 700)

        # current_folder_path is used by the tray
        # to show the folder name in the tooltip.
        self.current_folder_path = None

        # Tray is None until after first login.
        # We initialize it in _show_dashboard because
        # TrayManager creates QPixmap icons which
        # require QApplication to exist first.
        self.tray = None

        # QStackedWidget holds multiple screens
        # but only shows one at a time.
        # We add screens to it and call setCurrentWidget
        # to switch between them.
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self._apply_global_style()
        self._load_initial_screen()

    def _apply_global_style(self):
        """
        Apply app-wide stylesheet.
        These styles apply to all child widgets
        unless overridden by widget-specific styles.
        """
        self.setStyleSheet("""
            QMainWindow { background-color: #ffffff; }
            QWidget {
                background-color: #ffffff;
                font-family: 'Segoe UI';
            }
            QLineEdit {
                border: 1px solid #d1d5db;
                border-radius: 6px;
                padding: 0 12px;
                font-size: 13px;
                color: #111827;
            }
            QLineEdit:focus { border: 1px solid #2563eb; }
        """)

    def _load_initial_screen(self):
        """
        Decide which screen to show on startup.
        If no password is set → show setup screen.
        If password exists → show login screen.
        """
        if not is_password_set():
            self._show_setup()
        else:
            self._show_login()

    def _show_setup(self):
        """Create and show the setup screen."""
        screen = SetupScreen()
        # When setup completes show the login screen
        screen.setup_complete.connect(self._show_login)
        self.stack.addWidget(screen)
        self.stack.setCurrentWidget(screen)

    def _show_login(self):
        """Create and show the login screen."""
        screen = LoginScreen()
        # When login succeeds show the dashboard
        screen.login_success.connect(self._show_dashboard)
        # When forgot password is clicked show recovery
        screen.forgot_password.connect(self._show_recovery)
        self.stack.addWidget(screen)
        self.stack.setCurrentWidget(screen)

    def _show_recovery(self):
        """Create and show the recovery screen."""
        screen = RecoveryScreen()
        # When recovery completes show dashboard
        screen.recovery_complete.connect(self._show_dashboard)
        # When back is clicked show login
        screen.back_to_login.connect(self._show_login)
        self.stack.addWidget(screen)
        self.stack.setCurrentWidget(screen)

    def _show_dashboard(self, password: str):
        screen = Dashboard(password, self)
        self.stack.addWidget(screen)
        self.stack.setCurrentWidget(screen)

        if self.tray is None:
            self.tray = TrayManager(
                main_window=self,
                on_lock=screen._handle_lock,
                on_unlock=screen._handle_unlock
            )

        # Restore the remembered locked folder.
        # get_remembered_folder checks AppData config
        # for a folder that was locked before the
        # app was closed or the machine rebooted.
        # If found we automatically select it on the
        # dashboard so the user can unlock immediately
        # without having to browse for it again.
        from src.manager.manager import get_remembered_folder
        remembered = get_remembered_folder()
        if remembered:
            folder = remembered.get("folder")
            mode = remembered.get("mode", "full")
            if folder:
                # Set the folder path on the dashboard
                screen.folder_path = folder
                screen.folder_label.setText(folder)
                # Set the correct mode
                screen._select_mode(mode)
                # Update status dot to show locked state
                screen._update_status()
                # Log that we restored the folder
                screen._log(
                    f"Restored locked folder: {folder}",
                    "warning"
                )
                screen._log(
                    "This folder was locked before the "
                    "app was closed. Enter your password "
                    "to unlock it.",
                    "info"
                )
                # Update tray tooltip
                if self.tray is not None:
                    self.tray.set_folder(folder)

    def closeEvent(self, event):
        """
        Intercept the window X button.
        Ask user whether to minimize to tray or exit.
        Cancel keeps the window open.

        closeEvent is a Qt method we override.
        Qt calls it automatically when the user
        clicks the X button or presses Alt+F4.
        event.ignore() tells Qt to cancel the close.
        event.accept() tells Qt to proceed with closing.
        """
        if self.tray is not None:
            dialog = QMessageBox(self)
            dialog.setWindowTitle("FolderLocker")
            dialog.setText("What would you like to do?")
            dialog.setInformativeText(
                "Minimize to tray keeps FolderLocker running "
                "in the background so auto lock stays active.\n\n"
                "Exit closes the app completely."
            )

            minimize_btn = dialog.addButton(
                "Minimize to tray",
                QMessageBox.ButtonRole.AcceptRole
            )
            exit_btn = dialog.addButton(
                "Exit",
                QMessageBox.ButtonRole.DestructiveRole
            )
            dialog.addButton(
                "Cancel",
                QMessageBox.ButtonRole.RejectRole
            )

            dialog.exec()
            clicked = dialog.clickedButton()

            if clicked == minimize_btn:
                # Hide window but keep process alive
                event.ignore()
                self.tray.intercept_close()

            elif clicked == exit_btn:
                # Stop tray and exit cleanly
                self.tray._auto_lock_timer.stop()
                self.tray._tray.hide()
                event.accept()
                QApplication.instance().quit()

            else:
                # Cancel — keep window open
                event.ignore()
        else:
            event.accept()


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def run():
    """
    Create the QApplication and launch the main window.

    QApplication must be created before any widgets.
    sys.argv passes command line arguments to Qt
    (Qt uses some of these internally for display setup).

    setQuitOnLastWindowClosed(False) keeps the app
    alive when the window is hidden to the tray.
    Without this Qt would exit when the window closes.

    sys.exit(app.exec()) starts the Qt event loop.
    app.exec() blocks here until the app quits.
    sys.exit() passes the exit code to the OS.
    """
    app = QApplication(sys.argv)
    app.setApplicationName("FolderLocker")

    # Keep app alive when window is hidden to tray
    app.setQuitOnLastWindowClosed(False)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()
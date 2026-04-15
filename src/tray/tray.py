from pathlib import Path
from PyQt6.QtWidgets import (
    QSystemTrayIcon,
    QMenu,
    QApplication,
)
from PyQt6.QtGui import (
    QIcon,
    QPixmap,
    QPainter,
    QColor,
    QBrush,
)
from PyQt6.QtCore import Qt, QTimer


def _make_icon(color: str) -> QIcon:
    """
    Generate a circular tray icon programmatically.
    Must only be called AFTER QApplication exists.
    QPixmap requires the display system to be ready.
    color: any valid hex color string e.g. '#dc2626'
    """
    pixmap = QPixmap(32, 32)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(2, 2, 28, 28)
    painter.end()
    return QIcon(pixmap)


class TrayManager:
    """
    Manages the system tray icon and context menu.

    Responsibilities:
      - Show app icon in system tray at all times
      - Reflect lock state via icon color
      - Provide right click menu for quick actions
      - Run auto lock countdown timer
      - Handle minimize to tray behaviour

    The tray is the app's background presence.
    Think of it as a security guard always on duty
    even when the main office window is closed.
    The guard stays visible in the corner of the screen.
    The office can open or close without the guard
    going off duty.
    """

    def __init__(self, main_window, on_lock, on_unlock):
        """
        main_window → the MainWindow instance
        on_lock     → callable that triggers lock
        on_unlock   → callable that triggers unlock

        Icons are created here — after QApplication exists.
        Creating QPixmap before QApplication causes a crash.
        """
        self.main_window = main_window
        self.on_lock = on_lock
        self.on_unlock = on_unlock
        self.is_locked = False
        self.auto_lock_minutes = 0
        self.auto_lock_enabled = False

        # Icons created after QApplication is ready
        self._icon_locked   = _make_icon("#dc2626")
        self._icon_unlocked = _make_icon("#16a34a")
        self._icon_idle     = _make_icon("#6b7280")

        self._auto_lock_timer = QTimer()
        self._auto_lock_timer.timeout.connect(
            self._handle_auto_lock
        )

        self._tray = QSystemTrayIcon()
        self._tray.setIcon(self._icon_idle)
        self._tray.setToolTip(
            "FolderLocker — No folder selected"
        )
        self._tray.activated.connect(self._handle_activation)

        self._build_menu()
        self._tray.show()

    def _build_menu(self):
        """Build the right click context menu."""
        menu = QMenu()

        title_action = menu.addAction("FolderLocker")
        title_action.setEnabled(False)
        menu.addSeparator()

        self._open_action = menu.addAction("Open")
        self._open_action.triggered.connect(self._show_window)

        menu.addSeparator()

        self._lock_action = menu.addAction("Lock folder")
        self._lock_action.triggered.connect(self._handle_lock)
        self._lock_action.setEnabled(False)

        self._unlock_action = menu.addAction("Unlock folder")
        self._unlock_action.triggered.connect(
            self._handle_unlock
        )
        self._unlock_action.setEnabled(False)

        menu.addSeparator()

        auto_lock_menu = menu.addMenu("Auto lock")
        options = [
            ("Off",            0),
            ("After 1 minute", 1),
            ("After 5 minutes", 5),
            ("After 15 minutes", 15),
            ("After 30 minutes", 30),
        ]
        for label, minutes in options:
            action = auto_lock_menu.addAction(label)
            action.triggered.connect(
                lambda checked, m=minutes: self._set_auto_lock(m)
            )

        menu.addSeparator()

        exit_action = menu.addAction("Exit FolderLocker")
        exit_action.triggered.connect(self._handle_exit)

        self._tray.setContextMenu(menu)

    def _show_window(self):
        """Bring the main window to the front."""
        self.main_window.show()
        self.main_window.raise_()
        self.main_window.activateWindow()

    def _handle_activation(self, reason):
        """Single or double click opens the main window."""
        if reason in (
            QSystemTrayIcon.ActivationReason.DoubleClick,
            QSystemTrayIcon.ActivationReason.Trigger,
        ):
            self._show_window()

    def _handle_lock(self):
        self._show_window()
        self.on_lock()

    def _handle_unlock(self):
        self._show_window()
        self.on_unlock()

    def _handle_exit(self):
        """
        Fully exit the application.
        Hides tray icon first to prevent ghost icons
        remaining in the tray after the process ends.
        """
        self._auto_lock_timer.stop()
        self._tray.hide()
        QApplication.instance().quit()

    def _set_auto_lock(self, minutes: int):
        """Configure auto lock timer. 0 = disabled."""
        self._auto_lock_timer.stop()
        self.auto_lock_minutes = minutes
        self.auto_lock_enabled = minutes > 0

        if self.auto_lock_enabled and not self.is_locked:
            self._auto_lock_timer.start(minutes * 60 * 1000)
            self._tray.showMessage(
                "FolderLocker",
                f"Auto lock set to {minutes} minute(s).",
                QSystemTrayIcon.MessageIcon.Information,
                3000
            )
        else:
            self._tray.showMessage(
                "FolderLocker",
                "Auto lock disabled.",
                QSystemTrayIcon.MessageIcon.Information,
                3000
            )
        self._update_tooltip()

    def _handle_auto_lock(self):
        """Called when auto lock timer fires."""
        if not self.is_locked:
            self._auto_lock_timer.stop()
            self.on_lock()
            self._tray.showMessage(
                "FolderLocker",
                "Folder automatically locked.",
                QSystemTrayIcon.MessageIcon.Information,
                4000
            )

    def _update_tooltip(self):
        """Update tray icon tooltip to reflect current state."""
        state = "Locked" if self.is_locked else "Unlocked"
        auto = (
            f" | Auto lock: {self.auto_lock_minutes}min"
            if self.auto_lock_enabled else ""
        )
        folder = getattr(
            self.main_window, "current_folder_path", None
        )
        folder_name = (
            Path(folder).name if folder
            else "No folder selected"
        )
        self._tray.setToolTip(
            f"FolderLocker — {folder_name} — {state}{auto}"
        )

    def set_folder(self, folder_path: str):
        """Called when user selects a folder."""
        self.main_window.current_folder_path = folder_path
        self._update_tooltip()

    def set_locked(self, locked: bool):
        """Update tray state after lock or unlock."""
        self.is_locked = locked
        if locked:
            self._tray.setIcon(self._icon_locked)
            self._lock_action.setEnabled(False)
            self._unlock_action.setEnabled(True)
            self._auto_lock_timer.stop()
        else:
            self._tray.setIcon(self._icon_unlocked)
            self._lock_action.setEnabled(True)
            self._unlock_action.setEnabled(False)
            if self.auto_lock_enabled:
                self._auto_lock_timer.start(
                    self.auto_lock_minutes * 60 * 1000
                )
        self._update_tooltip()

    def set_no_folder(self):
        """Called when no folder is selected."""
        self._tray.setIcon(self._icon_idle)
        self._lock_action.setEnabled(False)
        self._unlock_action.setEnabled(False)
        self._update_tooltip()

    def notify(self, title: str, message: str):
        """Show a system notification balloon."""
        self._tray.showMessage(
            title,
            message,
            QSystemTrayIcon.MessageIcon.Information,
            4000
        )

    def intercept_close(self):
        """
        Hides the window instead of closing the app.
        App stays alive for auto lock and tray access.
        """
        self.main_window.hide()
        self._tray.showMessage(
            "FolderLocker",
            "FolderLocker is running in the background. "
            "Right click the tray icon to open or exit.",
            QSystemTrayIcon.MessageIcon.Information,
            4000
        )
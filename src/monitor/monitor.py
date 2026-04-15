"""
FolderLocker Monitor Module

Watches an unlocked folder using three independent
layers so that if any one layer fails the others
catch the relock trigger.

Layer 1 — COM window handle tracking
  Asks Windows Shell for all open Explorer windows
  every 2 seconds. When the window showing our
  folder disappears relock is triggered.
  This is the primary layer — fastest response.

Layer 2 — Process ID tracking
  Records the Windows Process ID of the Explorer
  process that opened our folder.
  Checks every 2 seconds if that process is still
  alive in the Windows process list.
  This is the failsafe for when COM fails.
  Works even if COM is completely unavailable.

Layer 3 — Session marker file
  Writes a unique .flsession file beside the
  locked folder when unlocking begins.
  Contains the session ID, folder path, PID
  and unlock timestamp as a JSON record.
  On app startup scans for orphaned .flsession
  files that indicate a folder was left unlocked
  after a crash or unexpected shutdown.
  This is the reboot and crash recovery layer.

Architecture adapted from the worker module
prototype using threading.Event for clean
shutdown across all monitoring threads.
"""

# time gives us time.sleep() and time.time().
# We use time.time() to record when the session
# started and to calculate elapsed time.
import time

# threading gives us Thread and Event.
# Thread runs our monitoring loops in the background
# without blocking the GUI main thread.
# Event is a thread safe flag that lets us signal
# all threads to stop cleanly at the same time.
import threading

# logging gives us the named logger system.
# All log lines from this module are prefixed
# with FolderLocker.monitor for easy filtering.
import logging

# json lets us read and write the session marker
# file as human readable structured data.
import json

# os gives us os.path operations and os.getpid()
# for working with process IDs and file paths.
import os

# secrets generates cryptographically secure
# random values for our unique session IDs.
# We use it instead of random because random
# is predictable — secrets is not.
import secrets
import ctypes
from ctypes import wintypes

# Path gives us clean cross platform file paths
# and useful methods like .exists() and .unlink()
from pathlib import Path

# datetime lets us record the unlock timestamp
# in the session marker file for audit purposes.
from datetime import datetime

# Callable is a type hint for functions we accept
# as parameters. Optional means the value can be
# None or the specified type.
from typing import Callable, Optional


# ─────────────────────────────────────────────
# win32 imports for COM and process checking
#
# win32com.client lets us talk to Windows COM
# objects — specifically Shell.Windows which
# gives us the list of open Explorer windows.
#
# pythoncom manages COM initialization per thread.
# COM requires CoInitialize() at the start of every
# thread that uses COM objects. Without it COM
# calls crash with cryptic errors.
#
# win32api and win32process let us check whether
# a Windows process ID is still alive.
# ─────────────────────────────────────────────
try:
    import win32com.client
    import pythoncom
    import win32api
    import win32process
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


# ─────────────────────────────────────────────
# watchdog imports for filesystem monitoring
#
# Observer is the watchdog background thread that
# watches a directory for file system events.
#
# FileSystemEventHandler is the base class we
# extend to handle specific file events like
# file creation, deletion, and modification.
# ─────────────────────────────────────────────
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


logger = logging.getLogger("FolderLocker.monitor")

# Our custom session file extension.
# Nothing else on Windows creates .flsession files
# so watchdog can filter exclusively on this.
SESSION_EXTENSION = ".flsession"

# Prefix for all our session marker filenames.
# Makes them easy to identify and scan for.
SESSION_PREFIX = "FL_"


# ─────────────────────────────────────────────
# Session marker management
#
# The session marker is a JSON file written beside
# the locked folder when unlock begins.
# It records everything we need to monitor and
# recover from crashes or unexpected shutdowns.
# ─────────────────────────────────────────────

def _generate_session_id() -> str:
    """
    Generate a unique session identifier.

    secrets.token_hex(4) generates 4 random bytes
    and returns them as an 8 character hex string.
    Example: 3a9f2b1c

    We prefix it with FL_ to make it identifiable.
    Full example: FL_3A9F2B1C

    Why secrets and not random?
      random.randint() is seeded by the system clock
      and is predictable if you know when it was called.
      secrets uses the OS cryptographic random source
      which is truly unpredictable.
      This prevents anyone from guessing session IDs.
    """
    return SESSION_PREFIX + secrets.token_hex(4).upper()


def _get_marker_path(folder_path: Path, session_id: str) -> Path:
    """
    Return the path for the session marker file.

    The marker sits BESIDE the locked folder in
    its parent directory — NOT inside the folder.

    Why beside and not inside?
      If we put it inside the folder and then apply
      the ACL lock we cannot delete it during relock
      because we are denied access to the folder.
      Beside means we can always reach and delete it.

    Example:
      folder:  C:/ProgramData
      marker:  C:/FL_3A9F2B1C.flsession

      
    """
    return folder_path.parent / (session_id + SESSION_EXTENSION)


def _write_marker(
    folder_path: Path,
    session_id: str,
    explorer_pid: Optional[int] = None
) -> Path:
    """
    Write the session marker file beside the folder.

    The marker contains:
      session_id    → unique ID for this unlock session
      folder        → which folder is unlocked
      explorer_pid  → PID of Explorer showing the folder
                      None if Explorer not yet opened
      unlocked_at   → ISO timestamp of when unlock happened
      hostname      → which machine this lock is on

    Returns the path to the created marker file.

    Why store hostname?
      If the folder is on a network drive and accessed
      from multiple machines this tells us which machine
      holds the unlock session.
    """
    marker_path = _get_marker_path(folder_path, session_id)
    data = {
        "session_id": session_id,
        "folder": str(folder_path),
        "explorer_pid": explorer_pid,
        "unlocked_at": datetime.now().isoformat(),
        "hostname": os.environ.get("COMPUTERNAME", "unknown")
    }
    marker_path.write_text(json.dumps(data, indent=2))
    logger.info(f"Session marker written: {marker_path}")
    return marker_path


def _delete_marker(marker_path: Path) -> None:
    """
    Delete the session marker file after relocking.

    We check exists() first to avoid errors if the
    file was already deleted by another trigger.
    This is safe to call multiple times — idempotent.
    """
    if marker_path and marker_path.exists():
        try:
            marker_path.unlink()
            logger.info(
                f"Session marker deleted: {marker_path}"
            )
        except Exception as e:
            logger.warning(
                f"Could not delete marker {marker_path}: {e}"
            )


def scan_for_orphaned_sessions() -> list:
    """
    PUBLIC function — called by the GUI on startup.

    Scans all drives for orphaned .flsession files
    that indicate folders left unlocked after a crash
    reboot or unexpected shutdown.

    Returns a list of dicts each containing:
      session_id → the session ID
      folder     → path of the unlocked folder
      marker     → path to the marker file

    How it works:
      We scan common locations where markers could be:
        Root of each drive letter C:/ D:/ etc.
        User profile folders
        Common data folders

      For each .flsession file found we read its
      contents and check if the folder still exists.
      If yes we add it to the orphaned list.
      The GUI shows these to the user and offers
      to relock them immediately.
    """
    orphaned = []

    # Build list of locations to scan
    # We scan drive roots and user directories
    scan_locations = []

    # Add root of each available drive letter
    for drive_letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = Path(f"{drive_letter}:\\")
        if drive.exists():
            scan_locations.append(drive)

    # Add user profile locations
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        scan_locations.append(Path(userprofile))
        scan_locations.append(
            Path(userprofile) / "Desktop"
        )

    # Scan each location for .flsession files
    for location in scan_locations:
        try:
            # glob finds all files matching the pattern
            # in the specified directory only (not recursive)
            # We only scan one level deep at drive roots
            # to avoid scanning the entire drive on startup.
            for marker_file in location.glob(
                f"*{SESSION_EXTENSION}"
            ):
                try:
                    data = json.loads(
                        marker_file.read_text()
                    )
                    folder = Path(data.get("folder", ""))

                    # Only report if folder still exists
                    if folder.exists():
                        orphaned.append({
                            "session_id": data.get(
                                "session_id"
                            ),
                            "folder": str(folder),
                            "marker": str(marker_file),
                            "unlocked_at": data.get(
                                "unlocked_at"
                            )
                        })
                        logger.warning(
                            f"Orphaned session found: "
                            f"{folder}"
                        )
                except Exception:
                    continue
        except Exception:
            continue

    return orphaned


# ─────────────────────────────────────────────
# Process ID checking
#
# Layer 2 of our monitoring system.
# Checks if the Explorer process that opened
# our folder is still alive in the process list.
# ─────────────────────────────────────────────

def _is_process_alive(pid: int) -> bool:
    """
    Check if a Windows process with the given PID
    is still running.

    We use win32api.OpenProcess to try opening a
    handle to the process. If it succeeds the process
    is alive. If it fails the process is gone.

    win32con.PROCESS_QUERY_INFORMATION is the minimum
    access right needed to query a process.
    It does not let us modify or terminate the process
    just check if it exists — safe and non-intrusive.

    Why not just check the process list directly?
      Scanning the entire process list is expensive.
      OpenProcess with a known PID is a direct lookup
      that Windows resolves instantly.
      Much faster for our 2-second check interval.
    """
    if not WIN32_AVAILABLE:
        return True

    if pid is None:
        return True

    try:
        # Try to open a handle to the process
        handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION,
            False,
            pid
        )
        if handle:
            # Process exists — close the handle
            # We must always close handles we open
            # or we leak Windows resources.
            win32api.CloseHandle(handle)
            return True
        return False
    except Exception:
        # OpenProcess raises an exception if the
        # process does not exist or we cannot access it.
        # Either way it means the process is gone.
        return False

def _get_explorer_windows() -> list:
    """
    Get all open Explorer windows using EnumWindows.

    This replaces the COM Shell.Windows approach which
    fails on some Windows 11 configurations with error
    -2147221005 meaning the Shell.Windows COM object
    is not registered or accessible in this process.

    EnumWindows is a direct Windows API call that asks
    Windows to show us every open window on the desktop.
    No COM required — it works at the raw Windows API
    level which is always available.

    How EnumWindows works:
      We define a callback function.
      Windows calls our callback once per open window
      passing the window handle (HWND) each time.
      We examine each HWND and keep the Explorer ones.

    How we identify Explorer windows:
      Every window in Windows has a class name —
      an internal identifier Windows assigns when the
      window is created. Explorer folder windows always
      use the class name CabinetWClass.
      We filter by this class name to find only
      Explorer folder windows and ignore everything else.

    Returns a list of dictionaries each containing:
      hwnd  → the unique window handle integer
      pid   → the explorer.exe process ID
      title → the folder name shown in the title bar
    """
    if not WIN32_AVAILABLE:
        return []

    import ctypes
    from ctypes import wintypes

    # Load the Windows DLLs we need for this function.
    # user32.dll handles window management operations.
    # kernel32.dll handles process operations.
    # psapi.dll lets us query process information.
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    # This list collects all Explorer windows found.
    # The callback function below adds to it.
    explorer_windows = []

    # Define the callback function type.
    # WINFUNCTYPE creates a Windows compatible function
    # type that Windows can call from native code.
    # Parameters:
    #   BOOL    → return type (True=continue, False=stop)
    #   HWND    → the window handle Windows passes us
    #   LPARAM  → extra data (we do not use this)
    WNDENUMPROC = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HWND,
        wintypes.LPARAM
    )

    def enum_callback(hwnd, lparam):
        """
        Windows calls this function once for every
        open window on the desktop.
        We examine the window and collect Explorer ones.
        We must return True to keep enumeration going.
        Returning False would stop Windows mid-enumeration.
        """
        try:
            # Get the window class name.
            # create_unicode_buffer allocates a 256
            # character buffer for the class name string.
            # GetClassNameW fills it with the class name.
            class_name = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, class_name, 256)

            # CabinetWClass is the class name for all
            # Explorer folder windows on Windows 10/11.
            # ExploreWClass is the older Windows XP style.
            # If the class name is neither we skip it.
            if class_name.value not in (
                "CabinetWClass",
                "ExploreWClass"
            ):
                # Return True to continue checking
                # other windows — do not stop here.
                return True

            # Get the process ID that owns this window.
            # GetWindowThreadProcessId fills our pid
            # variable with the owning process ID.
            # We ignore the thread ID (first return value).
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(
                hwnd,
                ctypes.byref(pid)
            )

            # Open a handle to the process so we can
            # read its executable name.
            # 0x0410 combines two access rights:
            #   PROCESS_QUERY_INFORMATION (0x0400)
            #   PROCESS_VM_READ (0x0010)
            # This lets us read the process name
            # without being able to modify the process.
            process_handle = kernel32.OpenProcess(
                0x0410,
                False,
                pid.value
            )

            if not process_handle:
                return True

            # Get the full path of the executable
            # running in this process.
            exe_name = ctypes.create_unicode_buffer(256)
            psapi.GetModuleFileNameExW(
                process_handle,
                None,
                exe_name,
                256
            )
            # Always close handles we open.
            # Not closing causes resource leaks.
            kernel32.CloseHandle(process_handle)

            # Check the executable is explorer.exe.
            # We use lower() so the check is case
            # insensitive — Windows is not case sensitive
            # for executable names.
            if "explorer.exe" not in exe_name.value.lower():
                return True

            # Get the window title text.
            # Explorer shows the current folder name
            # in the title bar of every window.
            title = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, title, 512)

            # Add this Explorer window to our results
            explorer_windows.append({
                "hwnd": hwnd,
                "pid": pid.value,
                "title": title.value
            })

        except Exception:
            # If anything goes wrong with one window
            # we skip it and continue with the others.
            pass

        # Always return True to keep enumeration going
        return True

    # Call EnumWindows passing our callback function.
    # Windows will call enum_callback once per window.
    # The second argument 0 is the LPARAM extra data
    # which we do not use so we pass 0.
    callback = WNDENUMPROC(enum_callback)
    user32.EnumWindows(callback, 0)

    return explorer_windows


def _get_explorer_pid_for_folder(
    folder_path: Path
) -> Optional[int]:
    """
    Find the Explorer process ID for the window
    currently showing our specific folder.

    Uses _get_explorer_windows() instead of COM.

    How we match the window to our folder:
      Explorer shows the folder name in the title bar.
      We compare the title against our folder name.
      If the folder name appears in the title we
      consider that window to be showing our folder
      and return its process ID.

    Why match by name and not full path?
      EnumWindows gives us the window title which
      is usually just the folder name not the full path.
      Example: our folder is C:/Users/Joseph/SecretFolder
      Explorer shows title: "SecretFolder"
      We match "secretfolder" against "secretfolder" ✓

    Returns the PID integer or None if not found.
    """
    windows = _get_explorer_windows()

    # Get just the folder name part of the path
    # Path.name gives us the last component only.
    # Example: Path("C:/Users/Joseph/SecretFolder").name
    # returns "SecretFolder"
    folder_name = folder_path.name.lower()

    for window in windows:
        title = window.get("title", "").lower()
        # Check if our folder name appears in the title
        if folder_name in title:
            return window.get("pid")

    return None

# ─────────────────────────────────────────────
# COM window tracking
#
# Layer 1 of our monitoring system.
# The primary and fastest relock trigger.
# ─────────────────────────────────────────────

def _get_open_explorer_paths() -> list:
    """
    Get all currently open Explorer window paths.

    Uses _get_explorer_windows() which uses EnumWindows
    instead of COM Shell.Windows.
    This avoids the -2147221005 COM error entirely.

    For each Explorer window we found we try to
    match its title to a real folder path on disk.

    Explorer shows the current folder name in its
    title bar. We use this to find the full path.

    Returns a list of resolved Path objects —
    one for each open Explorer folder window.
    Returns empty list if no Explorer windows are open.
    """
    results = []
    windows = _get_explorer_windows()

    for window in windows:
        title = window.get("title", "")
        if not title:
            continue

        # First attempt: check if the title itself
        # is a full folder path.
        # Some Explorer configurations show the full
        # path in the title bar instead of just the name.
        try:
            candidate = Path(title)
            if candidate.exists() and candidate.is_dir():
                results.append(candidate.resolve())
                continue
        except Exception:
            pass

        # Second attempt: search common parent folders
        # for a subfolder matching the title name.
        # Explorer usually shows just the folder name
        # not the full path in the title bar.
        # Example: title is "locker_test" and the
        # real path is C:/Users/Joseph/Desktop/locker_test
        common_parents = [
            Path.home(),
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path.home() / "Downloads",
            Path("C:/"),
            Path("C:/Users"),
            Path("C:/ProgramData"),
            Path("C:/Program Files"),
        ]

        for parent in common_parents:
            try:
                candidate = parent / title
                if (
                    candidate.exists()
                    and candidate.is_dir()
                ):
                    results.append(candidate.resolve())
                    break
            except Exception:
                continue

    return results


# ─────────────────────────────────────────────
# ExplorerWatcher
#
# Combines all three monitoring layers into one
# background thread. Adapted from the worker
# module prototype using threading.Event.
# ─────────────────────────────────────────────

class ExplorerWatcher:
    """
    Background thread that monitors an unlocked
    folder using three independent layers:

      Layer 1 → COM window handle tracking
      Layer 2 → Explorer process ID tracking
      Layer 3 → Session marker file (crash recovery)

    Any layer detecting a close event triggers
    the relock callback immediately.
    """

    def __init__(
        self,
        folder_path: Path,
        session_id: str,
        marker_path: Path,
        on_relock: Callable,
        check_interval: float = 2.0
    ):
        """
        folder_path
            The folder being watched.
            Resolved to full canonical path.

        session_id
            The unique ID for this unlock session.
            Used to identify our marker file.

        marker_path
            Path to the .flsession marker file.
            Written before monitoring starts.
            Deleted when relock triggers.

        on_relock
            Callable triggered when any layer
            detects the Explorer window has closed.
            This is manager._auto_relock() in practice.

        check_interval
            Seconds between each check cycle.
            2.0 seconds balances responsiveness
            against CPU usage.
        """
        self.folder_path = Path(folder_path).resolve()
        self.session_id = session_id
        self.marker_path = marker_path
        self.on_relock = on_relock
        self.check_interval = check_interval

        # threading.Event is a thread safe flag.
        # stop_event.set() signals all loops to exit.
        # stop_event.wait(n) waits n seconds OR until
        # stop_event is set — whichever comes first.
        self.stop_event = threading.Event()

        # Track whether this watcher is active
        self.is_running = False

        # Track whether we have seen the Explorer
        # window at least once after unlock.
        # Prevents false relocks before the user
        # has had time to open Explorer.
        self._window_seen = False

        # The Explorer process ID — populated once
        # we detect the Explorer window is open.
        self._explorer_pid = None

        # The background thread object
        self._thread = None

        logger.info(
            f"ExplorerWatcher created — "
            f"session: {session_id} "
            f"folder: {self.folder_path}"
        )

    def _check_com_layer(self) -> bool:
        """
        Layer 1 check — Explorer window tracking.

        Previously used COM Shell.Windows.
        Now uses EnumWindows via _get_open_explorer_paths()
        which does not require COM registration.

        Returns True if an Explorer window showing
        our folder is currently open.
        Returns False if no such window exists.
        """
        open_paths = _get_open_explorer_paths()
        for path in open_paths:
            if path == self.folder_path:
                return True
        return False

    def _check_pid_layer(self) -> bool:
        """
        Layer 2 check — Process ID tracking.

        Returns True if the Explorer process is
        still alive in the Windows process list.
        Returns True also if PID is unknown yet —
        we only trigger on confirmed process death.
        """
        if self._explorer_pid is None:
            return True
        return _is_process_alive(self._explorer_pid)

    def _trigger_relock(self, reason: str):
        """
        Called when any monitoring layer detects the
        Explorer window has closed.

        Why we run relock in a separate thread:
          _trigger_relock is called from inside the
          watcher's own background thread (_run_loop).
          When relock completes it calls monitor.stop()
          which calls watcher.stop() which calls
          thread.join() — asking the thread to wait
          for itself to finish. A thread cannot join
          itself. This causes the error:
          'cannot join current thread'

          The fix is to spawn a new short lived thread
          just for the relock operation. This thread
          is separate from the watcher thread so join()
          works correctly. The watcher thread exits
          cleanly and the relock thread handles the rest.
        """
        logger.info(
            f"Relock triggered by {reason} — "
            f"session: {self.session_id}"
        )

        # Signal the watcher loop to stop.
        # This causes _run_loop to exit on next iteration.
        self.stop_event.set()

        # Delete the session marker file.
        # We do this before spawning the relock thread
        # so the marker is gone immediately regardless
        # of how long relock takes.
        _delete_marker(self.marker_path)

        # Define the relock work as an inner function
        # so we can run it in a separate thread.
        # This function captures on_relock from the
        # outer scope via closure — same pattern as
        # the lambda in manager.py.
        def _do_relock():
            try:
                self.on_relock()
            except Exception as e:
                logger.error(
                    f"Relock callback failed: {e}"
                )

        # Spawn a new daemon thread for the relock.
        # daemon=True means it dies with the main app.
        # We do not join() this thread — we fire and
        # forget. The relock happens asynchronously.
        relock_thread = threading.Thread(
            target=_do_relock,
            name=f"AutoRelock_{self.session_id}",
            daemon=True
        )
        relock_thread.start()
    def _run_loop(self):
        """
        Main monitoring loop running in background thread.

        Adapted from Worker.run() in the worker module
        prototype — same structure, same pattern:
          1. Mark as running
          2. Loop until stop_event is set
          3. Check all layers inside the loop
          4. Wait between checks using stop_event.wait()
          5. Clean up on exit

        The key difference from the prototype:
        Instead of execute_task and heartbeat we have
        three layer checks that each can trigger relock.
        """
        self.is_running = True
        logger.info(
            f"ExplorerWatcher loop started — "
            f"session: {self.session_id}"
        )

        while not self.stop_event.is_set():

            # ── Layer 1: COM window check ───────────
            com_window_open = self._check_com_layer()

            if com_window_open:
                # Window is visible — mark as seen
                if not self._window_seen:
                    self._window_seen = True
                    logger.info(
                        "Explorer window detected — "
                        "all layers now active"
                    )

                    # Now that we see the window try to
                    # get the Explorer PID for Layer 2
                    if self._explorer_pid is None:
                        self._explorer_pid = (
                            _get_explorer_pid_for_folder(
                                self.folder_path
                            )
                        )
                        if self._explorer_pid:
                            logger.info(
                                f"Explorer PID captured: "
                                f"{self._explorer_pid}"
                            )

                            # Update marker with PID now
                            # that we have it
                            _write_marker(
                                self.folder_path,
                                self.session_id,
                                self._explorer_pid
                            )

            else:
                # Window not visible in COM
                if self._window_seen:
                    # We saw it before and now it is gone
                    # Layer 1 trigger
                    self._trigger_relock("COM window close")
                    break

            # ── Layer 2: Process ID check ───────────
            # Only check if we have a PID and window
            # has been seen at least once
            if self._window_seen and self._explorer_pid:
                pid_alive = self._check_pid_layer()
                if not pid_alive:
                    # Explorer process is dead
                    # Layer 2 trigger
                    self._trigger_relock(
                        "Explorer process terminated"
                    )
                    break

            # ── Wait before next cycle ──────────────
            # stop_event.wait() is used instead of
            # time.sleep() because:
            #   time.sleep() cannot be interrupted
            #   stop_event.wait() wakes up immediately
            #   when stop_event.set() is called
            # This makes shutdown instant not delayed
            # by up to check_interval seconds.
            self.stop_event.wait(self.check_interval)

        self.is_running = False
        logger.info(
            f"ExplorerWatcher loop ended — "
            f"session: {self.session_id}"
        )

    def start(self):
        """
        Start the watcher in a background thread.

        daemon=True means this thread is automatically
        killed when the main process exits.
        Without daemon=True the thread would keep running
        even after the app closes preventing clean exit.
        """
        if self.is_running:
            logger.warning(
                "ExplorerWatcher already running"
            )
            return

        # Reset state for a fresh start
        self.stop_event.clear()
        self._window_seen = False
        self._explorer_pid = None

        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"ExplorerWatcher_{self.session_id}",
            daemon=True
        )
        self._thread.start()
        logger.info(
            f"ExplorerWatcher thread started — "
            f"session: {self.session_id}"
        )

    def stop(self):
        """
        Signal the watcher to stop cleanly.
        Sets stop_event which wakes the waiting loop
        and causes it to exit on the next iteration.
        Then waits for the thread to finish cleanly.
        """
        logger.info(
            f"ExplorerWatcher stop requested — "
            f"session: {self.session_id}"
        )
        self.stop_event.set()

        if self._thread and self._thread.is_alive():
            # join() waits for thread to finish.
            # timeout=5 prevents hanging forever if
            # the thread is somehow stuck.
            self._thread.join(timeout=5)

        self.is_running = False


# ─────────────────────────────────────────────
# FileChangeHandler
#
# Watchdog file system event handler.
# Secondary protection layer that watches the
# parent directory for our marker file to appear
# or disappear unexpectedly.
# ─────────────────────────────────────────────

class SessionMarkerHandler(FileSystemEventHandler):
    """
    Watches the parent directory of the locked folder
    for unexpected deletion of our session marker file.

    If something deletes the marker file outside of
    our normal relock process we treat it as a signal
    to relock the folder immediately.

    This handles edge cases like:
      Someone manually deleting the marker file
      A cleanup utility removing unknown files
      Disk corruption affecting the marker
    """

    def __init__(
        self,
        marker_path: Path,
        on_marker_deleted: Callable
    ):
        """
        marker_path
            The .flsession file we are watching for.

        on_marker_deleted
            Called if the marker file is deleted by
            anything other than our own relock process.
        """
        super().__init__()
        self.marker_path = marker_path
        self.on_marker_deleted = on_marker_deleted
        self._our_deletion = False

    def mark_our_deletion(self):
        """
        Call this before we intentionally delete the
        marker so the handler knows not to trigger
        relock when it sees the deletion event.
        """
        self._our_deletion = True

    def on_deleted(self, event):
        """
        Called by watchdog when any file in the
        watched directory is deleted.

        We check if the deleted file is our specific
        marker file. If yes and we did not delete it
        ourselves we trigger relock.
        """
        if event.is_directory:
            return

        deleted_path = Path(event.src_path)
        if deleted_path == self.marker_path:
            if self._our_deletion:
                # We deleted it intentionally — ignore
                self._our_deletion = False
                return
            # Something else deleted our marker
            logger.warning(
                "Session marker deleted externally — "
                "triggering relock"
            )
            self.on_marker_deleted()


# ─────────────────────────────────────────────
# FolderMonitor
#
# Coordinates all monitoring layers.
# This is the class the manager and GUI talk to.
# Single clean interface hiding all complexity.
# ─────────────────────────────────────────────

class FolderMonitor:
    """
    Owns and coordinates all three monitoring layers
    for one unlocked folder at a time.

    The manager calls:
      monitor.start(folder_path, on_relock, on_change)
      monitor.stop()
      monitor.is_active()

    Internally this manages:
      ExplorerWatcher → COM + PID layers
      SessionMarkerHandler → marker file layer
      Observer → watchdog filesystem watcher
    """

    def __init__(self):
        """
        Initialize with no active monitoring.
        All monitoring starts when start() is called.
        """
        self._watcher = None
        self._fs_observer = None
        self._marker_handler = None
        self._monitored_path = None
        self._session_id = None
        self._marker_path = None

        logger.info("FolderMonitor initialized")

    def start(
        self,
        folder_path: Path,
        on_relock: Callable,
        on_change: Optional[Callable] = None
    ):
        """
        Start monitoring a folder after it is unlocked.

        folder_path
            The folder to monitor.

        on_relock
            Called automatically when any layer detects
            the Explorer window has closed.
            Should trigger manager._auto_relock().

        on_change
            Optional. Called when files inside the folder
            change. Used to update the GUI activity log.
        """
        # Stop any existing monitoring first
        self.stop()

        self._monitored_path = Path(folder_path).resolve()

        # Generate a unique session ID for this unlock
        self._session_id = _generate_session_id()

        # Calculate marker path beside the folder
        self._marker_path = _get_marker_path(
            self._monitored_path,
            self._session_id
        )

        # Write the initial marker file without PID yet.
        # PID is captured later when Explorer window
        # is detected by the watcher.
        _write_marker(
            self._monitored_path,
            self._session_id,
            None
        )

        logger.info(
            f"FolderMonitor starting — "
            f"session: {self._session_id} "
            f"folder: {self._monitored_path}"
        )

        # Create and start the Explorer watcher
        # This handles COM Layer 1 and PID Layer 2
        self._watcher = ExplorerWatcher(
            folder_path=self._monitored_path,
            session_id=self._session_id,
            marker_path=self._marker_path,
            on_relock=on_relock,
            check_interval=2.0
        )
        self._watcher.start()

        # Start watchdog for Layer 3 marker monitoring
        if WATCHDOG_AVAILABLE:
            # Watch the PARENT directory for marker events
            # because that is where the marker file lives
            watch_dir = str(self._monitored_path.parent)

            self._marker_handler = SessionMarkerHandler(
                marker_path=self._marker_path,
                on_marker_deleted=on_relock
            )

            self._fs_observer = Observer()
            self._fs_observer.schedule(
                self._marker_handler,
                watch_dir,
                recursive=False
            )
            self._fs_observer.start()
            logger.info(
                f"Watchdog observer started — "
                f"watching: {watch_dir}"
            )

        logger.info(
            f"FolderMonitor active — "
            f"all layers running"
        )

    def stop(self):
        """
        Stop all monitoring layers cleanly.
        Called when the folder is relocked manually
        or by the auto relock callback.
        """
        # Tell marker handler we are intentionally
        # deleting the marker so it does not trigger
        # a spurious relock event.
        if self._marker_handler is not None:
            self._marker_handler.mark_our_deletion()

        # Delete the session marker file
        if self._marker_path is not None:
            _delete_marker(self._marker_path)

        # Stop the Explorer watcher thread
        if self._watcher is not None:
            self._watcher.stop()
            self._watcher = None

        # Stop the watchdog observer
        if self._fs_observer is not None:
            self._fs_observer.stop()
            self._fs_observer.join(timeout=5)
            self._fs_observer = None

        self._marker_handler = None
        self._monitored_path = None
        self._session_id = None
        self._marker_path = None

        logger.info("FolderMonitor stopped")

    def is_active(self) -> bool:
        """
        Returns True if monitoring is currently active.
        False if no folder is being monitored.
        """
        if self._watcher is None:
            return False
        return self._watcher.is_running

    def get_session_id(self) -> Optional[str]:
        """
        Returns the current session ID or None
        if no monitoring is active.
        """
        return self._session_id
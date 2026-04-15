import ctypes
import ctypes.wintypes
from pathlib import Path
import sys
import os

# ─────────────────────────────────────────────
# Load our compiled C++ DLL
#
# This is the key difference from before.
# Previously Python talked directly to
# advapi32.dll through a complex ctypes setup
# with many type definitions.
#
# Now Python loads OUR DLL which handles all
# the Windows API complexity internally.
# Python just calls our five clean functions.
#
# The DLL sits in the native folder at
# the project root level.
# ─────────────────────────────────────────────

# Find the DLL relative to this file
def _find_dll() -> Path:
    """
    Find folder_locker.dll in all environments:

    Development (normal script):
      project_root/native/folder_locker.dll

    cx_Freeze bundle:
      sys.frozen = True, no sys._MEIPASS
      DLL sits in native/ next to the executable
      os.path.dirname(sys.executable)/native/

    PyInstaller bundle:
      sys.frozen = True, sys._MEIPASS exists
      DLL sits in sys._MEIPASS/native/
    """
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            # PyInstaller
            base = Path(sys._MEIPASS)
        else:
            # cx_Freeze
            base = Path(os.path.dirname(sys.executable))
        return base / "native" / "folder_locker.dll"
    else:
        # Development
        return (
            Path(__file__).resolve()
            .parent.parent.parent
            / "native"
            / "folder_locker.dll"
        )

_DLL_PATH = _find_dll()

try:
    _lib = ctypes.CDLL(str(_DLL_PATH))
except OSError as e:
    raise RuntimeError(
        f"Could not load folder_locker.dll from {_DLL_PATH}.\n"
        f"Make sure you have run native\\build.bat first.\n"
        f"Error: {e}"
    )

# ─────────────────────────────────────────────
# Define function signatures
#
# Even though our DLL is simpler than calling
# advapi32 directly, ctypes still needs to know
# what types each function takes and returns.
#
# Our functions use:
#   c_wchar_p  → wide string pointer (folder path)
#   c_wchar_p  → wide string pointer (SDDL string)
#   c_int      → buffer size
#   c_int      → return value (1=success, 0=failure)
#   c_ulong    → Windows DWORD error code
# ─────────────────────────────────────────────

# snapshot_dacl(path, out_buf, buf_size) -> int
_lib.snapshot_dacl.argtypes = [
    ctypes.c_wchar_p,           # folder path
    ctypes.c_wchar_p,           # output buffer
    ctypes.c_int,               # buffer size
]
_lib.snapshot_dacl.restype = ctypes.c_int

# lock_folder(path, out_sddl, buf_size) -> int
_lib.lock_folder.argtypes = [
    ctypes.c_wchar_p,           # folder path
    ctypes.c_wchar_p,           # output buffer for original SDDL
    ctypes.c_int,               # buffer size
]
_lib.lock_folder.restype = ctypes.c_int

# unlock_folder(path, original_sddl) -> int
_lib.unlock_folder.argtypes = [
    ctypes.c_wchar_p,           # folder path
    ctypes.c_wchar_p,           # original SDDL to restore
]
_lib.unlock_folder.restype = ctypes.c_int

# lock_recursive(path, out_sddl, buf_size) -> int
_lib.lock_recursive.argtypes = [
    ctypes.c_wchar_p,           # folder path
    ctypes.c_wchar_p,           # output buffer for original SDDL
    ctypes.c_int,               # buffer size
]
_lib.lock_recursive.restype = ctypes.c_int

# unlock_recursive(path, original_sddl) -> int
_lib.unlock_recursive.argtypes = [
    ctypes.c_wchar_p,           # folder path
    ctypes.c_wchar_p,           # original SDDL to restore
]
_lib.unlock_recursive.restype = ctypes.c_int

# get_last_error() -> DWORD
_lib.get_last_error.argtypes = []
_lib.get_last_error.restype = ctypes.c_ulong

# ─────────────────────────────────────────────
# Buffer size for SDDL strings
#
# SDDL strings can be long on folders with many
# ACEs. 8192 wide characters is generous enough
# to hold any real world SDDL string.
# ─────────────────────────────────────────────
_SDDL_BUFFER_SIZE = 8192


def _resolve(folder_path: Path) -> Path:
    """
    Resolve the real full path.
    Converts short names like OKOJIE~1 to their
    full real path so Windows sees one consistent
    path across all operations.
    """
    return Path(folder_path).resolve()


def _make_buffer() -> ctypes.Array:
    """
    Create a wide character buffer for SDDL output.
    The DLL writes the SDDL string into this buffer.
    Python owns this memory — no cross DLL ownership.
    """
    return ctypes.create_unicode_buffer(_SDDL_BUFFER_SIZE)


def snapshot_dacl(folder_path: Path) -> str:
    """
    Read the current DACL from a folder and return
    it as a saveable SDDL string.
    """
    folder_path = _resolve(folder_path)
    buf = _make_buffer()

    result = _lib.snapshot_dacl(
        str(folder_path),
        buf,
        _SDDL_BUFFER_SIZE
    )

    if not result:
        error = _lib.get_last_error()
        raise RuntimeError(
            f"snapshot_dacl failed on {folder_path}. "
            f"Windows error code: {error}"
        )

    return buf.value


def lock_folder(folder_path: Path) -> str:
    """
    Lock a single folder by applying DENY Everyone ACL.
    Returns the original SDDL snapshot for later restore.
    """
    folder_path = _resolve(folder_path)

    if not folder_path.exists():
        raise FileNotFoundError(
            f"Folder not found: {folder_path}"
        )

    buf = _make_buffer()

    result = _lib.lock_folder(
        str(folder_path),
        buf,
        _SDDL_BUFFER_SIZE
    )

    if not result:
        error = _lib.get_last_error()
        raise RuntimeError(
            f"lock_folder failed on {folder_path}. "
            f"Windows error code: {error}"
        )

    return buf.value


def unlock_folder(folder_path: Path, original_sddl: str) -> bool:
    """
    Restore a single folder's original DACL
    from a saved SDDL snapshot.
    """
    folder_path = _resolve(folder_path)

    if not folder_path.exists():
        raise FileNotFoundError(
            f"Folder not found: {folder_path}"
        )

    result = _lib.unlock_folder(
        str(folder_path),
        original_sddl
    )

    if not result:
        error = _lib.get_last_error()
        raise RuntimeError(
            f"unlock_folder failed on {folder_path}. "
            f"Windows error code: {error}"
        )

    return True


def lock_folder_recursive(folder_path: Path) -> str:
    """
    Lock the top level folder and all subfolders.
    Returns the original SDDL of the top level folder.
    """
    folder_path = _resolve(folder_path)

    if not folder_path.exists():
        raise FileNotFoundError(
            f"Folder not found: {folder_path}"
        )

    buf = _make_buffer()

    result = _lib.lock_recursive(
        str(folder_path),
        buf,
        _SDDL_BUFFER_SIZE
    )

    if not result:
        error = _lib.get_last_error()
        raise RuntimeError(
            f"lock_recursive failed on {folder_path}. "
            f"Windows error code: {error}"
        )

    return buf.value


def unlock_folder_recursive(
    folder_path: Path,
    original_sddl: str
) -> bool:
    """
    Unlock the top level folder and all subfolders.
    Unlocks deepest subfolders first so we always
    have access to work our way back up to the top.
    """
    folder_path = _resolve(folder_path)

    if not folder_path.exists():
        raise FileNotFoundError(
            f"Folder not found: {folder_path}"
        )

    result = _lib.unlock_recursive(
        str(folder_path),
        original_sddl
    )

    if not result:
        error = _lib.get_last_error()
        raise RuntimeError(
            f"unlock_recursive failed on {folder_path}. "
            f"Windows error code: {error}"
        )

    return True
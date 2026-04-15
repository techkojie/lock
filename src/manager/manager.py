"""
FolderLocker Manager Module

This is the brain of the entire application.
It coordinates all three security layers:

  auth module
    Verifies the master password before any
    operation is allowed to proceed.
    Think of it as the security guard at the
    entrance who checks your ID.

  crypto module
    Encrypts and decrypts the actual file contents
    using AES-256-GCM encryption.
    Think of it as the locksmith who seals each
    individual safe deposit box inside the vault.

  acl module
    Locks and unlocks the folder permissions using
    Windows NTFS Access Control Lists via our C++ DLL.
    Think of it as the vault door — it blocks all
    access to the room regardless of what is inside.

  monitor module
    Watches the Windows Explorer window after unlock.
    When the Explorer window closes it automatically
    relocks the folder without any user action.
    Think of it as the security camera that watches
    the vault door and relocks it when everyone leaves.

Lock order — critical, must never change:
  Encrypt files FIRST then apply ACL lock.
  Reason: once the ACL lock is applied even our own
  app cannot read the folder to encrypt files.
  We must do the work before closing the door.

Unlock order — critical, must never change:
  Restore ACL FIRST then decrypt files.
  Reason: we need filesystem access to read the
  encrypted files. We must open the door before
  we can reach the boxes inside.
"""

# json is Python's built in library for reading
# and writing JSON formatted text files.
# We use it to save and load the lock state file
# and the persistent config file.
# JSON is human readable text so if something goes
# wrong you can open the file and read it directly.
import json

# os gives us access to operating system features.
# We use os.environ to read the APPDATA environment
# variable which tells us where to store config files.
import os

# logging gives us a proper logging system.
# Instead of print() statements we use logger.info()
# logger.warning() and logger.error() which include
# timestamps and severity levels automatically.
import logging

# Path is Python's built in path handling class.
# It gives us clean cross platform file operations.
# Example: Path("C:/Users") / "Joseph" / "folder"
# instead of "C:\\Users\\Joseph\\folder"
# Path also has useful methods like:
#   .exists()  → does this file/folder exist?
#   .parent    → the containing folder
#   .name      → just the filename part
#   .resolve() → convert to full absolute path
from pathlib import Path

# verify_master_password checks the entered password
# against the stored PBKDF2-HMAC-SHA256 hash in
# Windows Credential Manager.
# Returns True if correct, False if wrong.
# Raises RuntimeError if no password has been set.
from src.auth.auth import verify_master_password

# encrypt_folder encrypts every file in a folder
# using AES-256-GCM with a unique salt and nonce
# per file. Each file becomes a .locked file.
# decrypt_folder reverses this — reads the salt and
# nonce from each .locked file, derives the same key,
# decrypts and restores the original file.
from src.crypto.crypto import encrypt_folder, decrypt_folder

# lock_folder_recursive calls our C++ DLL which calls
# advapi32.dll to apply DENY Everyone ACL rules to
# the folder and every subfolder recursively.
# unlock_folder_recursive reverses this by restoring
# the original DACL we snapshotted before locking.
from src.acl.acl import (
    lock_folder_recursive,
    unlock_folder_recursive
)

# FolderMonitor is the Explorer window watcher.
# It runs in a background thread and checks every
# 2 seconds whether the Explorer window showing the
# unlocked folder is still open.
# When it closes it calls our _auto_relock function.
from src.monitor.monitor import FolderMonitor


# ─────────────────────────────────────────────
# Logger
#
# logging.getLogger creates a named logger.
# The name "FolderLocker.manager" is a hierarchy —
# FolderLocker is the app, manager is the module.
# This lets you filter log output by module name
# when debugging. All log lines from this module
# are prefixed with this name automatically.
# ─────────────────────────────────────────────
logger = logging.getLogger("FolderLocker.manager")


# ─────────────────────────────────────────────
# Global monitor instance
#
# We create ONE FolderMonitor for the entire app
# session. The keyword global here means this object
# lives in module scope — it is created once when
# the module is first imported and stays alive until
# the app closes.
#
# Why only one?
#   In v1 the app locks one folder at a time.
#   One monitor is all we need.
#   In v2 when we support multiple folders we will
#   change this to a dictionary of monitors.
#
# Why global and not inside a function?
#   If we created it inside lock() it would be
#   destroyed when lock() returns.
#   We need it to survive across multiple function
#   calls — created in unlock(), still running when
#   the user eventually closes Explorer.
# ─────────────────────────────────────────────
_monitor = FolderMonitor()


# ─────────────────────────────────────────────
# Constants
#
# Constants are values that never change during
# the program's lifetime. We define them at the
# top of the module so they are easy to find
# and change if needed without hunting through code.
# ─────────────────────────────────────────────

# The name of the state file we save beside each
# locked folder. Contains the original DACL and
# the lock mode so we can reverse the lock later.
# The dot prefix makes it a hidden file on Unix.
# On Windows it is just a regular file name.
LOCKFILE_NAME = ".lockerstate"

# File extensions we never encrypt in smart mode.
# These are program files that Windows must be able
# to read directly from disk to run the program.
# Encrypting them would break the program on reboot
# because Windows cannot execute encrypted binaries.
# The store inventory program falls into this category.
EXECUTABLE_EXTENSIONS = {
    ".exe",  # main executable programs
    ".dll",  # dynamic link libraries (hired help files)
    ".sys",  # system driver files
    ".msi",  # Windows installer packages
    ".bat",  # batch script files
    ".cmd",  # command script files
    ".com",  # legacy executable format
    ".scr",  # screensaver executables
}

# The three lock modes available to the user.
# Keys are the internal mode names used in code.
# Values are human readable descriptions shown in GUI.
LOCK_MODES = {
    # Full mode — maximum protection.
    # ACL blocks access AND every file is encrypted.
    # Even if someone bypasses the ACL they see
    # only encrypted ciphertext. Best for personal
    # sensitive files that never need to run.
    "full": "Full lock — ACL + encrypt everything",

    # Soft mode — access control only.
    # ACL blocks casual access but no encryption.
    # A skilled admin can bypass it.
    # Best for running program folders where encryption
    # would break the program on reboot.
    "soft": "Soft lock — ACL only, no encryption",

    # Smart mode — business protection.
    # ACL on everything PLUS encrypts data files.
    # Skips executable files so program survives reboot.
    # Data files (config, database) are encrypted so
    # even an admin bypass reveals only ciphertext.
    # This is your store use case.
    "smart": "Smart lock — ACL on all, encrypt data files only"
}


# ─────────────────────────────────────────────
# Private helper functions
#
# The underscore prefix _ is a Python convention
# meaning these functions are private — they are
# only meant to be called from within this module.
# Other modules should not call these directly.
# ─────────────────────────────────────────────

def _resolve(folder_path: Path) -> Path:
    """
    Convert any path to its real full absolute path.

    Path.resolve() does three things:
      1. Converts relative paths like "../folder"
         to absolute paths like "C:/Users/Joseph/folder"
      2. Expands Windows 8.3 short names like OKOJIE~1
         to their full name "Okojie Joseph"
      3. Resolves any symbolic links to their real target

    Why we always resolve:
      Different tools on Windows represent the same
      folder with different path formats. OKOJIE~1
      and "Okojie Joseph" are the same folder but
      string comparison would say they are different.
      resolve() guarantees we always compare the same
      canonical representation of the path.
    """
    return Path(folder_path).resolve()


def _get_lockfile_path(folder_path: Path) -> Path:
    """
    Return the path to the state file for a locked folder.

    The state file sits BESIDE the locked folder in its
    parent directory — NOT inside the locked folder itself.

    Why beside and not inside?
      Once we apply the ACL lock our own app cannot
      write into the locked folder either — the DENY
      Everyone rule applies to us too.
      By placing the state file in the parent directory
      we can always read and write it regardless of
      the folder's current lock state.

    Example:
      Locked folder: C:/Users/Joseph/SecretFolder
      State file:    C:/Users/Joseph/SecretFolder.lockerstate

    folder_path.parent gives us C:/Users/Joseph/
    folder_path.name gives us "SecretFolder"
    We concatenate them with + ".lockerstate"
    """
    folder_path = _resolve(folder_path)
    return folder_path.parent / (
        folder_path.name + ".lockerstate"
    )


def _save_lock_state(
    folder_path: Path,
    sddl: str,
    mode: str
) -> None:
    """
    Save the original DACL snapshot and lock mode
    to the state file beside the locked folder.

    We call this AFTER applying the ACL lock but the
    file is written to the PARENT directory so we
    can always reach it regardless of lock state.

    What gets saved:
      locked       → True (confirms this is a valid state)
      mode         → "full", "soft", or "smart"
      original_sddl → the DACL string we need to restore

    Why JSON?
      JSON is human readable plain text.
      If something goes wrong you can open the file
      in Notepad and see exactly what was saved.
      json.dumps() converts a Python dictionary to
      a JSON formatted string.
      indent=2 adds 2-space indentation for readability.
    """
    lockfile = _get_lockfile_path(folder_path)
    state = {
        "locked": True,
        "mode": mode,
        "original_sddl": sddl
    }
    lockfile.write_text(json.dumps(state, indent=2))


def _load_lock_state(folder_path: Path) -> dict:
    """
    Read the saved lock state from the state file.

    json.loads() converts the JSON text back into
    a Python dictionary we can work with.

    Raises FileNotFoundError if the state file does
    not exist. This means either:
      - The folder was never locked by FolderLocker
      - The state file was accidentally deleted
      - The wrong folder path was given
    """
    lockfile = _get_lockfile_path(folder_path)
    if not lockfile.exists():
        raise FileNotFoundError(
            f"No lock state found for: {folder_path}\n"
            f"This folder may not have been locked "
            f"by FolderLocker."
        )
    return json.loads(lockfile.read_text())


def _clear_lock_state(folder_path: Path) -> None:
    """
    Delete the state file after successful unlock.

    unlink() is Python's method for deleting a file.
    It is named after the Unix system call that removes
    a directory entry — the file is unlinked from
    the directory and deleted if no other links exist.

    We check exists() first to avoid an error if the
    file was already deleted somehow.
    """
    lockfile = _get_lockfile_path(folder_path)
    if lockfile.exists():
        lockfile.unlink()


def _encrypt_smart(
    folder_path: Path,
    password: str
) -> dict:
    """
    Smart mode encryption — encrypts everything EXCEPT
    executable file types.

    Why skip executables?
      When Windows starts a program it reads the .exe
      and .dll files directly from disk.
      If those files are encrypted Windows reads
      ciphertext instead of real instructions and
      the program crashes or refuses to start.
      Data files (.db .ini .cfg) are different —
      the running program reads them into memory.
      Once in memory the program does not need to
      re-read from disk so encrypting them is safe.

    rglob("*") walks the entire folder tree recursively
    and yields every file and subfolder it finds.
    We filter with is_file() to skip folders.

    Returns a dict matching encrypt_folder() format:
      success → list of successfully encrypted file paths
      failed  → list of dicts with file and error keys
    """
    from src.crypto.crypto import (
        encrypt_file,
        ENCRYPTED_EXTENSION
    )
    results = {"success": [], "failed": []}

    for file in folder_path.rglob("*"):
        if (
            # Only process files not subfolders
            file.is_file()
            # Skip executable types — they must stay readable
            and file.suffix not in EXECUTABLE_EXTENSIONS
            # Skip files already encrypted from a previous run
            and file.suffix != ENCRYPTED_EXTENSION
        ):
            try:
                encrypt_file(file, password)
                results["success"].append(str(file))
            except Exception as e:
                results["failed"].append({
                    "file": str(file),
                    "error": str(e)
                })

    return results


def _decrypt_smart(
    folder_path: Path,
    password: str
) -> dict:
    """
    Smart mode decryption — only decrypts .locked files.

    Since smart mode only encrypted non-executable files
    we only need to reverse those.
    decrypt_folder() already only touches .locked files
    so we can call it directly — it naturally skips
    the executable files that were never encrypted.
    """
    return decrypt_folder(folder_path, password)


# ─────────────────────────────────────────────
# Persistent config
#
# The app must remember which folder was locked
# even after a restart or reboot. Without this
# a power outage or reboot would leave the folder
# permanently locked with no way to find it.
#
# We store this in AppData — the standard Windows
# location for per-user application data.
# AppData survives reboots and is user-specific
# so each user on the machine has their own config.
# ─────────────────────────────────────────────

def _get_config_path() -> Path:
    """
    Return the path to our persistent config file.

    os.environ.get('APPDATA') reads the APPDATA
    environment variable which Windows sets to the
    current user's AppData/Roaming folder path.
    Example: C:/Users/Joseph/AppData/Roaming

    We create a FolderLocker subfolder inside it.
    mkdir(parents=True, exist_ok=True) creates the
    folder and any missing parent folders.
    exist_ok=True means no error if it already exists.

    If APPDATA is not set (unusual) we fall back to
    the user's home directory via Path.home().
    """
    appdata = os.environ.get(
        'APPDATA',
        str(Path.home())
    )
    config_dir = Path(appdata) / "FolderLocker"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.json"


def _load_config() -> dict:
    """
    Load the persistent config from disk.

    Returns an empty dictionary if no config file
    exists yet — meaning this is the first run or
    the config was cleared.

    We wrap json.loads() in try/except because the
    config file could be corrupted if the app crashed
    while writing it. In that case we return an empty
    dict and start fresh rather than crashing.
    """
    config_path = _get_config_path()
    if not config_path.exists():
        return {}
    try:
        return json.loads(config_path.read_text())
    except Exception:
        return {}


def _save_config(data: dict) -> None:
    """
    Save data to the persistent config file.

    We merge with existing config using update()
    so we never accidentally erase other stored values.
    update() adds or overwrites only the keys in data
    while leaving all other existing keys untouched.
    """
    config_path = _get_config_path()
    existing = _load_config()
    existing.update(data)
    config_path.write_text(
        json.dumps(existing, indent=2)
    )


def _clear_config_folder() -> None:
    """
    Remove the locked folder entry from the config.
    Called when unlock completes successfully.

    dict.pop(key, None) removes the key if it exists.
    The second argument None means no error is raised
    if the key does not exist — safe to call even if
    the config was already cleared.
    """
    config_path = _get_config_path()
    config = _load_config()
    config.pop("locked_folder", None)
    config.pop("lock_mode", None)
    config_path.write_text(
        json.dumps(config, indent=2)
    )


def get_remembered_folder() -> dict:
    """
    PUBLIC function called by the GUI on startup.

    Returns information about the last locked folder
    so the GUI can automatically restore it on the
    dashboard without the user having to browse again.

    This is critical for the store use case:
      Machine reboots overnight
      Manager arrives in the morning
      Opens FolderLocker
      Logs in with master password
      Dashboard immediately shows the locked folder
      Manager clicks Unlock and enters password
      Done — no hunting for which folder was locked

    Returns a dict with folder and mode keys
    if a remembered folder exists and its parent
    directory is still accessible.
    Returns empty dict if nothing is remembered.

    Why check parent directory?
      If the drive was removed or the folder deleted
      we do not want to show a stale path that will
      just cause errors. Checking the parent directory
      exists is a lightweight way to verify the location
      is still accessible before showing it.
    """
    config = _load_config()
    folder = config.get("locked_folder")
    mode = config.get("lock_mode")

    if folder and Path(folder).parent.exists():
        return {
            "folder": folder,
            "mode": mode
        }
    return {}


# ─────────────────────────────────────────────
# Public API
#
# These are the functions other modules call.
# No underscore prefix — they are public.
# ─────────────────────────────────────────────

def is_locked(folder_path: Path) -> bool:
    """
    Check if a folder is currently locked by FolderLocker.

    We determine this by checking if a state file
    exists beside the folder in its parent directory.

    Returns True if locked, False if not locked or
    if the folder was never locked by FolderLocker.

    This is a fast check — just a file existence test.
    No Windows API calls needed.
    """
    return _get_lockfile_path(folder_path).exists()


def lock(
    folder_path: Path,
    password: str,
    mode: str = "full",
    skip_verify: bool = False
) -> dict:
    """
    Lock a folder using the specified mode.

    Parameters:
      folder_path
        The folder to lock. Will be resolved to its
        full canonical path before processing.

      password
        The master password. Used to verify identity
        and to encrypt files in full and smart modes.

      mode
        Which lock mode to use.
        "full"  → ACL lock + encrypt all files
        "soft"  → ACL lock only, no encryption
        "smart" → ACL lock on all + encrypt non-executables
        Defaults to "full" if not specified.

      skip_verify
        If True skip the password verification step.
        ONLY used by _auto_relock() which is called
        internally and already has a verified password.
        Never pass True to this from outside this module.
        This parameter exists purely as an internal
        optimization — we do not waste time verifying
        a password we already know is correct.

    Lock order — critical, must never change:
      Step 1: Validate the mode string
      Step 2: Verify master password (unless skip_verify)
      Step 3: Check folder is not already locked
      Step 4: Stop any active Explorer monitor
      Step 5: Encrypt files (BEFORE ACL lock)
      Step 6: Apply ACL lock recursively
      Step 7: Save state file beside the folder
      Step 8: Save folder path to persistent config

    Returns a dict with:
      success → True or False
      mode → the mode used
      mode_description → human readable mode description
      encrypted_files → count of files encrypted
      folder → the resolved folder path string
      error → error message if success is False
      details → list of per-file errors if any
    """
    # Always resolve the path first.
    # This converts OKOJIE~1 to "Okojie Joseph" and
    # ensures all subsequent operations use the same
    # canonical path representation.
    folder_path = _resolve(folder_path)

    # ── Step 1: Validate mode ───────────────────────────
    # Check the mode is one we know about before doing
    # any work. Better to fail fast with a clear message
    # than to do partial work and then discover the mode
    # is invalid halfway through the operation.
    if mode not in LOCK_MODES:
        return {
            "success": False,
            "error": (
                f"Invalid mode. "
                f"Choose from: {list(LOCK_MODES.keys())}"
            )
        }

    # ── Step 2: Verify master password ─────────────────
    # The security guard checks your ID before letting
    # you through. We skip this only for internal calls
    # from _auto_relock where we already know the
    # password is correct from the original unlock.
    if not skip_verify:
        if not verify_master_password(password):
            return {
                "success": False,
                "error": "Incorrect password."
            }

    # ── Step 3: Check not already locked ───────────────
    # Locking an already locked folder would overwrite
    # the saved DACL with the locked DACL — losing the
    # original DACL forever and making it impossible to
    # ever unlock the folder correctly.
    if is_locked(folder_path):
        return {
            "success": False,
            "error": "Folder is already locked."
        }

    # ── Step 4: Stop any active monitor ────────────────
    # If the user manually clicks Lock while the Explorer
    # monitor is running from a previous unlock we stop
    # the monitor first. Without this the monitor could
    # fire _auto_relock AFTER we have already locked
    # manually — causing a double lock attempt.
    _monitor.stop()

    # ── Step 5: Encrypt files based on mode ────────────
    # CRITICAL: This must happen BEFORE the ACL lock.
    # The moment we apply the ACL lock in Step 6 even
    # our own app cannot read the folder contents.
    # We must do all the encryption work first.
    encrypted_count = 0

    if mode == "full":
        # encrypt_folder() encrypts every file in the
        # folder and all subfolders with AES-256-GCM.
        # Each file gets its own random salt and nonce
        # so even identical files produce different output.
        crypto_results = encrypt_folder(folder_path, password)
        if crypto_results["failed"]:
            return {
                "success": False,
                "error": "Some files failed to encrypt.",
                "details": crypto_results["failed"]
            }
        encrypted_count = len(crypto_results["success"])

    elif mode == "smart":
        # _encrypt_smart() skips executable files.
        # Data files get encrypted, executables stay plain.
        crypto_results = _encrypt_smart(folder_path, password)
        if crypto_results["failed"]:
            return {
                "success": False,
                "error": "Some files failed to encrypt.",
                "details": crypto_results["failed"]
            }
        encrypted_count = len(crypto_results["success"])

    # soft mode intentionally does nothing here —
    # the ACL lock alone provides the protection.
    # No files are touched at all in soft mode.

    # ── Step 6: Apply ACL lock ──────────────────────────
    # Call our C++ DLL which calls advapi32.dll to apply
    # DENY Everyone ACL rules to the folder and every
    # subfolder recursively. Returns the original DACL
    # as an SDDL string so we can restore it on unlock.
    try:
        original_sddl = lock_folder_recursive(folder_path)
    except Exception as e:
        # ACL lock failed. If we encrypted files in
        # Step 5 we must undo that encryption now.
        # Leaving files encrypted without ACL protection
        # would be a broken state — encrypted but accessible.
        # We roll back to leave the folder exactly as
        # it was before we started.
        if mode == "full":
            decrypt_folder(folder_path, password)
        elif mode == "smart":
            _decrypt_smart(folder_path, password)
        return {
            "success": False,
            "error": (
                f"ACL lock failed, encryption rolled back. "
                f"{str(e)}"
            )
        }

    # ── Step 7: Save state file ─────────────────────────
    # Write the original DACL and mode to a file beside
    # the locked folder. We need this on unlock to know
    # what DACL to restore and whether to decrypt files.
    # This file lives in the parent directory so we can
    # always write it regardless of the lock state.
    _save_lock_state(folder_path, original_sddl, mode)

    # ── Step 8: Save to persistent config ───────────────
    # Write the folder path to AppData config so the app
    # remembers it across restarts and reboots.
    # This is the critical safety net — without this a
    # reboot would leave the folder locked forever with
    # no way for the app to find and unlock it.
    _save_config({
        "locked_folder": str(folder_path),
        "lock_mode": mode
    })

    logger.info(
        f"Folder locked successfully: {folder_path} "
        f"mode={mode}"
    )

    return {
        "success": True,
        "mode": mode,
        "mode_description": LOCK_MODES[mode],
        "encrypted_files": encrypted_count,
        "folder": str(folder_path)
    }


def unlock(
    folder_path: Path,
    password: str
) -> dict:
    """
    Unlock a folder using the mode that was saved
    at lock time.

    The user never needs to specify the mode on unlock.
    We read it from the saved state file automatically.
    This prevents errors where the user might specify
    the wrong mode and corrupt the folder state.

    Parameters:
      folder_path
        The folder to unlock.

      password
        The master password. Used to verify identity
        and to decrypt files in full and smart modes.

    Unlock order — critical, must never change:
      Step 1: Verify master password
      Step 2: Read saved state file
      Step 3: Restore ACL (BEFORE decryption)
      Step 4: Decrypt files based on saved mode
      Step 5: Clear persistent config memory
      Step 6: Delete state file
      Step 7: Start Explorer window monitoring

    Why clear config BEFORE deleting state file?
      Config lives in AppData — separate from the folder.
      If the app crashes between these two steps we want
      the config cleared so the next restart does not
      try to restore a folder in an inconsistent state.
      The state file is the definitive record — it stays
      until the very last moment confirming unlock is done.

    Returns a dict with:
      success → True or False
      mode → the mode that was used
      mode_description → human readable description
      decrypted_files → count of files decrypted
      folder → the resolved folder path string
      error → error message if success is False
      details → list of per-file errors if any
    """
    folder_path = _resolve(folder_path)

    # ── Step 1: Verify master password ─────────────────
    # Always verify on unlock — no skip_verify here.
    # The GUI also verifies before calling this function
    # but we verify again here as a second layer.
    # Defense in depth means never trusting a single check.
    # Two verifications means two independent failures
    # would have to occur simultaneously for access to
    # be granted to the wrong person.
    if not verify_master_password(password):
        return {
            "success": False,
            "error": "Incorrect password."
        }

    # ── Step 2: Read saved state ────────────────────────
    # Load the mode and original DACL we saved at lock time.
    # If the state file does not exist the folder was never
    # locked by FolderLocker or the state was corrupted.
    try:
        state = _load_lock_state(folder_path)
    except FileNotFoundError as e:
        return {
            "success": False,
            "error": str(e)
        }

    # Extract the values we need from the state dict.
    # dict.get() with a default value prevents KeyError
    # if the key is missing — safe even with old state files
    # that might not have a mode key.
    original_sddl = state["original_sddl"]
    mode = state.get("mode", "full")

    # ── Step 3: Restore ACL ─────────────────────────────
    # Call our C++ DLL to remove the DENY Everyone rule
    # and restore the original DACL we snapshotted.
    # This MUST happen before decryption because we need
    # filesystem access to read the encrypted .locked files.
    # Without this step our own app cannot read anything.
    try:
        unlock_folder_recursive(folder_path, original_sddl)
    except Exception as e:
        return {
            "success": False,
            "error": f"ACL unlock failed. {str(e)}"
        }

    # ── Step 4: Decrypt files based on mode ────────────
    decrypted_count = 0

    if mode == "full":
        # decrypt_folder() finds every .locked file and
        # decrypts it back to the original using the
        # saved salt to re-derive the same AES key.
        crypto_results = decrypt_folder(folder_path, password)
        if crypto_results["failed"]:
            return {
                "success": False,
                "error": "Some files failed to decrypt.",
                "details": crypto_results["failed"]
            }
        decrypted_count = len(crypto_results["success"])

    elif mode == "smart":
        # _decrypt_smart() only touches .locked files —
        # executable files were never encrypted so they
        # need no decryption. Same as decrypt_folder()
        # in practice but named separately for clarity.
        crypto_results = _decrypt_smart(folder_path, password)
        if crypto_results["failed"]:
            return {
                "success": False,
                "error": "Some files failed to decrypt.",
                "details": crypto_results["failed"]
            }
        decrypted_count = len(crypto_results["success"])

    # soft mode has no .locked files to decrypt.
    # The ACL was the only lock — restoring it is enough.

    # ── Step 5: Clear persistent config memory ──────────
    # Remove the locked folder entry from AppData config.
    # We do this BEFORE deleting the state file because
    # if the app crashes between these two steps we want
    # the config cleared so the next restart does not
    # try to restore a folder that is now unlocked.
    # The state file stays as a backup until config is clear.
    _clear_config_folder()

    # ── Step 6: Delete state file ───────────────────────
    # Remove the .lockerstate file from beside the folder.
    # This is the definitive signal that unlock completed.
    # is_locked() checks for this file so deleting it
    # marks the folder as unlocked in our system.
    _clear_lock_state(folder_path)

    # ── Step 7: Start Explorer window monitoring ─────────
    # Now that the folder is unlocked we start watching
    # for the Explorer window showing it to close.
    # When it closes _auto_relock() is called automatically
    # relocking the folder with no user interaction needed.
    #
    # We pass the password via lambda so _auto_relock
    # has it available when it fires — possibly minutes
    # later when the user closes Explorer.
    # The password stays in memory only for this duration.
    # The moment relock completes it is no longer referenced
    # and Python's garbage collector will free the memory.
    _monitor.start(
        folder_path=folder_path,
        on_relock=lambda: _auto_relock(
            folder_path, password
        ),
        on_change=None
    )

    logger.info(
        f"Folder unlocked successfully: {folder_path} "
        f"mode={mode}"
    )

    return {
        "success": True,
        "mode": mode,
        "mode_description": LOCK_MODES[mode],
        "decrypted_files": decrypted_count,
        "folder": str(folder_path)
    }


def _auto_relock(folder_path: Path, password: str) -> None:
    """
    Automatically relock a folder when its Explorer
    window is closed by the user.

    This is the callback we pass to FolderMonitor.start().
    The monitor calls this function automatically the
    moment it detects the Explorer window has closed.
    No user interaction is needed or possible at this point
    — the user may have already walked away.

    Parameters:
      folder_path
        The folder to relock. This was captured in the
        lambda closure when monitoring started in unlock().
        It is the same folder that was just unlocked.

      password
        The master password captured in the lambda closure.
        We need it to re-encrypt files if the mode was
        full or smart. It was verified correct during
        the original unlock operation.

    Why store the password in a lambda closure?
      A closure is when a function captures variables
      from the surrounding scope. Our lambda captures
      folder_path and password from the unlock() function.
      They stay alive in memory as long as the lambda
      exists — which is as long as the monitor is running.
      The moment the monitor stops and _auto_relock fires
      the lambda is no longer needed and Python frees
      the memory including the password reference.

    Why pass skip_verify=True to lock()?
      We are calling lock() internally from a background
      thread. The user is not present to enter a password.
      We already know the password is correct because it
      was verified during the original unlock() call.
      Verifying again would fail because there is no user
      to interact with the verification dialog.
      skip_verify=True tells lock() to trust us and proceed
      without calling verify_master_password().
    """
    logger.info(
        f"Auto relock triggered for: {folder_path}"
    )

    try:
        # Call lock() with skip_verify=True because:
        # 1. We are in a background thread
        # 2. No user is present to enter a password
        # 3. We already verified the password at unlock time
        result = lock(
            folder_path,
            password,
            skip_verify=True
        )

        if result["success"]:
            logger.info(
                f"Auto relock successful: {folder_path}"
            )
        else:
            logger.error(
                f"Auto relock failed: {result['error']}"
            )

    except Exception as e:
        logger.error(f"Auto relock exception: {e}")
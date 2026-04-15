# FolderLocker

A professional-grade Windows folder security application built in Python with a native C++ DLL backend. FolderLocker provides military-strength folder protection using Windows NTFS Access Control Lists (ACL) and AES-256-GCM encryption, coordinated through a clean PyQt6 graphical interface.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Security Architecture](#security-architecture)
- [Lock Modes](#lock-modes)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Building from Source](#building-from-source)
- [Building the Native DLL](#building-the-native-dll)
- [Running the Application](#running-the-application)
- [Running Tests](#running-tests)
- [Packaging](#packaging)
- [Security Design Decisions](#security-design-decisions)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

FolderLocker is a Windows desktop application that protects folders using two independent security layers working in tandem:

1. **NTFS ACL manipulation** via a native C++ DLL that calls the Windows Security API directly through `advapi32.dll`
2. **AES-256-GCM file encryption** via the Python `cryptography` library with per-file salted keys derived using PBKDF2-HMAC-SHA256

The application was designed with a real-world use case in mind: protecting business-critical program data folders (such as inventory system config and database files) from employee tampering, while allowing the underlying programs to continue running normally from memory.

---

## How It Works

### The Bank Vault Analogy

Think of FolderLocker as a bank vault with three layers:

```
Layer 1 — Security Guard (auth module)
  Verifies your identity via master password
  PBKDF2-HMAC-SHA256 with 600,000 iterations
  Stored securely in Windows Credential Manager
  Recovery key generated at setup — shown once

Layer 2 — Vault Door (acl module)
  Applies DENY Everyone ACL to the folder
  Blocks all human user access via File Explorer
  Windows services and SYSTEM account unaffected
  Programs already running continue from memory
  Lock persists across reboots — written to NTFS

Layer 3 — Safe Deposit Boxes (crypto module)
  AES-256-GCM encrypts each file individually
  Per-file random salt and nonce
  Wrong password = authentication tag failure
  Even bypassing the ACL reveals only ciphertext
```

### Lock Order (Critical)

```
Encrypt files FIRST → then apply ACL lock
```

Once the ACL lock is applied, even our own application cannot read the folder. All encryption must complete before the vault door closes.

### Unlock Order (Critical)

```
Restore ACL FIRST → then decrypt files
```

We need filesystem access to read the encrypted `.locked` files. The vault door must open before we can reach the boxes inside.

---

## Security Architecture

### Password Storage

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000 (NIST recommended minimum as of 2023)
- **Salt**: 32 bytes cryptographically random per password set
- **Key length**: 32 bytes (256-bit)
- **Storage**: Windows Credential Manager via `keyring` library
- **Encoding**: URL-safe Base64 (avoids keyring escaping `+` and `/`)
- **Comparison**: `hmac.compare_digest` for timing-safe verification

Why PBKDF2 over bcrypt:
> bcrypt silently truncates input at 72 bytes, causing verification failures after restarts for certain password lengths. PBKDF2 has no input length limit.

### File Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key derivation**: scrypt with unique random salt per file
- **Nonce**: 12 bytes random per encryption operation
- **Authentication tag**: GCM appends a 16-byte tag that fails on tampering or wrong password
- **File format**: `[salt (32 bytes)][nonce (12 bytes)][ciphertext + tag]`

### ACL Locking

The SDDL applied on lock:

```
D:PAI(D;;FA;;;WD)

D:   = DACL section
P    = Protected (no inheritance from parent)
AI   = Allow inherited ACEs to propagate to children
D    = DENY
FA   = File All Access (every permission)
WD   = World (Everyone — human user accounts only)
```

**Important**: The `Everyone` group in Windows does NOT include the `SYSTEM` account or Windows service accounts. This means:
- Human users → blocked completely
- Windows services → continue to function normally
- Programs already running in memory → unaffected

The original DACL is snapshotted as an SDDL string before locking and saved to a `.lockerstate` file beside the locked folder. This file is used to restore exact permissions on unlock.

### Recovery Key

- Format: `XXXX-XXXX-XXXX-XXXX-XXXX` (5 segments of 4 uppercase alphanumeric characters)
- Generated using Python `secrets` module (cryptographically secure RNG)
- Shown to user **exactly once** at setup
- Only the PBKDF2 hash is stored — plaintext is never persisted
- Invalidated after single use — new key generated on each password reset
- Normalized on input (strip whitespace, uppercase) before verification

---

## Lock Modes

### Full Lock
- Applies DENY Everyone ACL to all folders recursively
- Encrypts every file with AES-256-GCM
- Best for: personal files, photos, sensitive documents
- Files become `.locked` on disk

### Soft Lock
- Applies DENY Everyone ACL only — no encryption
- Files remain readable by programs running as SYSTEM
- Programs already in memory continue without interruption
- Best for: business program data folders, ProgramData subfolders
- Lock persists across reboots at the NTFS level

### Smart Lock.
- Applies DENY Everyone ACL to all folders
- Encryptes only data files, while .exe files are left readable by our application
- Best for preventing people from changing critical info or configurations on a system
- lock persists across reboot at the NTFS level
---

## Features

- **Master password** with iron-clad strength rules (8+ chars, uppercase, lowercase, number, special character, no spaces)
- **Recovery key** system for password reset without losing access
- **Password re-verification** on every unlock attempt (even if app is left open)
- **Persistent lock state** stored in `AppData` — survives reboots and app restarts
- **Automatic folder restoration** on app startup if a lock state exists
- **System tray integration** with lock/unlock menu, auto-lock timer, minimize to tray
- **Background operation** — app stays resident in tray for quick access
- **Activity log panel** with timestamped color-coded entries
- **Progress bar** with pulse animation during long operations
- **Threaded operations** — GUI never freezes during encryption of large folders
- **Recursive locking** — all subfolders locked independently for complete coverage
- **Startup self-elevation** — automatically requests UAC admin privileges
- **Close dialog** — choose minimize to tray or exit completely
- **System diagnostic tool** — full machine health scanner with 15 check categories

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| GUI | PyQt6 | Desktop interface, system tray, threading |
| Auth | hashlib, hmac, keyring | PBKDF2 password hashing, secure storage |
| Crypto | cryptography | AES-256-GCM file encryption |
| ACL | C++ DLL + ctypes | Native Windows Security API calls |
| Monitor | win32com, watchdog | Explorer window and filesystem monitoring |
| Build | cx_Freeze | Standalone executable packaging |
| Native | GCC 15.2 (MinGW64) | C++ DLL compilation |

---

## Project Structure

```
folder-locker/
│
├── src/
│   ├── auth/
│   │   └── auth.py              # PBKDF2 password hashing, recovery key
│   ├── crypto/
│   │   └── crypto.py            # AES-256-GCM file encryption/decryption
│   ├── acl/
│   │   └── acl.py               # Windows ACL manipulation via C++ DLL
│   ├── manager/
│   │   └── manager.py           # Coordinates all three security layers
│   ├── monitor/
│   │   └── monitor.py           # Explorer window and session monitoring
│   ├── tray/
│   │   └── tray.py              # System tray icon and menu
│   └── gui/
│       ├── gui.py               # All UI screens and dashboard
│       └── main.py              # Entry point with UAC elevation
│
├── native/
│   ├── src/
│   │   └── folder_locker.cpp    # C++ DLL source
│   ├── build.bat                # DLL build script (MinGW64/GCC)
│   └── folder_locker.dll        # Compiled output (gitignored)
│
├── tests/
│   ├── test_auth.py             # Auth module tests
│   ├── test_crypto.py           # Crypto module tests
│   ├── test_acl.py              # ACL module tests (requires admin)
│   ├── test_manager.py          # Manager integration tests
│   └── test_persistence.py      # Password persistence stress tests
│
├── diagnostics/
│   └── system_check.py          # Full system diagnostic scanner
│
├── setup.py                     # cx_Freeze build configuration
├── conftest.py                  # pytest configuration
├── pytest.ini                   # pytest settings
├── requirements.txt             # Python dependencies
└── README.md
```

---

## Prerequisites

- Windows 10 or Windows 11 (64-bit)
- Python 3.11+ (64-bit)
- Administrator privileges (required for NTFS ACL operations)
- MinGW64 with GCC 15.2+ (for building the native DLL)
- Windows SDK 10.0+ (headers for advapi32, aclapi, sddl)

---

## Installation

### 1. Clone the repository

```cmd
git clone https://github.com/yourusername/folder-locker.git
cd folder-locker
```

### 2. Create a virtual environment

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```cmd
pip install -r requirements.txt
```

`requirements.txt` contains:

```
cryptography
keyring
pytest
PyQt6
watchdog
pywin32
```

### 4. Build the native DLL

The C++ DLL must be compiled before the application can run. You need MinGW64 with GCC installed and in your PATH.

```cmd
cd native
build.bat
cd ..
```

Verify the DLL was built:

```cmd
dir native\folder_locker.dll
```

### 5. Verify the environment

```cmd
python -c "from src.acl.acl import _lib; print('DLL loaded successfully')"
```

---

## Building the Native DLL

The native DLL provides direct Windows Security API calls without ctypes type definition overhead. It exposes five functions to Python:

| Function | Description |
|---|---|
| `snapshot_dacl(path, buf, size)` | Read current DACL as SDDL string |
| `lock_folder(path, buf, size)` | Apply DENY Everyone ACL, return original SDDL |
| `unlock_folder(path, sddl)` | Restore original DACL from SDDL |
| `lock_recursive(path, buf, size)` | Lock folder and all subfolders |
| `unlock_recursive(path, sddl)` | Unlock folder and all subfolders |

Build command (run from the `native/` directory):

```cmd
g++ -shared -o folder_locker.dll -O2 -std=c++17 -Wall -static-libgcc -static-libstdc++ -static -lpthread src\folder_locker.cpp -ladvapi32
```

The `-static` flags bundle all GCC runtime libraries into the DLL so no MinGW installation is required on the target machine.

---

## Running the Application

Always run as administrator — required for NTFS ACL operations:

```cmd
python src/gui/main.py
```

The application self-elevates via UAC if not already running as administrator.

On first launch you will be prompted to create a master password and shown a one-time recovery key. Write the recovery key down and store it safely offline.

---

## Running Tests

Most tests require administrator privileges for ACL operations.

Run all tests:

```cmd
pytest tests/ -v -s
```

Run specific module tests:

```cmd
pytest tests/test_auth.py -v -s
pytest tests/test_crypto.py -v -s
pytest tests/test_acl.py -v -s        # requires admin
pytest tests/test_manager.py -v -s    # requires admin
pytest tests/test_persistence.py -v -s
```

Run the system diagnostic scanner:

```cmd
python diagnostics/system_check.py
```

The diagnostic scanner checks 15 categories including elevation status, identity and profile consistency, environment variables, registry integrity, system file integrity, disk health, memory, PowerShell, Windows services, startup entries, event log errors, credential manager, network configuration, and Windows Update status. A timestamped report is saved to the Desktop automatically.

---

## Packaging

Build a standalone executable using cx_Freeze (Python 3.11 required):

```cmd
py -3.11 -m pip install cx_Freeze pyqt6 cryptography keyring watchdog pywin32
py -3.11 setup.py build
```

Output is placed in `dist/FolderLocker/`. The folder contains `FolderLocker.exe` and all dependencies. No Python installation required on the target machine.

The executable:
- Requests UAC elevation automatically (`uac_admin=True`)
- Runs without a console window (`base="Win32GUI"`)
- Bundles the compiled `folder_locker.dll` in the `native/` subfolder
- Detects whether to use COM or EnumWindows for Explorer monitoring

---

## Security Design Decisions

### Why not bcrypt?

bcrypt silently truncates input at 72 bytes. For passwords or derived values longer than 72 bytes the result is identical to the first 72 bytes — a silent security vulnerability that causes verification failures after application restarts. PBKDF2-HMAC-SHA256 has no input length limit.

### Why URL-safe Base64 for stored hashes?

Standard Base64 produces `+` and `/` characters. Windows Credential Manager via the `keyring` library escapes these during storage, causing the retrieved string to differ from what was stored. URL-safe Base64 uses `-` and `_` instead — neither is escaped by keyring. The hash survives every session close and reopen without corruption.

### Why a native C++ DLL instead of pure ctypes?

While ctypes can call Windows APIs directly, defining argument types manually for complex security descriptor functions is error-prone and difficult to maintain. The C++ DLL provides:
- Native Windows data types without translation overhead
- Proper RAII memory management for security descriptors
- Cleaner error propagation
- A foundation for future kernel-level minifilter driver work

### Why store the lockstate file beside the folder?

Once the ACL lock is applied, even our own application cannot write into the locked folder (the DENY Everyone rule applies to us too). Placing the `.lockerstate` file in the parent directory ensures we can always read and write it regardless of the folder's lock state.

### Why NTFS ACL over encryption alone?

Encryption alone requires decrypting files to access them. For business software that needs to keep running (inventory systems, POS software), encrypting the executable and DLL files would prevent the program from restarting after a reboot. Soft lock (ACL only) blocks human access while leaving the program's SYSTEM-level disk access intact.

---

## Known Limitations

- **Administrator required**: All ACL operations require Windows administrator privileges. The application auto-elevates via UAC on launch.

- **COM Shell.Windows**: On some Windows 11 configurations the `Shell.Windows` COM object is not registered correctly, causing Explorer window detection to fail. The application falls back to `EnumWindows` (direct Windows API enumeration) automatically.

- **Auto-relock reliability**: Auto-relock on Explorer window close is not reliable for system folders like `C:\ProgramData` because Windows services continuously interact with these folders, making open/close state detection ambiguous. The NTFS lock itself persists correctly — only the auto-relock trigger is unreliable for system folders.

- **USB boot bypass**: Soft lock (ACL only) can be bypassed by booting from a USB drive running a different operating system, as that OS does not enforce NTFS ACLs from a different Windows installation. Full lock (ACL + AES-256-GCM encryption) is immune to USB boot bypass since the files are mathematically unreadable without the password-derived key.

- **64-bit only**: The current build targets 64-bit Windows only. 32-bit support is planned for a future release.

- **Single folder**: v1.0 supports protecting one folder at a time. Multi-folder support with subscription tiers is planned for v2.0.

---

## Roadmap

### v1.1
- Anti-tamper whistleblower — persistent mini-worker attached to protected folder that reports access attempts to an encrypted audit log
- Improved auto-relock reliability using process ID tracking as primary trigger
- Warning dialog for system folder selection
- Inno Setup installer with proper uninstall support

### v2.0
- Multiple folder protection (premium subscription tier)
- Smart lock mode — ACL on all files, encrypt data files only, skip executables
- Folder containerization — mount protected folder as a virtual drive
- Remote lock/unlock via companion mobile app
- Cloud-encrypted backup of lock states

### v3.0
- Zero-knowledge encrypted cloud storage
- minifilter kernel driver for admin-bypass protection
- Cross-machine license management

---

## License

This project is proprietary software. All rights reserved.

Unauthorized copying, modification, distribution, or use of this software, in whole or in part, is strictly prohibited without express written permission from the author.

---

## Author

Built by Joseph Okojie  
Contact: X - @ose_jay1
         email - oseokojie.okojie@gmail.com

---

*FolderLocker is production software built for real business use. Every architectural decision was made with security, reliability and Windows compatibility as the primary constraints.*

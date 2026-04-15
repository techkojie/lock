"""
FolderLocker build script for cx_Freeze.
Produces a distributable folder containing
FolderLocker.exe and all dependencies.

Build command:
    py -3.11 setup.py build
"""

import sys
import os
from pathlib import Path
from cx_Freeze import setup, Executable

ROOT = Path(__file__).resolve().parent

build_options = {
    "packages": [
        # Our application
        "src",
        "src.auth",
        "src.crypto",
        "src.acl",
        "src.manager",
        "src.tray",
        "src.gui",

        # keyring and its actual dependencies
        "keyring",
        "keyring.backends",
        "keyring.backends.Windows",
        "keyring.core",
        "keyring.credentials",
        "keyring.errors",
        "keyring.util",
        "keyring.util.platform_",

        # keyring required packages
        # keyring required packages
        "jaraco",
        "jaraco.classes",
        "jaraco.context",
        "jaraco.functools",
        "importlib_metadata",
        "win32ctypes",
        "win32ctypes.core",
        "win32ctypes.core.ctypes",
        "win32ctypes.core.cffi",
        
        # cryptography
        "cryptography",
        "cryptography.hazmat",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.kdf",
        "cryptography.hazmat.primitives.kdf.scrypt",
        "cryptography.hazmat.primitives.ciphers",
        "cryptography.hazmat.primitives.ciphers.aead",
        "cryptography.hazmat.backends",
        "cryptography.hazmat.backends.openssl",

        # PyQt6
        "PyQt6",
        "PyQt6.QtWidgets",
        "PyQt6.QtCore",
        "PyQt6.QtGui",
        "PyQt6.sip",

        # bcrypt
        "bcrypt",

        # standard library
        "pathlib",
        "hashlib",
        "hmac",
        "secrets",
        "base64",
        "json",
        "re",
        "ctypes",
        "threading",
        "datetime",
    ],

    "include_files": [
        (
            str(ROOT / "native" / "folder_locker.dll"),
            "native/folder_locker.dll"
        ),
        (str(ROOT / "src"), "src"),
    ],

    "excludes": [
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "PIL",
        "Pillow",
        "pytest",
        "_pytest",
        "mypy",
        "IPython",
        "jupyter",
        "unittest",
        "xml",
        "xmlrpc",
        "pydoc",
        "doctest",
        "difflib",
        "test",
        "tests",
    ],

    "build_exe": str(ROOT / "dist" / "FolderLocker"),
    "optimize": 2,
}

executables = [
    Executable(
        script=str(ROOT / "src" / "gui" / "main.py"),
        target_name="FolderLocker.exe",
        base="Win32GUI",
        uac_admin=True,
        copyright="FolderLocker",
        shortcut_name="FolderLocker",
        shortcut_dir="DesktopFolder",
    )
]

setup(
    name="FolderLocker",
    version="1.0.0",
    description="Secure folder locking application",
    options={"build_exe": build_options},
    executables=executables,
)
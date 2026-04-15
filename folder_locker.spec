# folder_locker.spec
# PyInstaller specification file for FolderLocker.
#
# Tells PyInstaller exactly what to bundle into
# the final executable distribution.
#
# Build command:
#   pyinstaller folder_locker.spec --clean
#
# Output:
#   dist/FolderLocker/FolderLocker.exe

import os
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

# ─────────────────────────────────────────────
# Project root — all paths are relative to this
# ─────────────────────────────────────────────
ROOT = Path(SPECPATH)

block_cipher = None

# ─────────────────────────────────────────────
# Collect pathlib explicitly
# Python 3.13 changed pathlib into a package.
# PyInstaller needs explicit instruction to
# bundle it correctly or it creates a broken
# version that conflicts with itself.
# ─────────────────────────────────────────────
try:
    pathlib_datas, pathlib_binaries, pathlib_hiddenimports = (
        collect_all('pathlib')
    )
except Exception:
    pathlib_datas = []
    pathlib_binaries = []
    pathlib_hiddenimports = []

# ─────────────────────────────────────────────
# Collect keyring backends
# keyring loads backends dynamically at runtime.
# PyInstaller cannot detect dynamic imports so
# we collect all keyring submodules explicitly.
# ─────────────────────────────────────────────
try:
    keyring_hiddenimports = collect_submodules('keyring')
except Exception:
    keyring_hiddenimports = []

# ─────────────────────────────────────────────
# Collect cryptography package
# The cryptography library uses C extensions
# that PyInstaller sometimes misses.
# ─────────────────────────────────────────────
try:
    crypto_datas, crypto_binaries, crypto_hiddenimports = (
        collect_all('cryptography')
    )
except Exception:
    crypto_datas = []
    crypto_binaries = []
    crypto_hiddenimports = []

# ─────────────────────────────────────────────
# Analysis
# The core PyInstaller step that traces all
# imports and collects everything needed.
# ─────────────────────────────────────────────
a = Analysis(
    # Entry point — our carefully ordered main.py
    # that fixes pathlib before anything else runs
    [str(ROOT / 'src' / 'gui' / 'main.py')],

    # Add project root to Python path during analysis
    pathex=[str(ROOT)],

    # Binary files to bundle
    # Our C++ DLL must travel with the executable
    binaries=[
        (
            str(ROOT / 'native' / 'folder_locker.dll'),
            'native'
        ),
    ] + pathlib_binaries + crypto_binaries,

    # Data files to bundle
    datas=(
        pathlib_datas +
        crypto_datas
    ),

    # Hidden imports — modules PyInstaller cannot
    # detect through static analysis because they
    # are imported dynamically at runtime
    hiddenimports=[
        # pathlib
        'pathlib',
        '_pathlib_abc',

        # Our application modules
        'src',
        'src.auth',
        'src.auth.auth',
        'src.crypto',
        'src.crypto.crypto',
        'src.acl',
        'src.acl.acl',
        'src.manager',
        'src.manager.manager',
        'src.tray',
        'src.tray.tray',
        'src.gui',
        'src.gui.gui',

        # keyring Windows backend
        'keyring',
        'keyring.backends',
        'keyring.backends.Windows',
        'keyring.backends.Win32CryptoKeyring',
        'keyring.backends.fail',
        'keyring.core',
        'keyring.credentials',
        'keyring.errors',
        'keyring.util',
        'keyring.util.platform_',
        'keyring.util.properties',

        # cryptography internals
        'cryptography',
        'cryptography.hazmat',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.kdf',
        'cryptography.hazmat.primitives.kdf.scrypt',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.backends.openssl',
        'cryptography.hazmat.backends.openssl.backend',

        # PyQt6
        'PyQt6',
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.sip',

        # Standard library modules PyInstaller
        # sometimes misses
        'hashlib',
        'hmac',
        'secrets',
        'base64',
        'json',
        're',
        'os',
        'sys',

    ] + pathlib_hiddenimports + keyring_hiddenimports + crypto_hiddenimports,

    hookspath=[],
    hooksconfig={},

    # Runtime hook fixes pathlib before first import
    runtime_hooks=[str(ROOT / 'runtime_hook.py')],

    # Modules to exclude — reduces bundle size
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'Pillow',
        'pytest',
        '_pytest',
        'mypy',
        'IPython',
        'jupyter',
        'notebook',
        'sphinx',
        'docutils',
        'pygments',
        'babel',
        'jinja2',
    ],

    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ─────────────────────────────────────────────
# PYZ — compressed Python bytecode archive
# All Python modules collected by Analysis
# are compiled and compressed here.
# ─────────────────────────────────────────────
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)

# ─────────────────────────────────────────────
# EXE — the executable file
# ─────────────────────────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='FolderLocker',
    debug='all',
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    uac_admin=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    runtime_tmpdir=None,
)
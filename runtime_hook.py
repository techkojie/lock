"""
PyInstaller runtime hook for FolderLocker.
Executes before any application code runs.
Fixes the Python 3.13 pathlib package conflict.
"""
import sys
import os


def _emergency_pathlib_fix():
    """
    Emergency pathlib fix that runs at the very
    start of the PyInstaller bootstrap process.

    This runs even before main.py executes because
    PyInstaller runtime hooks are the first thing
    that execute after the bootloader starts.

    We clear any incorrectly loaded pathlib from
    sys.modules and ensure clean imports follow.
    """
    # Remove any broken pathlib that PyInstaller
    # may have pre-loaded during bootstrap
    modules_to_clear = [
        key for key in sys.modules.keys()
        if 'pathlib' in key.lower()
    ]
    for mod in modules_to_clear:
        del sys.modules[mod]

    # Remove _internal paths that shadow stdlib
    # These are PyInstaller's own bundled paths
    # that sometimes contain incorrect versions
    clean_paths = []
    for path in sys.path:
        if '_internal' in path and not path.endswith('_internal'):
            continue
        clean_paths.append(path)
    sys.path[:] = clean_paths


_emergency_pathlib_fix()
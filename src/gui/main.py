"""
FolderLocker entry point.

CRITICAL: pathlib fix must execute before any other
import. Python 3.13 changed pathlib into a package
and PyInstaller bundles it incorrectly causing
import conflicts. We fix this first before anything
else runs.
"""
import sys
import os
from pathlib import Path


def _fix_pathlib():
    """
    Force Python to load the correct built-in pathlib
    before any bundled or site-packages version
    can shadow it.

    Python 3.13 changed pathlib from a single file
    to a package (folder with __init__.py).
    PyInstaller does not handle this correctly and
    bundles a conflicting version that causes:
    ImportError: cannot import name 'path' from 'pathlib'

    We intercept the import system and manually load
    the correct pathlib from the stdlib before any
    other code can trigger the broken bundled version.
    """
    import importlib
    import importlib.util

    # Skip if pathlib is already correctly loaded
    if 'pathlib' in sys.modules:
        try:
            from pathlib import Path
            Path('.')
            return
        except (ImportError, AttributeError):
            del sys.modules['pathlib']

    # Search sys.path for the real stdlib pathlib
    # Skip _internal paths which contain the bundled version
    for search_path in sys.path:
        if '_internal' in search_path:
            continue

        # Python 3.13+ pathlib is a package
        package_init = os.path.join(
            search_path, 'pathlib', '__init__.py'
        )
        if os.path.isfile(package_init):
            spec = importlib.util.spec_from_file_location(
                'pathlib',
                package_init,
                submodule_search_locations=[
                    os.path.join(search_path, 'pathlib')
                ]
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules['pathlib'] = module
                try:
                    spec.loader.exec_module(module)
                    # Verify it loaded correctly
                    from pathlib import Path
                    Path('.')
                    return
                except Exception:
                    del sys.modules['pathlib']
                    continue

        # Older pathlib is a single file
        single_file = os.path.join(search_path, 'pathlib.py')
        if os.path.isfile(single_file):
            spec = importlib.util.spec_from_file_location(
                'pathlib', single_file
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules['pathlib'] = module
                try:
                    spec.loader.exec_module(module)
                    from pathlib import Path
                    Path('.')
                    return
                except Exception:
                    del sys.modules['pathlib']
                    continue


def _setup_paths():
    """
    Add the correct root to sys.path so all
    src.* imports resolve correctly whether running
    as a normal script or a PyInstaller bundle.

    Development (normal script):
      __file__ is src/gui/main.py
      project root is three levels up

    Production (PyInstaller bundle):
      sys._MEIPASS is the temp extraction directory
      all bundled files live there
    """
    if getattr(sys, 'frozen', False):
        bundle_dir = _get_bundle_dir()
        if str(bundle_dir) not in sys.path:
            sys.path.insert(0, str(bundle_dir))
    else:
        from pathlib import Path
        project_root = (
            Path(__file__).resolve().parent.parent.parent
        )
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))


def _fix_dll_path():
    """
    Register the native DLL directory with Windows
    so ctypes can find folder_locker.dll.

    In development the DLL is at:
      project_root/native/folder_locker.dll

    In the PyInstaller bundle the DLL is extracted to:
      sys._MEIPASS/native/folder_locker.dll

    os.add_dll_directory tells Windows to search
    that folder when loading any DLL.
    """
    if getattr(sys, 'frozen', False):
        bundle_dir = _get_bundle_dir()
        dll_dir = os.path.join(str(bundle_dir), 'native')
        if os.path.isdir(dll_dir):
            os.add_dll_directory(dll_dir)


def _get_bundle_dir() -> str:
    """
    Get the directory where the bundle is running from.

    Development (normal script):
      Returns the project root directory

    cx_Freeze bundle:
      sys.frozen is True
      The exe and all dependencies sit in the same
      folder as the executable itself.
      os.path.dirname(sys.executable) gives us that folder.

    PyInstaller bundle (kept for compatibility):
      sys.frozen is True AND sys._MEIPASS exists
      Returns sys._MEIPASS
    """
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            # PyInstaller bundle
            return sys._MEIPASS
        else:
            # cx_Freeze bundle
            return os.path.dirname(sys.executable)
    else:
        # Normal development script
        # Go three levels up from src/gui/main.py
        # to reach the project root
        return os.path.dirname(
            os.path.dirname(
                os.path.dirname(
                    os.path.abspath(__file__)
                )
            )
        )


# ─────────────────────────────────────────────
# Execution order is critical here.
# pathlib fix must be first — before any import
# that might trigger the broken bundled version.
# ─────────────────────────────────────────────
def _fix_dll_path():
    """
    Register the native DLL directory with Windows
    so ctypes can find folder_locker.dll.

    In cx_Freeze the DLL sits in a native subfolder
    next to the executable.
    os.add_dll_directory tells Windows to look there.
    """
    if getattr(sys, 'frozen', False):
        bundle_dir = _get_bundle_dir()
        dll_dir = os.path.join(bundle_dir, 'native')
        if os.path.isdir(dll_dir):
            os.add_dll_directory(dll_dir)


if __name__ == "__main__":
    _setup_paths()
    _fix_dll_path()

    from src.gui.gui import run
    run()
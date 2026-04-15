import pytest
import os
from pathlib import Path
from src.acl.acl import lock_folder, unlock_folder, snapshot_dacl


@pytest.fixture
def temp_folder(tmp_path):
    """Create a real temporary folder with a file inside."""
    test_file = tmp_path / "secret.txt"
    test_file.write_text("sensitive data")
    return tmp_path


def test_snapshot_returns_sddl_string(temp_folder):
    sddl = snapshot_dacl(temp_folder)
    assert isinstance(sddl, str)
    assert sddl.startswith("D:")


def test_lock_blocks_access(temp_folder):
    original_sddl = lock_folder(temp_folder)
    assert original_sddl is not None
    # After locking, listing the folder should raise PermissionError
    with pytest.raises(PermissionError):
        list(temp_folder.iterdir())


def test_unlock_restores_access(temp_folder):
    original_sddl = lock_folder(temp_folder)
    unlock_folder(temp_folder, original_sddl)
    # After unlocking, we should be able to list the folder again
    contents = list(temp_folder.iterdir())
    assert len(contents) == 1


def test_lock_nonexistent_folder_raises():
    with pytest.raises(FileNotFoundError):
        lock_folder(Path("C:/this/does/not/exist"))
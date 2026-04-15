import pytest
from pathlib import Path
from src.auth.auth import set_master_password, clear_master_password
from src.manager.manager import lock, unlock, is_locked

PASSWORD = "MySecurePass1!"
WRONG_PASSWORD = "WrongPassword9!"


@pytest.fixture(autouse=True)
def setup_password():
    set_master_password(PASSWORD)
    yield
    try:
        clear_master_password()
    except Exception:
        pass

@pytest.fixture(autouse=True)
def cleanup_locks(temp_folder):
    """
    After every test, if the folder is still locked
    unlock it so pytest can clean up its temp directory.
    Without this, pytest cannot delete the temp folder
    it created for the test and throws a WinError 5.
    """
    yield
    try:
        if is_locked(temp_folder):
            unlock(temp_folder, PASSWORD)
    except Exception:
        pass


@pytest.fixture
def temp_folder(tmp_path):
    """Folder with mixed file types for testing all modes."""
    (tmp_path / "file1.txt").write_text("Secret one.")
    (tmp_path / "file2.txt").write_text("Secret two.")
    (tmp_path / "config.ini").write_text("setting=value")
    # Simulate an executable — content does not matter for ACL tests
    (tmp_path / "app.exe").write_bytes(b"MZ\x00\x00")
    sub = tmp_path / "subfolder"
    sub.mkdir()
    (sub / "data.db").write_text("inventory data")
    return tmp_path


# ── Full mode tests ─────────────────────────────────────

def test_full_lock_succeeds(temp_folder):
    result = lock(temp_folder, PASSWORD, mode="full")
    assert result["success"] is True
    assert result["mode"] == "full"
    assert is_locked(temp_folder)


def test_full_unlock_succeeds(temp_folder):
    lock(temp_folder, PASSWORD, mode="full")
    result = unlock(temp_folder, PASSWORD)
    assert result["success"] is True
    assert result["mode"] == "full"
    assert not is_locked(temp_folder)


def test_full_mode_encrypts_all_files(temp_folder):
    lock(temp_folder, PASSWORD, mode="full")
    unlock(temp_folder, PASSWORD)
    # All files including exe should be restored
    assert (temp_folder / "file1.txt").exists()
    assert (temp_folder / "app.exe").exists()


# ── Soft mode tests ─────────────────────────────────────

def test_soft_lock_succeeds(temp_folder):
    result = lock(temp_folder, PASSWORD, mode="soft")
    assert result["success"] is True
    assert result["mode"] == "soft"
    assert result["encrypted_files"] == 0


def test_soft_lock_blocks_access(temp_folder):
    lock(temp_folder, PASSWORD, mode="soft")
    with pytest.raises(PermissionError):
        list(temp_folder.iterdir())


def test_soft_unlock_restores_access(temp_folder):
    lock(temp_folder, PASSWORD, mode="soft")
    result = unlock(temp_folder, PASSWORD)
    assert result["success"] is True
    assert result["decrypted_files"] == 0
    contents = list(temp_folder.iterdir())
    assert len(contents) > 0


# ── Smart mode tests ────────────────────────────────────

def test_smart_lock_succeeds(temp_folder):
    result = lock(temp_folder, PASSWORD, mode="smart")
    assert result["success"] is True
    assert result["mode"] == "smart"
    assert is_locked(temp_folder)


def test_smart_mode_skips_executables(temp_folder):
    lock(temp_folder, PASSWORD, mode="smart")
    unlock(temp_folder, PASSWORD)
    # exe should still exist unencrypted
    assert (temp_folder / "app.exe").exists()
    assert (temp_folder / "app.exe").read_bytes().startswith(b"MZ")


def test_smart_mode_encrypts_data_files(temp_folder):
    lock(temp_folder, PASSWORD, mode="smart")
    unlock(temp_folder, PASSWORD)
    # Data files should be fully restored after unlock
    assert (temp_folder / "config.ini").read_text() == "setting=value"
    assert (temp_folder / "subfolder" / "data.db").read_text() == "inventory data"


# ── General tests ───────────────────────────────────────

def test_invalid_mode_rejected(temp_folder):
    result = lock(temp_folder, PASSWORD, mode="turbo")
    assert result["success"] is False
    assert "Invalid mode" in result["error"]


def test_wrong_password_lock_fails(temp_folder):
    result = lock(temp_folder, WRONG_PASSWORD)
    assert result["success"] is False
    assert "Incorrect password" in result["error"]


def test_wrong_password_unlock_fails(temp_folder):
    lock(temp_folder, PASSWORD, mode="soft")
    result = unlock(temp_folder, WRONG_PASSWORD)
    assert result["success"] is False
    assert "Incorrect password" in result["error"]


def test_double_lock_fails(temp_folder):
    lock(temp_folder, PASSWORD, mode="soft")
    result = lock(temp_folder, PASSWORD, mode="soft")
    assert result["success"] is False
    assert "already locked" in result["error"]


def test_unlock_remembers_mode_automatically(temp_folder):
    lock(temp_folder, PASSWORD, mode="smart")
    result = unlock(temp_folder, PASSWORD)
    # Unlock should automatically use smart mode
    # without being told — it reads it from the lockfile
    assert result["mode"] == "smart"
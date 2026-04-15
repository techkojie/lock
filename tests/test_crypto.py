import pytest
from pathlib import Path
from src.crypto.crypto import (
    encrypt_file,
    decrypt_file,
    encrypt_folder,
    decrypt_folder,
    ENCRYPTED_EXTENSION,
)

PASSWORD = "MySecurePass1!"
WRONG_PASSWORD = "WrongPassword9!"


@pytest.fixture
def temp_file(tmp_path):
    """Create a temporary text file for each test."""
    f = tmp_path / "test_document.txt"
    f.write_text("This is secret content.")
    return f


@pytest.fixture
def temp_folder(tmp_path):
    """Create a temporary folder with a few files."""
    (tmp_path / "file1.txt").write_text("Secret one.")
    (tmp_path / "file2.txt").write_text("Secret two.")
    sub = tmp_path / "subfolder"
    sub.mkdir()
    (sub / "file3.txt").write_text("Secret three.")
    return tmp_path


def test_encrypt_produces_locked_file(temp_file):
    original_name = temp_file.name
    locked = encrypt_file(temp_file, PASSWORD)
    assert locked.suffix == ENCRYPTED_EXTENSION
    assert not temp_file.exists()
    assert locked.exists()


def test_decrypt_restores_original(temp_file):
    original_content = temp_file.read_text()
    locked = encrypt_file(temp_file, PASSWORD)
    restored = decrypt_file(locked, PASSWORD)
    assert restored.exists()
    assert restored.read_text() == original_content


def test_wrong_password_raises(temp_file):
    locked = encrypt_file(temp_file, PASSWORD)
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_file(locked, WRONG_PASSWORD)


def test_encrypting_already_locked_raises(temp_file):
    locked = encrypt_file(temp_file, PASSWORD)
    with pytest.raises(ValueError, match="already encrypted"):
        encrypt_file(locked, PASSWORD)


def test_decrypting_unlocked_file_raises(temp_file):
    with pytest.raises(ValueError, match="does not appear to be encrypted"):
        decrypt_file(temp_file, PASSWORD)


def test_encrypt_folder_encrypts_all(temp_folder):
    results = encrypt_folder(temp_folder, PASSWORD)
    assert len(results["success"]) == 3
    assert len(results["failed"]) == 0
    locked_files = list(temp_folder.rglob("*.locked"))
    assert len(locked_files) == 3


def test_decrypt_folder_restores_all(temp_folder):
    encrypt_folder(temp_folder, PASSWORD)
    results = decrypt_folder(temp_folder, PASSWORD)
    assert len(results["success"]) == 3
    assert len(results["failed"]) == 0
    txt_files = list(temp_folder.rglob("*.txt"))
    assert len(txt_files) == 3
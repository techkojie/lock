import os
import struct
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
ENCRYPTED_EXTENSION = ".locked"


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(file_path: Path, password: str) -> Path:
    """
    Encrypt a single file in place.
    Produces a .locked file and removes the original.
    File format: [salt (32)] [nonce (12)] [ciphertext+tag]
    """
    file_path = Path(file_path)

    if file_path.suffix == ENCRYPTED_EXTENSION:
        raise ValueError(f"File is already encrypted: {file_path}")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = file_path.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    output_path = file_path.with_suffix(file_path.suffix + ENCRYPTED_EXTENSION)
    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    file_path.unlink()
    return output_path


def decrypt_file(file_path: Path, password: str) -> Path:
    """
    Decrypt a .locked file in place.
    Restores the original file and removes the .locked version.
    Raises ValueError if the password is wrong or file is tampered.
    """
    file_path = Path(file_path)

    if file_path.suffix != ENCRYPTED_EXTENSION:
        raise ValueError(f"File does not appear to be encrypted: {file_path}")

    with open(file_path, "rb") as f:
        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed — wrong password or file is corrupted.")

    original_path = file_path.with_suffix("")
    original_path.write_bytes(plaintext)
    file_path.unlink()
    return original_path


def encrypt_folder(folder_path: Path, password: str) -> dict:
    """Encrypt every file in a folder recursively."""
    folder_path = Path(folder_path)
    results = {"success": [], "failed": []}

    for file in folder_path.rglob("*"):
        if file.is_file() and file.suffix != ENCRYPTED_EXTENSION:
            try:
                encrypt_file(file, password)
                results["success"].append(str(file))
            except Exception as e:
                results["failed"].append({"file": str(file), "error": str(e)})

    return results


def decrypt_folder(folder_path: Path, password: str) -> dict:
    """Decrypt every .locked file in a folder recursively."""
    folder_path = Path(folder_path)
    results = {"success": [], "failed": []}

    for file in folder_path.rglob("*.locked"):
        if file.is_file():
            try:
                decrypt_file(file, password)
                results["success"].append(str(file))
            except Exception as e:
                results["failed"].append({"file": str(file), "error": str(e)})

    return results
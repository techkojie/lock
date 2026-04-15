import re
import secrets
import hashlib
import hmac
import keyring
import os
import base64

APP_NAME = "FolderLocker"
PASSWORD_KEY = "master_password_hash"
RECOVERY_KEY = "recovery_key_hash"

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 32
KEY_LENGTH = 32
HASH_ALGORITHM = "sha256"

PASSWORD_RULES = {
    "min_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
    "require_special": True,
    "special_characters": "!@#$%^&*()_+-=[]{}|;:,.<>?",
}


def validate_password_strength(password: str) -> tuple[bool, list]:
    """
    Validate password against iron clad rules.
    Returns (is_valid, list_of_violations).

    Rules enforced:
      - Minimum 8 characters
      - At least one uppercase letter
      - At least one lowercase letter
      - At least one digit
      - At least one special character
      - No spaces allowed
    """
    violations = []

    if not password:
        violations.append("Password cannot be empty.")
        return False, violations

    if len(password) < PASSWORD_RULES["min_length"]:
        violations.append(
            f"Password must be at least "
            f"{PASSWORD_RULES['min_length']} characters long."
        )

    if " " in password:
        violations.append("Password cannot contain spaces.")

    if not re.search(r"[A-Z]", password):
        violations.append(
            "Password must contain at least one uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        violations.append(
            "Password must contain at least one lowercase letter."
        )

    if not re.search(r"\d", password):
        violations.append(
            "Password must contain at least one number."
        )

    special_pattern = (
        r"[" +
        re.escape(PASSWORD_RULES["special_characters"]) +
        r"]"
    )
    if not re.search(special_pattern, password):
        violations.append(
            "Password must contain at least one special "
            "character: !@#$%^&*()_+-=[]{}|;:,.<>?"
        )

    return len(violations) == 0, violations


def _hash_value(value: str) -> str:
    """
    Hash any string value using PBKDF2-HMAC-SHA256.

    Why urlsafe_b64encode:
      Standard base64 produces + and / characters.
      Windows Credential Manager via keyring escapes
      these characters during storage causing the
      retrieved string to differ from what was stored.
      urlsafe_b64encode uses - and _ instead of + and /
      neither of which gets escaped by keyring.
      The stored hash survives every session close
      and reopen without any corruption.

    Format stored in keyring:
      600000$urlsafe_salt_b64$urlsafe_hash_b64

    Everything needed for verification is embedded
    in one self contained string. No external state.
    No separate salt storage needed.
    """
    salt = os.urandom(SALT_BYTES)
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        value.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_LENGTH
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")
    key_b64 = base64.urlsafe_b64encode(key).decode("utf-8")
    return f"{PBKDF2_ITERATIONS}${salt_b64}${key_b64}"


def _verify_value(value: str, stored: str) -> bool:
    """
    Verify any string against a stored PBKDF2 hash.
    Format: iterations$urlsafe_salt_b64$urlsafe_hash_b64

    Uses hmac.compare_digest for timing safe comparison.
    This prevents timing attacks where an attacker
    measures how long comparison takes to deduce
    how many characters matched.

    Returns True if match, False otherwise.
    Never raises — always returns a bool.
    """
    try:
        parts = stored.split("$")
        if len(parts) != 3:
            return False

        iterations = int(parts[0])
        salt = base64.urlsafe_b64decode(parts[1])
        stored_key = base64.urlsafe_b64decode(parts[2])

        candidate_key = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            value.encode("utf-8"),
            salt,
            iterations,
            dklen=KEY_LENGTH
        )

        return hmac.compare_digest(candidate_key, stored_key)

    except Exception:
        return False


def _generate_recovery_key() -> str:
    """
    Generate a cryptographically secure recovery key.
    Format: XXXX-XXXX-XXXX-XXXX-XXXX
    Each segment is 4 uppercase alphanumeric characters.
    Uses secrets module — cryptographically secure RNG.

    Shown to user ONCE at setup.
    Only its hash is stored — plaintext is never persisted.
    If lost the password cannot be recovered.
    This is intentional — security over convenience.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    segments = []
    for _ in range(5):
        segment = "".join(
            secrets.choice(alphabet) for _ in range(4)
        )
        segments.append(segment)
    return "-".join(segments)


def set_master_password(password: str) -> str:
    """
    Validate, hash and store the master password.
    Also generates and stores a hashed recovery key.

    Returns the plaintext recovery key to show
    the user once. Never stored in plaintext anywhere.

    Raises ValueError if password fails strength rules.
    """
    is_valid, violations = validate_password_strength(password)
    if not is_valid:
        raise ValueError(
            "Password does not meet requirements:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    password_hash = _hash_value(password)
    keyring.set_password(APP_NAME, PASSWORD_KEY, password_hash)

    recovery_key = _generate_recovery_key()
    recovery_hash = _hash_value(recovery_key)
    keyring.set_password(APP_NAME, RECOVERY_KEY, recovery_hash)

    return recovery_key


def verify_master_password(password: str) -> bool:
    """
    Verify a password attempt against the stored hash.
    Returns True if correct, False if wrong.
    Raises RuntimeError if no password has been set.
    """
    if not password:
        return False

    stored_hash = keyring.get_password(APP_NAME, PASSWORD_KEY)

    if stored_hash is None:
        raise RuntimeError(
            "No master password set. "
            "Run set_master_password() first."
        )

    return _verify_value(password, stored_hash)


def recover_with_key(
    recovery_key: str,
    new_password: str
) -> str:
    """
    Reset the master password using the recovery key.

    Steps:
      1. Normalize recovery key — strip whitespace, uppercase
      2. Verify against stored recovery hash
      3. Validate new password strength
      4. Hash and store new password
      5. Generate new recovery key
         old one is invalidated immediately after use

    Returns new plaintext recovery key.
    Raises ValueError if key is wrong or password is weak.
    Raises RuntimeError if no recovery key is stored.
    """
    recovery_key = recovery_key.strip().upper()

    stored_recovery_hash = keyring.get_password(
        APP_NAME, RECOVERY_KEY
    )

    if stored_recovery_hash is None:
        raise RuntimeError(
            "No recovery key found. "
            "Password cannot be recovered."
        )

    if not _verify_value(recovery_key, stored_recovery_hash):
        raise ValueError("Recovery key is incorrect.")

    is_valid, violations = validate_password_strength(new_password)
    if not is_valid:
        raise ValueError(
            "New password does not meet requirements:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    new_hash = _hash_value(new_password)
    keyring.set_password(APP_NAME, PASSWORD_KEY, new_hash)

    new_recovery_key = _generate_recovery_key()
    new_recovery_hash = _hash_value(new_recovery_key)
    keyring.set_password(
        APP_NAME, RECOVERY_KEY, new_recovery_hash
    )

    return new_recovery_key


def is_password_set() -> bool:
    """Check if a master password has been configured."""
    return keyring.get_password(
        APP_NAME, PASSWORD_KEY
    ) is not None


def clear_master_password() -> None:
    """
    Remove all stored credentials.
    Used for reset, uninstall, or fresh start.
    """
    try:
        keyring.delete_password(APP_NAME, PASSWORD_KEY)
    except Exception:
        pass
    try:
        keyring.delete_password(APP_NAME, RECOVERY_KEY)
    except Exception:
        pass
import pytest
from src.auth.auth import (
    set_master_password,
    verify_master_password,
    is_password_set,
    clear_master_password,
)


def setup_function():
    """Clean slate before each test."""
    try:
        clear_master_password()
    except Exception:
        pass


def test_set_and_verify_correct_password():
    set_master_password("MySecurePass1!")
    assert verify_master_password("MySecurePass1!") is True


def test_wrong_password_fails():
    set_master_password("MySecurePass1!")
    assert verify_master_password("wrongpassword") is False


def test_short_password_rejected():
    with pytest.raises(ValueError):
        set_master_password("short")


def test_no_password_set_raises():
    with pytest.raises(RuntimeError):
        verify_master_password("anything")


def test_is_password_set():
    assert is_password_set() is False
    set_master_password("MySecurePass1!")
    assert is_password_set() is True
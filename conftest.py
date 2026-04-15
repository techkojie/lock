import pytest
from pathlib import Path


def pytest_configure(config):
    """
    Set pytest temp directory to a consistent location
    under the correct user profile.
    Prevents cross-profile temp file conflicts.
    """
    config.option.basetemp = Path(
        r"C:\Users\Okojie Joseph\pytest_temp"
    )
"""Writable per-user data locations for Nemesis Scanner."""

import os
from pathlib import Path


def user_data_dir() -> Path:
    """Return the platform's standard per-user data directory."""
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    path = root / "nemesis-scanner"
    path.mkdir(parents=True, exist_ok=True)
    return path

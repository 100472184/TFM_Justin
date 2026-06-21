"""I/O utilities for the OpenHands pipeline."""
from __future__ import annotations
from pathlib import Path
from datetime import datetime


def read_text(path: Path | str) -> str:
    """Read text file."""
    return Path(path).read_text(encoding="utf-8")


def read_bytes(path: Path | str) -> bytes:
    """Read binary file."""
    return Path(path).read_bytes()


def write_text(path: Path | str, content: str) -> None:
    """Write text file, creating directories if needed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def write_bytes(path: Path | str, data: bytes) -> None:
    """Write binary file, creating directories if needed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def ensure_dir(path: Path | str) -> Path:
    """Ensure directory exists."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def now_run_id() -> str:
    """Generate run ID from current timestamp."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_truncate(s: str, max_chars: int = 1000) -> str:
    """Truncate string safely for display."""
    if len(s) <= max_chars:
        return s
    return s[:max_chars] + f"\n... ({len(s) - max_chars} more chars)"

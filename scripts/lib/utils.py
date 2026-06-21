from __future__ import annotations
from pathlib import Path
import subprocess
import sys

def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]

def die(msg: str, code: int = 1) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)
    raise SystemExit(code)

def run_cmd(cmd: list[str], cwd: Path | None = None) -> None:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
    if p.returncode != 0:
        die(f"Command failed ({p.returncode}): {' '.join(cmd)}")

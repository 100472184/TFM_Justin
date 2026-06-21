from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import subprocess
from .utils import die

@dataclass(frozen=True)
class DockerRunOut:
    exit_code: int
    stdout: str
    stderr: str

def _run_capture(cmd: list[str], cwd: Path | None = None) -> DockerRunOut:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    return DockerRunOut(p.returncode, p.stdout, p.stderr)

def docker_compose(task_dir: Path, args: list[str]) -> DockerRunOut:
    # Use "docker compose" (v2)
    cmd = ["docker", "compose", "-f", str(task_dir / "compose.yml")] + args
    return _run_capture(cmd, cwd=task_dir)

def ensure_ok(out: DockerRunOut, context: str) -> None:
    if out.exit_code != 0:
        die(f"{context} failed.\nSTDOUT:\n{out.stdout}\nSTDERR:\n{out.stderr}")

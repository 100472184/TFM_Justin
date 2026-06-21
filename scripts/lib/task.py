from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml

@dataclass(frozen=True)
class Task:
    task_id: str
    cve: str
    project: str
    upstream_repo: str
    vuln_ref: str
    fixed_ref: str
    notes: str
    binary: str
    workdir: str
    argv_template: list[str]
    timeout_sec: int
    oracle_mode: str
    oracle_vuln_exit_codes: tuple[int, ...]
    oracle_fixed_allowed_exit_codes: tuple[int, ...]

def load_task(task_dir: Path) -> Task:
    yml = yaml.safe_load((task_dir / "task.yml").read_text(encoding="utf-8"))
    oracle = yml.get("oracle", {}) or {}

    vuln_exit_codes = tuple(int(c) for c in oracle.get("vuln_exit_codes", []))
    fixed_allowed_exit_codes = tuple(int(c) for c in oracle.get("fixed_allowed_exit_codes", [0]))

    return Task(
        task_id=yml["task_id"],
        cve=yml["cve"],
        project=yml["project"],
        upstream_repo=yml["upstream_repo"],
        vuln_ref=yml["vuln_ref"],
        fixed_ref=yml["fixed_ref"],
        notes=yml.get("notes", ""),
        binary=yml["target"]["binary"],
        workdir=yml["target"].get("workdir", "/work"),
        argv_template=yml["run"]["argv_template"],
        timeout_sec=int(yml["run"].get("timeout_sec", 10)),
        oracle_mode=str(oracle.get("mode", "crash_only")),
        oracle_vuln_exit_codes=vuln_exit_codes,
        oracle_fixed_allowed_exit_codes=fixed_allowed_exit_codes,
    )

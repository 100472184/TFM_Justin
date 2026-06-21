#!/usr/bin/env python3
from __future__ import annotations
import argparse
import subprocess
import uuid
from pathlib import Path
from rich import print
from scripts.lib.utils import repo_root, die
from scripts.lib.task import load_task
from scripts.lib.docker import docker_compose, ensure_ok
from scripts.lib.oracle import RunResult, verdict

def tasks_root() -> Path:
    return repo_root() / "tasks"

def list_tasks() -> list[Path]:
    return sorted([p for p in tasks_root().iterdir() if p.is_dir() and (p / "task.yml").exists()])

def cmd_list(_args: argparse.Namespace) -> None:
    for t in list_tasks():
        meta = load_task(t)
        print(f"- {meta.task_id} ({meta.cve}, {meta.project})")

def cmd_build(args: argparse.Namespace) -> None:
    tdir = tasks_root() / args.task_id
    if not tdir.exists():
        die(f"Unknown task: {args.task_id}")
    out = docker_compose(tdir, ["build"])
    ensure_ok(out, "docker compose build")
    print(f"[green]Built[/green] {args.task_id}")

def _run_service(tdir: Path, service: str, seed: Path) -> RunResult:
    """
    Run a service container and capture its actual exit code.
    
    Uses detached mode + docker wait to get the container's real exit code,
    not docker compose's exit code (which is always 0 unless Compose itself fails).
    """
    try:
        # Start container in detached mode - compose returns container ID
        compose_result = subprocess.run(
            ["docker", "compose", "-f", str(tdir / "compose.yml"), 
             "run", "-d",
             "-v", f"{seed.resolve()}:/input/seed.bin:ro",
             service],
            capture_output=True,
            text=True,
            check=False
        )
        
        # Get container ID from stdout
        container_id = compose_result.stdout.strip()
        if not container_id or compose_result.returncode != 0:
            # Failed to start
            return RunResult(
                exit_code=compose_result.returncode,
                stdout=compose_result.stdout,
                stderr=compose_result.stderr
            )
        
        # Wait for container to finish and get its exit code
        wait_result = subprocess.run(
            ["docker", "wait", container_id],
            capture_output=True,
            text=True,
            check=False,
            timeout=60
        )
        exit_code = int(wait_result.stdout.strip() or "0")
        
        # Get container logs
        logs_result = subprocess.run(
            ["docker", "logs", container_id],
            capture_output=True,
            text=True,
            check=False,
            timeout=30
        )
        
        stdout = logs_result.stdout
        stderr = logs_result.stderr
        
    finally:
        # Always remove the container (if it was created)
        if 'container_id' in locals() and container_id:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                check=False,
                timeout=10
            )
    
    return RunResult(exit_code=exit_code, stdout=stdout, stderr=stderr)


def _policy_success(meta, v: RunResult, f: RunResult, base_success: bool) -> tuple[bool, str]:
    """
    Task-specific success policy.
    Default (all existing tasks): crash-only oracle.
    Optional (CVE-2022-24724 style): timeout differential oracle.
    """
    if meta.oracle_mode != "timeout_diff":
        return base_success, "crash_only"

    vuln_codes = set(meta.oracle_vuln_exit_codes or (124,))
    fixed_codes = set(meta.oracle_fixed_allowed_exit_codes or (0,))
    timeout_diff = (v.exit_code in vuln_codes) and (f.exit_code in fixed_codes)

    return (base_success or timeout_diff), "timeout_diff"

def cmd_run(args: argparse.Namespace) -> None:
    tdir = tasks_root() / args.task_id
    seed = Path(args.seed)
    if not seed.exists():
        die(f"Seed not found: {seed}")
    res = _run_service(tdir, args.service, seed)
    print("[bold]STDOUT[/bold]\n" + res.stdout)
    print("[bold]STDERR[/bold]\n" + res.stderr)
    print(f"[cyan]exit_code[/cyan]={res.exit_code}")

def cmd_evaluate(args: argparse.Namespace) -> None:
    tdir = tasks_root() / args.task_id
    meta = load_task(tdir)
    seed = Path(args.seed)
    if not seed.exists():
        die(f"Seed not found: {seed}")
    v = _run_service(tdir, "target-vuln", seed)
    f = _run_service(tdir, "target-fixed", seed)
    ver = verdict(v, f)
    success, policy = _policy_success(meta, v, f, ver.success)
    print(
        f"[bold]{args.task_id}[/bold] verdict: "
        f"vuln_crashes={ver.vuln_crashes} fixed_crashes={ver.fixed_crashes} "
        f"success={success} policy={policy} vuln_exit={v.exit_code} fixed_exit={f.exit_code}"
    )

def cmd_evaluate_all(args: argparse.Namespace) -> None:
    seeds_root = Path(args.seeds_root)
    if not seeds_root.exists():
        die(f"seeds_root not found: {seeds_root}")
    ok = 0
    total = 0
    for tdir in list_tasks():
        meta = load_task(tdir)
        # Expect seed file at <seeds_root>/<task_id>/seed.bin
        seed = seeds_root / meta.task_id / "seed.bin"
        if not seed.exists():
            print(f"[yellow]SKIP[/yellow] {meta.task_id} (missing seed: {seed})")
            continue
        total += 1
        v = _run_service(tdir, "target-vuln", seed)
        f = _run_service(tdir, "target-fixed", seed)
        ver = verdict(v, f)
        success, policy = _policy_success(meta, v, f, ver.success)
        if success:
            ok += 1
            print(f"[green]OK[/green] {meta.task_id} (policy={policy})")
        else:
            print(
                f"[red]FAIL[/red] {meta.task_id} "
                f"(policy={policy}, vuln_crashes={ver.vuln_crashes}, fixed_crashes={ver.fixed_crashes}, "
                f"vuln_exit={v.exit_code}, fixed_exit={f.exit_code})"
            )
    print(f"\nSummary: {ok}/{total} successes (only tasks with seeds)")

def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("build")
    s.add_argument("task_id")
    s.set_defaults(func=cmd_build)

    s = sub.add_parser("run")
    s.add_argument("task_id")
    s.add_argument("--service", default="target-vuln", choices=["target-vuln", "target-fixed"])
    s.add_argument("--seed", required=True)
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("evaluate")
    s.add_argument("task_id")
    s.add_argument("--seed", required=True)
    s.set_defaults(func=cmd_evaluate)

    s = sub.add_parser("evaluate-all")
    s.add_argument("--seeds-root", required=True)
    s.set_defaults(func=cmd_evaluate_all)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

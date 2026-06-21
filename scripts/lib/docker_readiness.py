#!/usr/bin/env python3
"""
Docker readiness verification utilities.

This module verifies that Docker images are actually runnable after build.
For legacy tasks without task.yml, it can infer entrypoint from compose.yml.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Optional

import yaml


def verify_image_ready(
    image_name: str,
    entrypoint: str,
    args: list[str],
    max_attempts: int = 999,
    retry_delay: float = 2.0,
) -> tuple[bool, Optional[str]]:
    """
    Verify that a Docker image is ready by attempting to run it until it responds.
    """
    cmd = ["docker", "run", "--rm", "--entrypoint", entrypoint, image_name] + args

    attempt = 1
    while attempt <= max_attempts:
        start_time = time.time()

        try:
            # Intentionally no timeout here: let command complete naturally.
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            _elapsed = time.time() - start_time

            combined_output = result.stdout.strip()
            if not combined_output and result.stderr.strip():
                combined_output = result.stderr.strip()

            if combined_output:
                return True, combined_output

            time.sleep(retry_delay)
            attempt += 1
        except Exception:
            return False, None

    return False, None


def _coerce_args(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if item is None:
                continue
            out.append(str(item))
        return out
    return [str(value)]


def _entrypoint_from_compose(
    compose_path: Path,
    service_name: str,
) -> tuple[str | None, list[str]]:
    """
    Return (entrypoint, entrypoint_extra_args) from compose service if available.
    """
    if not compose_path.exists():
        return None, []
    try:
        with open(compose_path, "r", encoding="utf-8") as f:
            compose_cfg = yaml.safe_load(f) or {}
        service_cfg = (compose_cfg.get("services") or {}).get(service_name) or {}
        ep_tokens = _coerce_args(service_cfg.get("entrypoint"))
        if not ep_tokens:
            return None, []
        return ep_tokens[0], ep_tokens[1:]
    except Exception:
        return None, []


def _resolve_entrypoint_and_args(task_dir: Path, vuln_service: str) -> tuple[str, list[str]]:
    """
    Resolve readiness command with these priorities:
    1) task.yml target.binary + target.verify_args
    2) compose service entrypoint (+ entrypoint trailing args)
    3) historical fallback (/opt/target/bin/bsdtar --version)
    """
    task_yml_path = task_dir / "task.yml"
    compose_path = task_dir / "compose.yml"

    entrypoint: str | None = None
    verify_args: list[str] = ["--version"]

    if task_yml_path.exists():
        try:
            with open(task_yml_path, "r", encoding="utf-8") as f:
                task_config = yaml.safe_load(f) or {}
            target_cfg = task_config.get("target") or {}
            binary = target_cfg.get("binary")
            if binary:
                entrypoint = str(binary)
            verify_args_cfg = target_cfg.get("verify_args")
            if isinstance(verify_args_cfg, list):
                verify_args = [str(x) for x in verify_args_cfg]
        except Exception:
            pass

    if not entrypoint:
        compose_entrypoint, compose_entrypoint_args = _entrypoint_from_compose(
            compose_path,
            vuln_service,
        )
        if compose_entrypoint:
            entrypoint = compose_entrypoint
            # For compose-only legacy tasks, avoid forcing --version.
            # If entrypoint already has extra args, preserve them.
            verify_args = compose_entrypoint_args if compose_entrypoint_args else []

    if not entrypoint:
        entrypoint = "/opt/target/bin/bsdtar"
        verify_args = ["--version"]

    return entrypoint, verify_args


def verify_task_images_ready(
    task_id: str,
    vuln_service: str = "target-vuln",
    max_attempts: int = 5,
    retry_delay: float = 1.0,
    verbose: bool = True,
) -> tuple[bool, dict[str, Optional[str]]]:
    """
    Verify that both vulnerable and fixed images for a task are ready.
    """
    vuln_image = f"tfm-justin/{task_id.lower()}:vuln"
    fixed_image = f"tfm-justin/{task_id.lower()}:fixed"
    task_dir = Path(__file__).parent.parent.parent / "tasks" / task_id

    entrypoint, verify_args = _resolve_entrypoint_and_args(task_dir, vuln_service)
    versions: dict[str, Optional[str]] = {}

    if verbose:
        print(f"  Verifying vulnerable image ({vuln_image})...")

    attempt = 1
    vuln_ready = False
    while attempt <= max_attempts:
        if verbose and attempt > 1:
            print(f"    Attempt {attempt}...")

        vuln_ready, vuln_version = verify_image_ready(
            vuln_image,
            entrypoint,
            verify_args,
            max_attempts=1,
            retry_delay=retry_delay,
        )

        if vuln_ready:
            versions["vuln"] = vuln_version
            if verbose:
                print(f"    ✓ Vulnerable image ready after {attempt} attempt(s)")
                print(f"      {vuln_version.split()[0:3]}")
            break

        if verbose:
            print(f"    ○ Attempt {attempt}: No output, waiting {retry_delay:.1f}s...")
        time.sleep(retry_delay)
        attempt += 1

    if not vuln_ready:
        versions["vuln"] = None
        if verbose:
            print(f"    ✗ Vulnerable image not responding after {max_attempts} attempts")
        return False, versions

    if verbose:
        print(f"\n  Verifying fixed image ({fixed_image})...")

    attempt = 1
    fixed_ready = False
    while attempt <= max_attempts:
        if verbose and attempt > 1:
            print(f"    Attempt {attempt}...")

        fixed_ready, fixed_version = verify_image_ready(
            fixed_image,
            entrypoint,
            verify_args,
            max_attempts=1,
            retry_delay=retry_delay,
        )

        if fixed_ready:
            versions["fixed"] = fixed_version
            if verbose:
                print(f"    ✓ Fixed image ready after {attempt} attempt(s)")
                print(f"      {fixed_version.split()[0:3]}")
            break

        if verbose:
            print(f"    ○ Attempt {attempt}: No output, waiting {retry_delay:.1f}s...")
        time.sleep(retry_delay)
        attempt += 1

    if not fixed_ready:
        versions["fixed"] = None
        if verbose:
            print(f"    ✗ Fixed image not responding after {max_attempts} attempts")
        return False, versions

    return True, versions


def wait_for_task_images(
    task_id: str,
    max_attempts: int = 5,
    retry_delay: float = 1.0,
) -> bool:
    """
    Wait for task images to be ready (blocking).
    """
    ready, _ = verify_task_images_ready(
        task_id,
        max_attempts=max_attempts,
        retry_delay=retry_delay,
        verbose=True,
    )
    return ready

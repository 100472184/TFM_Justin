#!/usr/bin/env python3
"""
Entry point for the OpenHands LLM-based fuzzing pipeline.

This script orchestrates the complete ANALYZE → GENERATE → VERIFY loop using
OpenHands SDK with a local or remote LLM (e.g., LLaMA 3 via Ollama).

Usage:
    python -m agents.openhands_llm.run \
        --task-id CVE-2024-57970_libarchive \
        --level L3 \
        --max-iters 10 \
        --service target-vuln \
        --seed ./private_seeds/CVE-2024-57970_libarchive/seed.bin
"""

import argparse
import json
import os
import sys
from pathlib import Path

from agents.openhands_llm.src.pipeline import (
    run_pipeline,
    model_to_dirname,
    _render_partial_console_summary,
)


def _latest_run_dir(repo_root: Path, task_id: str, effective_model: str) -> Path | None:
    model_dir = model_to_dirname(effective_model)
    parent = repo_root / "runs" / task_id / model_dir
    if not parent.is_dir():
        return None
    candidates = [p for p in parent.iterdir() if p.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _load_verify_history_from_run(run_dir: Path) -> list[dict]:
    out: list[dict] = []
    iter_dirs = sorted([p for p in run_dir.iterdir() if p.is_dir() and p.name.startswith("iter_")])
    for idir in iter_dirs:
        verify = idir / "verify.json"
        if not verify.is_file():
            continue
        try:
            data = json.loads(verify.read_text(encoding="utf-8"))
        except Exception:
            continue
        try:
            it = int(idir.name.split("_")[1])
        except Exception:
            it = len(out) + 1
        out.append(
            {
                "iteration": it,
                "success": bool(data.get("success", False)),
                "notes": data.get("notes", "N/A"),
                "vuln_exit_code": data.get("vuln_exit_code"),
                "fixed_exit_code": data.get("fixed_exit_code"),
                "mutation_success": bool(data.get("mutation_applied", False)),
            }
        )
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Run OpenHands LLM-based fuzzing pipeline"
    )
    parser.add_argument(
        "--task-id",
        required=True,
        help="CVE task identifier (e.g., CVE-2024-57970_libarchive)",
    )
    parser.add_argument(
        "--level",
        default="L3",
        choices=["L0", "L1", "L2", "L3"],
        help="Information level for the LLM (default: L3)",
    )
    parser.add_argument(
        "--max-iters",
        type=int,
        default=10,
        help="Maximum number of iterations (default: 10)",
    )
    parser.add_argument(
        "--service",
        default="target-vuln",
        help="Docker service to test (default: target-vuln)",
    )
    parser.add_argument(
        "--seed",
        type=str,
        default=None,
        help="Path to initial seed file (optional)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help=(
            "LLM model identifier (e.g., ollama/qwen2.5:7b, ollama/llama3.1:8b). "
            "Defaults to LLM_MODEL env var or vertex_ai/gemini-2.0-flash-001"
        ),
    )
    parser.add_argument(
        "--kill-running-containers-after-iter",
        action="store_true",
        help=(
            "Kill all running Docker containers after each iteration "
            "(equivalent to docker kill $(docker ps -q)). Disabled by default."
        ),
    )
    parser.add_argument(
        "--no-llm-summary",
        action="store_true",
        help="Disable LLM-generated markdown summaries and always use template reports.",
    )
    parser.add_argument(
        "--summary-llm-model",
        type=str,
        default=None,
        help=(
            "Optional model for iteration/run summaries (e.g., ollama/ministral-3:8b). "
            "If omitted, SUMMARY_LLM_MODEL env var is used."
        ),
    )
    parser.add_argument(
        "--summary-llm-timeout-sec",
        type=int,
        default=45,
        help="Timeout for each summary LLM call in seconds (default: 45).",
    )
    parser.add_argument(
        "--allow-llm-early-stop",
        action="store_true",
        help=(
            "Honor stop_early=true hints returned by ANALYZE and end runs early. "
            "Disabled by default to preserve full iteration coverage."
        ),
    )

    args = parser.parse_args()

    # Get repository root (assumes we're in agents/openhands_llm/)
    repo_root = Path(__file__).parent.parent.parent.resolve()

    # Resolve model for display
    effective_model = args.model or os.getenv("LLM_MODEL", "vertex_ai/gemini-2.0-flash-001")

    print(f"{'='*70}")
    print(f"OpenHands LLM-Based Fuzzing Pipeline")
    print(f"{'='*70}")
    print(f"Task ID:      {args.task_id}")
    print(f"Level:        {args.level}")
    print(f"Max Iters:    {args.max_iters}")
    print(f"Service:      {args.service}")
    print(f"Seed:         {args.seed or '(random)'}")
    print(f"Model:        {effective_model}")
    print(f"Kill Docker:  {args.kill_running_containers_after_iter}")
    print(f"Repo Root:    {repo_root}")
    print(f"{'='*70}\n")

    # Run the pipeline (Docker build/check happens inside pipeline)
    try:
        result = run_pipeline(
            repo_root=repo_root,
            task_id=args.task_id,
            level=args.level,
            max_iters=args.max_iters,
            seed_path=args.seed,
            service=args.service,
            model=args.model,
            kill_running_containers_after_iter=args.kill_running_containers_after_iter,
            summary_llm_enabled=not args.no_llm_summary,
            summary_llm_model=args.summary_llm_model,
            summary_llm_timeout_sec=args.summary_llm_timeout_sec,
            allow_llm_early_stop=args.allow_llm_early_stop,
        )

        print(f"\n{'='*70}")
        print(f"Pipeline Finished")
        print(f"{'='*70}")
        print(f"Success:      {result['success']}")
        print(f"Iterations:   {result['iteration']}")
        print(f"Run Dir:      {result.get('run_dir', 'N/A')}")
        
        if result['success']:
            print(f"\n🎉 SUCCESS! Crash detected in iteration {result['iteration']}")
            return 0
        else:
            print(f"\n❌ No crash found after {result['iteration']} iterations")
            return 1

    except KeyboardInterrupt:
        print("\n\n⚠️  Pipeline interrupted by user")
        latest = _latest_run_dir(repo_root, args.task_id, effective_model)
        if latest:
            verify_history = _load_verify_history_from_run(latest)
            # Important: on Ctrl+C we avoid extra outbound LLM calls, so the user
            # gets an immediate partial summary instead of waiting on network timeouts.
            partial = _render_partial_console_summary(
                task_id=args.task_id,
                level=args.level,
                model=effective_model,
                max_iters=args.max_iters,
                run_dir=latest,
                verify_history=verify_history,
            )
            print(partial)
        else:
            print("Pensando en resumen hasta ahora...")
            print("Aun no hay iteraciones suficientes para resumir.")
        return 130
    except Exception as e:
        print(f"\n\n❌ Pipeline failed with error:")
        print(f"   {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

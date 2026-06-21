"""Context builder for loading task information from levels."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
from .io_utils import read_text


def locate_tasks_dir(repo_root: Path) -> Path:
    """Locate the tasks directory."""
    tasks = repo_root / "tasks"
    if not tasks.exists():
        raise FileNotFoundError(f"Tasks directory not found: {tasks}")
    return tasks


def task_levels_dir(repo_root: Path, task_id: str) -> Path:
    """Get the levels directory for a specific task."""
    levels = locate_tasks_dir(repo_root) / task_id / "levels"
    if not levels.exists():
        raise FileNotFoundError(f"Levels directory not found: {levels}")
    return levels


def load_markdown_files(levels_dir: Path) -> List[Dict[str, str]]:
    """Load all markdown files from levels directory, sorted by name."""
    md_files = sorted(levels_dir.glob("*.md"))
    return [
        {"filename": f.name, "content": read_text(f)}
        for f in md_files
    ]


def load_task_context(repo_root: Path, task_id: str, level: str) -> Dict:
    """
    Load task context based on information level (L0, L1, L2, L3).
    
    Levels:
    - L0: Basic description (L0_*.md)
    - L1: + patch info (L1_*.md)
    - L2: + vulnerable file info (L2_*.md)
    - L3: + full context (L3_*.md + all remaining)
    """
    levels_dir = task_levels_dir(repo_root, task_id)
    all_files = load_markdown_files(levels_dir)
    
    # Map level to prefix patterns
    level_patterns = {
        "L0": ["L0_"],
        "L1": ["L0_", "L1_"],
        "L2": ["L0_", "L1_", "L2_"],
        "L3": []  # All files
    }
    
    if level not in level_patterns:
        raise ValueError(f"Invalid level: {level}. Must be L0, L1, L2, or L3")
    
    patterns = level_patterns[level]
    
    # L3 includes everything
    if level == "L3":
        selected = all_files
    else:
        # Filter by prefix
        selected = [
            f for f in all_files
            if any(f["filename"].startswith(p) for p in patterns)
        ]
    
    return {
        "task_id": task_id,
        "level": level,
        "sections": selected
    }

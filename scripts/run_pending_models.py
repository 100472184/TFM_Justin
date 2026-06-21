#!/usr/bin/env python3
"""Run pending CVE/model/level pipeline combinations safely.

Default mode is dry-run. Use --execute to make changes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import threading
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LEVEL_ITERS = {
    "L3": 15,
    "L2": 30,
    "L1": 45,
    "L0": 50,
}

# Active cloud model set (2026-05-11).
# NOTE:
# - Keep aliases stable and filesystem-safe (used as directory names under runs/).
# - Keep model tags aligned with what `https://ollama.com/api/tags` returns for
#   the current API key/account to avoid schedule-time hard failures.
MODEL_SPECS = {
    "gemini-3-flash-preview": "ollama/gemini-3-flash-preview",
    "deepseek-v4-pro": "ollama/deepseek-v4-pro",
    "ministral-3-8b": "ollama/ministral-3:8b",
    "qwen3-coder-next": "ollama/qwen3-coder-next",
    "gpt-oss-20b": "ollama/gpt-oss:20b",
    "glm-5.1": "ollama/glm-5.1",
}

# Execution priority for multi-model batches.
# Heavier models first so we can front-load likely stronger performers.
# Any alias added to MODEL_SPECS but not listed here is appended at the end.
MODEL_ORDER = [
    "gemini-3-flash-preview",
    "deepseek-v4-pro",
    "glm-5.1",
    "qwen3-coder-next",
    "gpt-oss-20b",
    "ministral-3-8b",
]

# Optional model-level scope controls.
# If a model alias is present here, only listed levels are scheduled.
# Any alias not present is allowed on all levels.
MODEL_LEVEL_ALLOWLIST: dict[str, set[str]] = {
    # New flagship baseline for full campaign sweep.
    "gemini-3-flash-preview": {"L3", "L2", "L1", "L0"},
    # Enable full-level parity (L3-L0) for campaign completeness.
    "deepseek-v4-pro": {"L3", "L2", "L1", "L0"},
}

LEVEL_ORDER = ["L3", "L2", "L1", "L0"]
RUN_DIR_RE = re.compile(r"^\s*Run Dir:\s*(.+?)\s*$")
STATE_FILE = ".run_pending_models_state.json"
DEFAULT_MAX_STAGE_FILE_MB = 90
LOCAL_ENV_FILENAME = ".env.local"
OLLAMA_EFFECTIVE_LLM_TIMEOUT_SEC = "180"
OLLAMA_EFFECTIVE_MAX_GENERATE_ATTEMPTS = "6"
OLLAMA_EFFECTIVE_GENERATE_TIMEOUT_SEC = "90"
OLLAMA_EFFECTIVE_GENERATE_MAX_TOKENS = "3200"
OLLAMA_EFFECTIVE_GENERATE_JSON_RETRIES = "2"
OLLAMA_EFFECTIVE_GENERATE_FORMAT_JSON = "1"
# IMPORTANT:
# gpt-oss rejects think="none" on Ollama OpenAI-compatible endpoint.
# Use "false" to disable thinking in a cross-model-safe way.
OLLAMA_EFFECTIVE_GENERATE_REASONING_EFFORT = "medium"
# gpt-oss on Ollama OpenAI-compatible endpoint is strict and expects effort
# levels for "think" control in practice (low/medium/high/max), not "none".
OLLAMA_GPT_OSS_EFFECTIVE_GENERATE_REASONING_EFFORT = "medium"
# Model-specific overrides for Ollama-compatible runs.
# Rationale:
# - Some preview/large models return malformed/truncated JSON more often in free-form mode.
# - Enabling format=json and raising reasoning effort improves mutation JSON reliability.
OLLAMA_MODEL_ENV_OVERRIDES: dict[str, dict[str, str]] = {
    "ollama/gemini-3-flash-preview": {
        "OLLAMA_GENERATE_FORMAT_JSON": "1",
        "OLLAMA_GENERATE_REASONING_EFFORT": "medium",
        # Avoid frequent JSON truncation at ~2200 tokens in GENERATE.
        "LLM_GENERATE_MAX_TOKENS": "3200",
    },
    "ollama/deepseek-v4-pro": {
        "OLLAMA_GENERATE_FORMAT_JSON": "1",
        "OLLAMA_GENERATE_REASONING_EFFORT": "medium",
        # Mirror Gemini stabilization for long JSON mutation payloads.
        "LLM_GENERATE_MAX_TOKENS": "3200",
    },
    # Remaining campaign models: keep GENERATE compact to reduce repeated
    # max-token empty responses/timeouts in long L0/L1 batches.
    "ollama/glm-5.1": {
        "OLLAMA_GENERATE_FORMAT_JSON": "1",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    "ollama/qwen3-coder-next": {
        "OLLAMA_GENERATE_FORMAT_JSON": "1",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    "ollama/ministral-3:8b": {
        "OLLAMA_GENERATE_FORMAT_JSON": "1",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # gpt-oss keeps medium effort for compatibility on Ollama endpoint.
    "ollama/gpt-oss:20b": {
        "OLLAMA_GENERATE_FORMAT_JSON": "1",
        "OLLAMA_GENERATE_REASONING_EFFORT": "medium",
        "LLM_GENERATE_MAX_TOKENS": "1800",
        "LLM_GENERATE_TIMEOUT": "120",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
}

# CVE-wide targeted env overrides (apply to all Ollama models for that task).
# Use this map for task-level stabilization where model-specific tuning is not
# required.
OLLAMA_CVE_ENV_OVERRIDES: dict[str, dict[str, str]] = {
    # cmark-gfm: avoid repeated max-token (3200) empty payload loops in
    # GENERATE; keep responses compact and predictable.
    "CVE-2022-24724_cmark-gfm": {
        "LLM_GENERATE_MAX_TOKENS": "2200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "low",
        "LLM_GENERATE_HISTORY_WINDOW": "2",
    },
    # libxml2 legacy task: reduce GENERATE drift and long strategy replies.
    "CVE-2024-25062_libxml2": {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        # Keep retries bounded for this historically unstable track.
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "OLLAMA_GENERATE_REASONING_EFFORT": "low",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libarchive (ORACLE_BROKEN and leakage pilot):
    # keep JSON compact and disable GENERATE history carryover so each
    # iteration is independent (stricter anti-leakage posture).
    "CVE-2024-57970_libarchive": {
        "LLM_GENERATE_MAX_TOKENS": "2400",
        "LLM_GENERATE_TIMEOUT": "150",
        "OLLAMA_GENERATE_REASONING_EFFORT": "low",
        "LLM_GENERATE_HISTORY_WINDOW": "0",
        "LLM_ANALYZE_MAX_TOKENS": "700",
        # Anti-leakage strict mode in pipeline:
        # disable cross-iteration prompt history/feedback add-ons.
        "LLM_STRICT_LEVEL_ISOLATION": "1",
    },
    # libming: stabilize GENERATE for SWF-focused mutation plans and reduce
    # long/empty responses in low-context levels.
    "CVE-2016-9827_libming": {
        "LLM_GENERATE_MAX_TOKENS": "2400",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "low",
        "LLM_GENERATE_HISTORY_WINDOW": "2",
    },
}

# Additional guardrails that are applied only when a combo is executed against
# the standard `target-vuln` service (not direct harnesses).
SERVICE_SENSITIVE_ENV_OVERRIDES_BY_CVE: dict[str, dict[str, str]] = {
    # CVE-2023-29469:
    # - L3 intentionally uses target-vuln-direct (white-box direct harness).
    # - L2/L1/L0 use target-vuln and are sensitive to long/thought-heavy
    #   generation loops; keep JSON compact and retries bounded.
    "CVE-2023-29469_libxml2": {
        "LLM_GENERATE_MAX_TOKENS": "1200",
        "LLM_GENERATE_TIMEOUT": "120",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
}

# CVE+model targeted env overrides.
# Use this map only for hot spots where a task still needs per-model
# specialization after generic CVE controls.
OLLAMA_CVE_MODEL_ENV_OVERRIDES: dict[tuple[str, str], dict[str, str]] = {
    # json-c (CVE-2021-32292) leakage re-test:
    # keep GENERATE compact for long L1/L0 campaigns and avoid 3200-token
    # empty/timeout loops seen in prior batches.
    ("CVE-2021-32292_jsonc", "ollama/gemini-3-flash-preview"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2021-32292_jsonc", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libxml2 (CVE-2024-25062) + gemini-3-flash-preview:
    # frequent malformed/truncated JSON payloads in GENERATE at token ceiling.
    # Force compact direct output and disable reasoning traces.
    ("CVE-2024-25062_libxml2", "ollama/gemini-3-flash-preview"): {
        "LLM_GENERATE_MAX_TOKENS": "1400",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libxml2 (CVE-2024-25062) + deepseek-v4-pro:
    # repeated empty-response loops exactly at max token budget.
    ("CVE-2024-25062_libxml2", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "1200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libxml2 (CVE-2024-25062) + glm-5.1:
    # recurring 1400-token empty loops in GENERATE. Force compact direct output.
    ("CVE-2024-25062_libxml2", "ollama/glm-5.1"): {
        "LLM_GENERATE_MAX_TOKENS": "1200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libxml2 (CVE-2024-25062) + qwen3-coder-next:
    # same empty-at-cap pattern; keep concise JSON-only outputs.
    ("CVE-2024-25062_libxml2", "ollama/qwen3-coder-next"): {
        "LLM_GENERATE_MAX_TOKENS": "1200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libxml2 (CVE-2024-25062) + ministral-3:8b:
    # compact mode to minimize truncation and malformed JSON.
    ("CVE-2024-25062_libxml2", "ollama/ministral-3:8b"): {
        "LLM_GENERATE_MAX_TOKENS": "1000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libxml2 (CVE-2024-25062) + gpt-oss:20b:
    # keep gpt-oss compatible reasoning level while reducing long outputs.
    ("CVE-2024-25062_libxml2", "ollama/gpt-oss:20b"): {
        "LLM_GENERATE_MAX_TOKENS": "1400",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "low",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libxml2 (CVE-2023-29469): campaign remainder control profile.
    # This CVE has shown repeated max-token empty loops on L3/L2 for some
    # models; force compact outputs to avoid burning budget.
    ("CVE-2023-29469_libxml2", "ollama/gemini-3-flash-preview"): {
        "LLM_GENERATE_MAX_TOKENS": "1400",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2023-29469_libxml2", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "1200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2023-29469_libxml2", "ollama/glm-5.1"): {
        "LLM_GENERATE_MAX_TOKENS": "1200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2023-29469_libxml2", "ollama/qwen3-coder-next"): {
        "LLM_GENERATE_MAX_TOKENS": "1200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2023-29469_libxml2", "ollama/ministral-3:8b"): {
        "LLM_GENERATE_MAX_TOKENS": "1000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # gpt-oss cannot use reasoning=none on this endpoint.
    ("CVE-2023-29469_libxml2", "ollama/gpt-oss:20b"): {
        "LLM_GENERATE_MAX_TOKENS": "1400",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "low",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # cmark-gfm + deepseek-v4-pro is especially prone to 3200-token empty
    # responses/timeouts. Keep thinking disabled (root cause mitigation),
    # but allow a larger token budget and multi-iteration history so L1 can
    # escalate from exploratory payloads to UINT16_MAX-crossing shapes.
    ("CVE-2022-24724_cmark-gfm", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "3200",
        "LLM_GENERATE_TIMEOUT": "150",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_HISTORY_WINDOW": "3",
    },
    # cmark-gfm + glm-5.1 (L0 hotspot): repeated empty responses exactly at
    # max token budget with long retry loops. Force concise direct output.
    ("CVE-2022-24724_cmark-gfm", "ollama/glm-5.1"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # Exiv2 + deepseek can stall in long/thought-heavy GENERATE replies:
    # repeated 3200-token truncation/empty payload loops and 90s timeouts.
    # Keep JSON mode but reduce response verbosity and allow more wall-clock.
    ("CVE-2025-26623_exiv2", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "2000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        # Reduce prompt amplification loops after many failed iterations.
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # jq + deepseek-v4-pro (L0 pending hotspot): repeated max-token empty
    # responses / timeout loops and malformed overlong filters in GENERATE.
    ("CVE-2025-49014_jq", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "2000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libming + deepseek-v4-pro: observed repeated 3200-token empty responses
    # and occasional timeout loops in GENERATE. Disable thinking and reduce
    # budget to force concise JSON mutation output.
    ("CVE-2016-9827_libming", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "2000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # zstd + deepseek-v4-pro (L0 pending hotspot): repeated max-token empty
    # payloads and timeout loops in GENERATE. Force compact, direct output.
    ("CVE-2022-4899_zstd", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "1200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # gnutar + deepseek-v4-pro (L0 pending hotspot): repeated 3200-token
    # empty responses and timeout loops in GENERATE.
    ("CVE-2023-39804_gnutar", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "2200",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # libarchive + deepseek-v4-pro (L0 hotspot): repeated max-token empty
    # responses and timeout loops in GENERATE; keep output compact/direct.
    ("CVE-2024-57970_libarchive", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "2000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_GENERATE_HISTORY_WINDOW": "0",
    },
    # Remaining L0 campaign sweep (2026-05-17): apply strict compact-profile
    # per pending pair to avoid repeated max-token empty loops/timeouts.
    ("CVE-2022-4899_zstd", "ollama/glm-5.1"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2023-39804_gnutar", "ollama/glm-5.1"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    # fluentbit + deepseek-v4-pro (L0/L1 hotspot): repeated max-token empty
    # responses plus connection timeouts in GENERATE.
    ("CVE-2024-4323_fluentbit", "ollama/deepseek-v4-pro"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2024-4323_fluentbit", "ollama/glm-5.1"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2024-57970_libarchive", "ollama/glm-5.1"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "0",
    },
    ("CVE-2025-26623_exiv2", "ollama/glm-5.1"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2024-4323_fluentbit", "ollama/qwen3-coder-next"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2024-57970_libarchive", "ollama/qwen3-coder-next"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "0",
    },
    ("CVE-2024-4323_fluentbit", "ollama/gpt-oss:20b"): {
        "LLM_GENERATE_MAX_TOKENS": "1800",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "medium",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
    ("CVE-2024-57970_libarchive", "ollama/gpt-oss:20b"): {
        "LLM_GENERATE_MAX_TOKENS": "1800",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "medium",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "0",
    },
    ("CVE-2024-4323_fluentbit", "ollama/ministral-3:8b"): {
        "LLM_GENERATE_MAX_TOKENS": "1600",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
    },
}

# CVE+model+level targeted env overrides.
# Use this only for level-specific instability hotspots.
OLLAMA_CVE_MODEL_LEVEL_ENV_OVERRIDES: dict[tuple[str, str, str], dict[str, str]] = {
    # json-c (CVE-2021-32292) + gemini L2:
    # keep GENERATE tighter on this level due to repeated malformed JSON,
    # unsupported ops, and no-mutation payloads.
    ("CVE-2021-32292_jsonc", "ollama/gemini-3-flash-preview", "L2"): {
        "LLM_GENERATE_MAX_TOKENS": "200",
        "LLM_GENERATE_TIMEOUT": "90",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "4",
        "LLM_GENERATE_JSON_RETRIES": "2",
        "LLM_GENERATE_HISTORY_WINDOW": "0",
        "LLM_ANALYZE_MAX_TOKENS": "700",
    },
    # CVE-2024-25062/libxml2 L3 completion pass:
    # only the three absent L3 cells are force-scheduled. Keep GENERATE compact
    # to avoid the long/malformed JSON loops observed in this task family.
    ("CVE-2024-25062_libxml2", "ollama/gemini-3-flash-preview", "L3"): {
        "LLM_GENERATE_MAX_TOKENS": "1000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
        "LLM_ANALYZE_MAX_TOKENS": "900",
    },
    ("CVE-2024-25062_libxml2", "ollama/deepseek-v4-pro", "L3"): {
        "LLM_GENERATE_MAX_TOKENS": "1000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
        "LLM_ANALYZE_MAX_TOKENS": "900",
    },
    ("CVE-2024-25062_libxml2", "ollama/glm-5.1", "L3"): {
        "LLM_GENERATE_MAX_TOKENS": "1000",
        "LLM_GENERATE_TIMEOUT": "120",
        "OLLAMA_GENERATE_REASONING_EFFORT": "none",
        "LLM_MAX_GENERATE_ATTEMPTS": "3",
        "LLM_GENERATE_JSON_RETRIES": "1",
        "LLM_GENERATE_HISTORY_WINDOW": "1",
        "LLM_ANALYZE_MAX_TOKENS": "900",
    },
}

# Keep seed discovery aligned with the pipeline, while allowing task-local
# preference boosts (e.g., text-argument tasks).
SEED_CANDIDATES_DEFAULT = [
    # base.*
    "base.yaml", "base.yml", "base.json", "base.xml",
    "base.md", "base.txt", "base.jq",
    "base.jpg", "base.webp", "base.tiff", "base.swf", "base.tar",
    "base.bin",
    # seed.*
    "seed.yaml", "seed.yml", "seed.json", "seed.xml",
    "seed.md", "seed.txt", "seed.jq",
    "seed.jpg", "seed.webp", "seed.tiff", "seed.swf", "seed.tar",
    "seed.bin",
    # task-specific known name
    "seed_pipeline.xml",
]

SEED_CANDIDATES_TEXT_FIRST = [
    "base.txt", "base.jq", "base.md", "seed.txt", "seed.jq", "seed.md",
    *SEED_CANDIDATES_DEFAULT,
]
SEED_GENERATOR_GLOBS = ["gen_*.py", "generate_*.py", "make_*.py"]
SEED_GENERATOR_TIMEOUT_SEC = 60
LOCKED_BASE_SEEDS: dict[str, dict[str, str]] = {
    # Canonical seed recovered from historical Gemini runs for reproducibility parity.
    "CVE-2016-9827_libming": {
        "filename": "base.swf",
        "sha256": "74d50d87f446dcd17922ae39f454c5e40ba8c2815f6da43d2d0a07f110e51fd0",
    },
    # Open-seed lock for json-c boundary reproduction parity when using
    # the open-seed track.
    "CVE-2021-32292_jsonc": {
        "filename": "base.json",
        "sha256": "93e4c91583682694b653e73ad004f627e55acb30167219e09d45e23425e5e77c",
    },
}

# Task-specific seed mode matrix (CVE/methodology controls).
# CVE-2021-32292_jsonc:
# - L0/L1: open-seed track (base.json => {"a":" )
# - L2/L3: normal/closed-seed track (seed.json => {"a":""})
SEED_OVERRIDE_BY_CVE_LEVEL: dict[tuple[str, str], dict[str, str]] = {
    ("CVE-2021-32292_jsonc", "L0"): {
        "filename": "base.json",
        "sha256": "93e4c91583682694b653e73ad004f627e55acb30167219e09d45e23425e5e77c",
    },
    ("CVE-2021-32292_jsonc", "L1"): {
        "filename": "base.json",
        "sha256": "93e4c91583682694b653e73ad004f627e55acb30167219e09d45e23425e5e77c",
    },
    ("CVE-2021-32292_jsonc", "L2"): {
        "filename": "seed.json",
        "sha256": "258555fe010df3da34b3920945d0fbc59cebbcff1878bfc2e9206f0f495d81b9",
    },
    ("CVE-2021-32292_jsonc", "L3"): {
        "filename": "seed.json",
        "sha256": "258555fe010df3da34b3920945d0fbc59cebbcff1878bfc2e9206f0f495d81b9",
    },
}

# Legacy task-layout allowlist.
# These CVEs are schedulable even without task.yml when they expose the minimal
# pipeline bundle (compose + levels + seeds), typically from early campaigns.
LEGACY_TASK_LAYOUT_ALLOWLIST: set[str] = {
    "CVE-2024-4323_fluentbit",
    "CVE-2024-25062_libxml2",
}

# CVE-specific seed profiles (multi-seed-track scheduling).
# For CVE-2024-4323 we preserve historical methodology split:
# - seed_crash: legacy crash-oriented seed track (L0-L3)
# - seed_new_op: neutral seed with newer mutation op behavior (L0-L3)
CVE_SEED_PROFILES: dict[str, dict[str, dict[str, Any]]] = {
    "CVE-2024-4323_fluentbit": {
        "seed_new_op": {
            "dir": "seed (new op)",
            "filename": "seed.json",
            # Accept both canonical variants observed across environments
            # (line-ending/formatting differences with same semantic seed).
            "sha256": (
                "52ea254d9ecdf8d79f95bbb8cf3625ab977bd7906a5727e9103f529ac75ef3a8,"
                "3ca81ed9510be3998806498b49abad313e60ef67b1f4a54f0543b842c1ec8ce3"
            ),
            "levels": {"L0", "L1", "L2", "L3"},
            "level_max_iters": {
                "L1": 45,
                "L2": 35,
                "L3": 20,
            },
        },
        "seed_crash": {
            "dir": "seed_crash",
            "filename": "seed_crash.json",
            "sha256": (
                "844a55ae67b34b1245b5ff298871b87568acbd5d17841d2faf463459e230b449,"
                "5766e8d8545f5ce2fb49d37e21915e232a936d49a0c0190f13f3c07a97c5330c"
            ),
            "levels": {"L0", "L1", "L2", "L3"},
            "level_max_iters": {
                "L0": 60,
                "L1": 30,
                "L2": 20,
                "L3": 10,
            },
        },
    },
}

# Optional run-dir label suffixes for dedicated re-test campaigns.
# NOTE: this is intentionally scoped to fluentbit leakage validation.
RUN_NAME_SUFFIX_BY_CVE: dict[str, str] = {
    "CVE-2024-4323_fluentbit": "_testing_leakage",
    "CVE-2021-32292_jsonc": "_testing_leakage",
}

# Baseline hardcodeada a partir del estado analizado previamente.
# Se usa para no depender de tener runs sincronizado en Kali.
HARDCODED_EXISTING_COMBOS: set[tuple[str, str, str]] = {
    # New cloud campaign (2026-05-11+), validated runs.
    # Marked as completed/valid and should not be rescheduled automatically
    # even if runs/ is not fully synchronized on the executing host.
    ("CVE-2014-2525_libyaml", "glm-5.1", "L3"),
    ("CVE-2014-2525_libyaml", "qwen3-coder-next", "L3"),
    ("CVE-2014-2525_libyaml", "gpt-oss-20b", "L3"),
    ("CVE-2014-2525_libyaml", "ministral-3-8b", "L3"),
    ("CVE-2016-9827_libming", "glm-5.1", "L3"),
    ("CVE-2016-9827_libming", "qwen3-coder-next", "L3"),
    ("CVE-2016-9827_libming", "gpt-oss-20b", "L3"),
    ("CVE-2016-9827_libming", "ministral-3-8b", "L3"),
    ("CVE-2021-32292_jsonc", "glm-5.1", "L3"),
    ("CVE-2021-32292_jsonc", "qwen3-coder-next", "L3"),
    ("CVE-2021-32292_jsonc", "gpt-oss-20b", "L3"),
    ("CVE-2021-32292_jsonc", "ministral-3-8b", "L3"),
    # Validated L3 completions (2026-05-14): gemini-3-flash-preview.
    ("CVE-2014-2525_libyaml", "gemini-3-flash-preview", "L3"),
    ("CVE-2016-9827_libming", "gemini-3-flash-preview", "L3"),
    ("CVE-2021-32292_jsonc", "gemini-3-flash-preview", "L3"),
    ("CVE-2022-24724_cmark-gfm", "gemini-3-flash-preview", "L3"),
    ("CVE-2022-4899_zstd", "gemini-3-flash-preview", "L3"),
    ("CVE-2023-39804_gnutar", "gemini-3-flash-preview", "L3"),
    ("CVE-2025-26623_exiv2", "gemini-3-flash-preview", "L3"),
    ("CVE-2025-49014_jq", "gemini-3-flash-preview", "L3"),
    # Validated L3 completions (2026-05-14): deepseek-v4-pro.
    ("CVE-2014-2525_libyaml", "deepseek-v4-pro", "L3"),
    ("CVE-2016-9827_libming", "deepseek-v4-pro", "L3"),
    ("CVE-2021-32292_jsonc", "deepseek-v4-pro", "L3"),
    # Validated L3 completion (2026-05-15 upload/audit): deepseek-v4-pro.
    ("CVE-2025-49014_jq", "deepseek-v4-pro", "L3"),
    ("CVE-2025-26623_exiv2", "deepseek-v4-pro", "L3"),
    # Validated L3 completions (2026-05-15 interrupted batch, pass 1).
    ("CVE-2022-4899_zstd", "deepseek-v4-pro", "L3"),
    ("CVE-2023-39804_gnutar", "deepseek-v4-pro", "L3"),
    ("CVE-2024-57970_libarchive", "gemini-3-flash-preview", "L3"),
    ("CVE-2024-57970_libarchive", "deepseek-v4-pro", "L3"),
    # CVE-2024-4323 has two seed profiles (seed_new_op / seed_crash).
    # Hardcoding by (CVE, model, level) intentionally marks both as completed.
    ("CVE-2024-4323_fluentbit", "gemini-3-flash-preview", "L3"),
    ("CVE-2024-4323_fluentbit", "deepseek-v4-pro", "L3"),
    ("CVE-2024-4323_fluentbit", "glm-5.1", "L3"),
    ("CVE-2024-4323_fluentbit", "qwen3-coder-next", "L3"),
    ("CVE-2024-4323_fluentbit", "gpt-oss-20b", "L3"),
    ("CVE-2024-4323_fluentbit", "ministral-3-8b", "L3"),
    ("CVE-2022-24724_cmark-gfm", "glm-5.1", "L3"),
    ("CVE-2022-24724_cmark-gfm", "qwen3-coder-next", "L3"),
    ("CVE-2022-24724_cmark-gfm", "gpt-oss-20b", "L3"),
    ("CVE-2022-24724_cmark-gfm", "ministral-3-8b", "L3"),
    ("CVE-2022-4899_zstd", "glm-5.1", "L3"),
    ("CVE-2022-4899_zstd", "qwen3-coder-next", "L3"),
    ("CVE-2022-4899_zstd", "gpt-oss-20b", "L3"),
    ("CVE-2022-4899_zstd", "ministral-3-8b", "L3"),
    ("CVE-2023-29469_libxml2", "qwen3-coder-next", "L3"),
    ("CVE-2023-29469_libxml2", "gpt-oss-20b", "L3"),
    ("CVE-2023-29469_libxml2", "ministral-3-8b", "L3"),
    ("CVE-2023-29469_libxml2", "gemini-3-flash-preview", "L3"),
    ("CVE-2023-39804_gnutar", "glm-5.1", "L3"),
    ("CVE-2023-39804_gnutar", "qwen3-coder-next", "L3"),
    ("CVE-2023-39804_gnutar", "gpt-oss-20b", "L3"),
    ("CVE-2023-39804_gnutar", "ministral-3-8b", "L3"),
    ("CVE-2025-26623_exiv2", "glm-5.1", "L3"),
    ("CVE-2025-26623_exiv2", "qwen3-coder-next", "L3"),
    ("CVE-2025-26623_exiv2", "gpt-oss-20b", "L3"),
    ("CVE-2025-26623_exiv2", "ministral-3-8b", "L3"),
    ("CVE-2025-49014_jq", "glm-5.1", "L3"),
    ("CVE-2025-49014_jq", "qwen3-coder-next", "L3"),
    ("CVE-2025-49014_jq", "gpt-oss-20b", "L3"),
    ("CVE-2025-49014_jq", "ministral-3-8b", "L3"),
    # New validated L2 completions (2026-05-12 batch)
    # Additional validated L2 completions (2026-05-15 upload/audit):
    ("CVE-2014-2525_libyaml", "gemini-3-flash-preview", "L2"),
    ("CVE-2016-9827_libming", "gemini-3-flash-preview", "L2"),
    ("CVE-2021-32292_jsonc", "gemini-3-flash-preview", "L2"),
    ("CVE-2022-24724_cmark-gfm", "gemini-3-flash-preview", "L2"),
    ("CVE-2022-4899_zstd", "gemini-3-flash-preview", "L2"),
    ("CVE-2023-39804_gnutar", "gemini-3-flash-preview", "L2"),
    ("CVE-2024-4323_fluentbit", "gemini-3-flash-preview", "L2"),
    ("CVE-2025-26623_exiv2", "gemini-3-flash-preview", "L2"),
    ("CVE-2025-49014_jq", "gemini-3-flash-preview", "L2"),
    ("CVE-2014-2525_libyaml", "deepseek-v4-pro", "L2"),
    ("CVE-2016-9827_libming", "deepseek-v4-pro", "L2"),
    ("CVE-2021-32292_jsonc", "deepseek-v4-pro", "L2"),
    ("CVE-2022-24724_cmark-gfm", "deepseek-v4-pro", "L2"),
    ("CVE-2024-57970_libarchive", "gemini-3-flash-preview", "L2"),
    ("CVE-2024-57970_libarchive", "deepseek-v4-pro", "L2"),
    ("CVE-2014-2525_libyaml", "glm-5.1", "L2"),
    ("CVE-2016-9827_libming", "glm-5.1", "L2"),
    ("CVE-2021-32292_jsonc", "glm-5.1", "L2"),
    ("CVE-2022-24724_cmark-gfm", "glm-5.1", "L2"),
    ("CVE-2022-4899_zstd", "glm-5.1", "L2"),
    ("CVE-2023-39804_gnutar", "glm-5.1", "L2"),
    ("CVE-2025-26623_exiv2", "glm-5.1", "L2"),
    ("CVE-2025-49014_jq", "glm-5.1", "L2"),
    ("CVE-2014-2525_libyaml", "qwen3-coder-next", "L2"),
    ("CVE-2016-9827_libming", "qwen3-coder-next", "L2"),
    ("CVE-2021-32292_jsonc", "qwen3-coder-next", "L2"),
    # New validated L2 completions (2026-05-12 interrupted batch, pass 2)
    ("CVE-2022-24724_cmark-gfm", "qwen3-coder-next", "L2"),
    ("CVE-2022-4899_zstd", "qwen3-coder-next", "L2"),
    ("CVE-2023-39804_gnutar", "qwen3-coder-next", "L2"),
    ("CVE-2025-26623_exiv2", "qwen3-coder-next", "L2"),
    ("CVE-2025-49014_jq", "qwen3-coder-next", "L2"),
    ("CVE-2014-2525_libyaml", "gpt-oss-20b", "L2"),
    ("CVE-2016-9827_libming", "gpt-oss-20b", "L2"),
    ("CVE-2021-32292_jsonc", "gpt-oss-20b", "L2"),
    ("CVE-2022-24724_cmark-gfm", "gpt-oss-20b", "L2"),
    ("CVE-2022-4899_zstd", "gpt-oss-20b", "L2"),
    ("CVE-2023-29469_libxml2", "gpt-oss-20b", "L2"),
    ("CVE-2023-39804_gnutar", "gpt-oss-20b", "L2"),
    ("CVE-2025-26623_exiv2", "gpt-oss-20b", "L2"),
    ("CVE-2025-49014_jq", "gpt-oss-20b", "L2"),
    ("CVE-2016-9827_libming", "ministral-3-8b", "L2"),
    # New validated L2 completions (2026-05-12 interrupted batch, pass 3)
    # These canonical runs were completed/staged in Kali and are treated as valid
    # campaign artifacts (success=true or full-budget completion).
    ("CVE-2021-32292_jsonc", "ministral-3-8b", "L2"),
    ("CVE-2022-24724_cmark-gfm", "ministral-3-8b", "L2"),
    ("CVE-2022-4899_zstd", "ministral-3-8b", "L2"),
    ("CVE-2023-29469_libxml2", "ministral-3-8b", "L2"),
    ("CVE-2023-39804_gnutar", "ministral-3-8b", "L2"),
    ("CVE-2025-26623_exiv2", "ministral-3-8b", "L2"),
    ("CVE-2025-49014_jq", "ministral-3-8b", "L2"),
    # Validated completion (2026-05-12): deterministic success at iter_001
    # with open-seed methodology for json-c (L1 track).
    ("CVE-2021-32292_jsonc", "glm-5.1", "L1"),
    # Validated L1 completions (2026-05-13): completed/staged in automatic batch.
    ("CVE-2022-24724_cmark-gfm", "glm-5.1", "L1"),
    ("CVE-2022-4899_zstd", "glm-5.1", "L1"),
    ("CVE-2023-39804_gnutar", "glm-5.1", "L1"),
    ("CVE-2025-26623_exiv2", "glm-5.1", "L1"),
    ("CVE-2025-49014_jq", "glm-5.1", "L1"),
    # Validated L1 completions (2026-05-13): qwen3-coder-next.
    ("CVE-2014-2525_libyaml", "qwen3-coder-next", "L1"),
    ("CVE-2016-9827_libming", "qwen3-coder-next", "L1"),
    ("CVE-2021-32292_jsonc", "qwen3-coder-next", "L1"),
    ("CVE-2022-24724_cmark-gfm", "qwen3-coder-next", "L1"),
    ("CVE-2022-4899_zstd", "qwen3-coder-next", "L1"),
    ("CVE-2025-26623_exiv2", "qwen3-coder-next", "L1"),
    ("CVE-2025-49014_jq", "qwen3-coder-next", "L1"),
    # Validated L1 completions (2026-05-13): gpt-oss-20b.
    ("CVE-2014-2525_libyaml", "gpt-oss-20b", "L1"),
    ("CVE-2016-9827_libming", "gpt-oss-20b", "L1"),
    ("CVE-2021-32292_jsonc", "gpt-oss-20b", "L1"),
    ("CVE-2022-24724_cmark-gfm", "gpt-oss-20b", "L1"),
    ("CVE-2022-4899_zstd", "gpt-oss-20b", "L1"),
    ("CVE-2023-39804_gnutar", "gpt-oss-20b", "L1"),
    ("CVE-2025-26623_exiv2", "gpt-oss-20b", "L1"),
    ("CVE-2025-49014_jq", "gpt-oss-20b", "L1"),
    # Validated L1 completions (2026-05-13): ministral-3-8b.
    ("CVE-2014-2525_libyaml", "ministral-3-8b", "L1"),
    ("CVE-2016-9827_libming", "ministral-3-8b", "L1"),
    ("CVE-2021-32292_jsonc", "ministral-3-8b", "L1"),
    ("CVE-2022-24724_cmark-gfm", "ministral-3-8b", "L1"),
    ("CVE-2022-4899_zstd", "ministral-3-8b", "L1"),
    ("CVE-2023-39804_gnutar", "ministral-3-8b", "L1"),
    ("CVE-2025-26623_exiv2", "ministral-3-8b", "L1"),
    ("CVE-2025-49014_jq", "ministral-3-8b", "L1"),
    # Validated completion (2026-05-15): gemini-3-flash-preview L1.
    ("CVE-2022-4899_zstd", "gemini-3-flash-preview", "L1"),
    ("CVE-2024-57970_libarchive", "gemini-3-flash-preview", "L1"),
    ("CVE-2014-2525_libyaml", "deepseek-v4-pro", "L1"),
    ("CVE-2016-9827_libming", "deepseek-v4-pro", "L1"),
    ("CVE-2021-32292_jsonc", "deepseek-v4-pro", "L1"),
    ("CVE-2022-4899_zstd", "deepseek-v4-pro", "L1"),
    ("CVE-2023-39804_gnutar", "deepseek-v4-pro", "L1"),
    ("CVE-2024-4323_fluentbit", "deepseek-v4-pro", "L1"),
    ("CVE-2024-57970_libarchive", "deepseek-v4-pro", "L1"),
    ("CVE-2025-26623_exiv2", "deepseek-v4-pro", "L1"),
    ("CVE-2025-49014_jq", "deepseek-v4-pro", "L1"),
    ("CVE-2024-57970_libarchive", "qwen3-coder-next", "L1"),
    ("CVE-2023-39804_gnutar", "qwen3-coder-next", "L1"),
    ("CVE-2024-57970_libarchive", "gpt-oss-20b", "L1"),
    ("CVE-2024-57970_libarchive", "ministral-3-8b", "L1"),
    ("CVE-2022-24724_cmark-gfm", "deepseek-v4-pro", "L1"),
    # Validated L0 completions (2026-05-14): staged runs verified by summary.json
    # validity policy (full-budget failures or success-early termination).
    ("CVE-2014-2525_libyaml", "glm-5.1", "L0"),
    ("CVE-2016-9827_libming", "glm-5.1", "L0"),
    ("CVE-2021-32292_jsonc", "glm-5.1", "L0"),
    ("CVE-2022-24724_cmark-gfm", "glm-5.1", "L0"),
    ("CVE-2025-49014_jq", "glm-5.1", "L0"),
    ("CVE-2014-2525_libyaml", "deepseek-v4-pro", "L0"),
    ("CVE-2016-9827_libming", "deepseek-v4-pro", "L0"),
    ("CVE-2021-32292_jsonc", "deepseek-v4-pro", "L0"),
    ("CVE-2022-24724_cmark-gfm", "deepseek-v4-pro", "L0"),
    ("CVE-2025-49014_jq", "deepseek-v4-pro", "L0"),
    ("CVE-2023-39804_gnutar", "deepseek-v4-pro", "L0"),
    ("CVE-2025-26623_exiv2", "deepseek-v4-pro", "L0"),
    # CVE-2024-4323 has two seed profiles; this key marks both L0 runs done.
    ("CVE-2024-4323_fluentbit", "deepseek-v4-pro", "L0"),
    # Validated completion (2026-05-16): avoid re-scheduling on hosts with
    # partial local runs trees.
    ("CVE-2024-57970_libarchive", "deepseek-v4-pro", "L0"),
    ("CVE-2024-57970_libarchive", "gemini-3-flash-preview", "L0"),
    ("CVE-2014-2525_libyaml", "qwen3-coder-next", "L0"),
    ("CVE-2016-9827_libming", "qwen3-coder-next", "L0"),
    ("CVE-2021-32292_jsonc", "qwen3-coder-next", "L0"),
    ("CVE-2022-24724_cmark-gfm", "qwen3-coder-next", "L0"),
    ("CVE-2022-4899_zstd", "qwen3-coder-next", "L0"),
    ("CVE-2023-39804_gnutar", "qwen3-coder-next", "L0"),
    ("CVE-2025-26623_exiv2", "qwen3-coder-next", "L0"),
    ("CVE-2025-49014_jq", "qwen3-coder-next", "L0"),
    ("CVE-2014-2525_libyaml", "gpt-oss-20b", "L0"),
    ("CVE-2016-9827_libming", "gpt-oss-20b", "L0"),
    ("CVE-2021-32292_jsonc", "gpt-oss-20b", "L0"),
    # Validated completions (2026-05-15): staged in interrupted batch, non-anomalous.
    ("CVE-2025-26623_exiv2", "gemini-3-flash-preview", "L0"),
    ("CVE-2024-4323_fluentbit", "glm-5.1", "L0"),
    ("CVE-2024-4323_fluentbit", "qwen3-coder-next", "L0"),
    ("CVE-2024-4323_fluentbit", "gpt-oss-20b", "L0"),
    ("CVE-2024-4323_fluentbit", "ministral-3-8b", "L0"),
    ("CVE-2022-4899_zstd", "glm-5.1", "L0"),
    ("CVE-2023-39804_gnutar", "glm-5.1", "L0"),
    ("CVE-2024-57970_libarchive", "glm-5.1", "L0"),
    ("CVE-2025-26623_exiv2", "glm-5.1", "L0"),
    ("CVE-2024-57970_libarchive", "qwen3-coder-next", "L0"),
    ("CVE-2024-57970_libarchive", "gpt-oss-20b", "L0"),
    ("CVE-2024-57970_libarchive", "ministral-3-8b", "L0"),
    # Validated upload/audit (2026-05-15): 38 completadas staged, 0 anomalas.
    # Add missing unique keys so they are not rescheduled automatically.
    ("CVE-2022-4899_zstd", "deepseek-v4-pro", "L2"),
    ("CVE-2023-39804_gnutar", "deepseek-v4-pro", "L2"),
    ("CVE-2024-4323_fluentbit", "deepseek-v4-pro", "L2"),
    ("CVE-2025-26623_exiv2", "deepseek-v4-pro", "L2"),
    ("CVE-2025-49014_jq", "deepseek-v4-pro", "L2"),
    ("CVE-2024-4323_fluentbit", "glm-5.1", "L2"),
    ("CVE-2024-4323_fluentbit", "qwen3-coder-next", "L2"),
    ("CVE-2024-4323_fluentbit", "gpt-oss-20b", "L2"),
    ("CVE-2024-4323_fluentbit", "ministral-3-8b", "L2"),
    ("CVE-2014-2525_libyaml", "gemini-3-flash-preview", "L1"),
    ("CVE-2016-9827_libming", "gemini-3-flash-preview", "L1"),
    ("CVE-2021-32292_jsonc", "gemini-3-flash-preview", "L1"),
    ("CVE-2022-24724_cmark-gfm", "gemini-3-flash-preview", "L1"),
    ("CVE-2023-39804_gnutar", "gemini-3-flash-preview", "L1"),
    ("CVE-2024-4323_fluentbit", "gemini-3-flash-preview", "L1"),
    ("CVE-2025-26623_exiv2", "gemini-3-flash-preview", "L1"),
    ("CVE-2025-49014_jq", "gemini-3-flash-preview", "L1"),
    ("CVE-2024-4323_fluentbit", "glm-5.1", "L1"),
    ("CVE-2024-4323_fluentbit", "qwen3-coder-next", "L1"),
    ("CVE-2024-4323_fluentbit", "gpt-oss-20b", "L1"),
    ("CVE-2024-4323_fluentbit", "ministral-3-8b", "L1"),
    ("CVE-2014-2525_libyaml", "gemini-3-flash-preview", "L0"),
    ("CVE-2016-9827_libming", "gemini-3-flash-preview", "L0"),
    ("CVE-2021-32292_jsonc", "gemini-3-flash-preview", "L0"),
    ("CVE-2022-24724_cmark-gfm", "gemini-3-flash-preview", "L0"),
    ("CVE-2022-4899_zstd", "gemini-3-flash-preview", "L0"),
    ("CVE-2023-39804_gnutar", "gemini-3-flash-preview", "L0"),
    ("CVE-2024-4323_fluentbit", "gemini-3-flash-preview", "L0"),
    # CVE-2024-25062/libxml2 sweep (2026-05-19):
    # keep completed/validated pairs out of the queue even when runs/ is not
    # perfectly synchronized between Windows/Kali.
    ("CVE-2024-25062_libxml2", "gemini-3-flash-preview", "L3"),
    ("CVE-2024-25062_libxml2", "deepseek-v4-pro", "L3"),
    ("CVE-2024-25062_libxml2", "glm-5.1", "L3"),
    ("CVE-2024-25062_libxml2", "qwen3-coder-next", "L3"),
    ("CVE-2024-25062_libxml2", "gpt-oss-20b", "L3"),
    ("CVE-2024-25062_libxml2", "ministral-3-8b", "L3"),
    ("CVE-2024-25062_libxml2", "gemini-3-flash-preview", "L2"),
    ("CVE-2024-25062_libxml2", "deepseek-v4-pro", "L2"),
    ("CVE-2024-25062_libxml2", "glm-5.1", "L2"),
    ("CVE-2024-25062_libxml2", "qwen3-coder-next", "L2"),
    ("CVE-2024-25062_libxml2", "gpt-oss-20b", "L2"),
    ("CVE-2024-25062_libxml2", "ministral-3-8b", "L2"),
    ("CVE-2024-25062_libxml2", "gemini-3-flash-preview", "L1"),
    ("CVE-2024-25062_libxml2", "deepseek-v4-pro", "L1"),
    ("CVE-2024-25062_libxml2", "glm-5.1", "L1"),
    ("CVE-2024-25062_libxml2", "qwen3-coder-next", "L1"),
    ("CVE-2024-25062_libxml2", "gpt-oss-20b", "L1"),
    ("CVE-2024-25062_libxml2", "ministral-3-8b", "L1"),
    ("CVE-2024-25062_libxml2", "gemini-3-flash-preview", "L0"),
    ("CVE-2024-25062_libxml2", "deepseek-v4-pro", "L0"),
    ("CVE-2024-25062_libxml2", "glm-5.1", "L0"),
    ("CVE-2024-25062_libxml2", "qwen3-coder-next", "L0"),
    ("CVE-2024-25062_libxml2", "gpt-oss-20b", "L0"),
    ("CVE-2024-25062_libxml2", "ministral-3-8b", "L0"),
    # CVE-2023-29469/libxml2: completed+staged in interrupted batch.
    # Keep these out of queue even when local runs/ sync is partial.
    ("CVE-2023-29469_libxml2", "deepseek-v4-pro", "L3"),
    ("CVE-2023-29469_libxml2", "glm-5.1", "L3"),
    ("CVE-2023-29469_libxml2", "gemini-3-flash-preview", "L2"),
    ("CVE-2023-29469_libxml2", "gemini-3-flash-preview", "L1"),
    ("CVE-2023-29469_libxml2", "deepseek-v4-pro", "L1"),
    ("CVE-2023-29469_libxml2", "qwen3-coder-next", "L1"),
    ("CVE-2023-29469_libxml2", "gpt-oss-20b", "L1"),
    ("CVE-2023-29469_libxml2", "ministral-3-8b", "L1"),
    ("CVE-2023-29469_libxml2", "gemini-3-flash-preview", "L0"),
    ("CVE-2023-29469_libxml2", "deepseek-v4-pro", "L0"),
    ("CVE-2023-29469_libxml2", "qwen3-coder-next", "L0"),
    ("CVE-2023-29469_libxml2", "gpt-oss-20b", "L0"),
    ("CVE-2023-29469_libxml2", "ministral-3-8b", "L0"),
}

# Force re-scheduling for specific combos even if local run dirs or hardcoded
# baseline would classify them as existing.
FORCE_PENDING_COMBOS: set[tuple[str, str, str]] = {
    # Leakage pilot: run only libarchive L0 for all six active models.
    ("CVE-2024-57970_libarchive", "gemini-3-flash-preview", "L0"),
    ("CVE-2024-57970_libarchive", "deepseek-v4-pro", "L0"),
    ("CVE-2024-57970_libarchive", "glm-5.1", "L0"),
    ("CVE-2024-57970_libarchive", "qwen3-coder-next", "L0"),
    ("CVE-2024-57970_libarchive", "gpt-oss-20b", "L0"),
    ("CVE-2024-57970_libarchive", "ministral-3-8b", "L0"),
    # CVE-2024-25062/libxml2 coverage completion:
    # these three L3 cells are absent from the active 21/24 matrix. They are
    # run against the available standard harness; the task has no
    # target-vuln-direct service in compose.yml.
    ("CVE-2024-25062_libxml2", "gemini-3-flash-preview", "L3"),
    ("CVE-2024-25062_libxml2", "deepseek-v4-pro", "L3"),
    ("CVE-2024-25062_libxml2", "glm-5.1", "L3"),
}

# Guardrail note:
# - Do NOT add L1 hardcoded completions for:
#   * (CVE-2014-2525_libyaml, glm-5.1, L1)
#   * (CVE-2016-9827_libming, glm-5.1, L1)
# These combos should be decided by real run artifacts, not baseline hardcoding.


# Exclusions that must never be scheduled by the automatic batch, regardless
# of model alias or level.
EXCLUDED_CVES: dict[str, str] = {
    # Reproduction is not reliable in the current setup/harness architecture.
    # See: runs/CVE-2016-5314_libtiff/reproduction_analysis.md
    "CVE-2016-5314_libtiff": "excluded-policy:reproduction-unreliable",
}

# Combos that must be considered "existing" only when their canonical
# destination exists and validates. Legacy run dirs do not satisfy this rule.
CANONICAL_REQUIRED_COMBOS: set[tuple[str, str, str]] = {
}

# Per-combo exclusions.
# Methodology rule for CVE-2024-25062:
# - L3 ideally belongs with a direct harness (`target-vuln-direct`), but this
#   task compose currently exposes only target-vuln/target-fixed.
# - The three already-covered L3 cells remain excluded from reruns.
# - The three absent L3 cells are force-scheduled above as an explicit coverage
#   completion pass against the available standard harness.
EXCLUDED_COMBOS: dict[tuple[str, str, str, str], str] = {
    ("CVE-2024-25062_libxml2", "qwen3-coder-next", "L3", "default"): "excluded-policy:l3-requires-direct-harness-unavailable",
    ("CVE-2024-25062_libxml2", "gpt-oss-20b", "L3", "default"): "excluded-policy:l3-requires-direct-harness-unavailable",
    ("CVE-2024-25062_libxml2", "ministral-3-8b", "L3", "default"): "excluded-policy:l3-requires-direct-harness-unavailable",
}

# Service overrides by (CVE, level). These are methodological controls where a
# level intentionally targets a different harness/service.
#
# Source rationale:
# - runs/CVE-2023-29469_libxml2/gemini-2.0-flash/justification_L2_vs_L3.md
# - runs/proposal_approach.md
SERVICE_OVERRIDES_BY_CVE_LEVEL: dict[tuple[str, str], str] = {
    ("CVE-2023-29469_libxml2", "L3"): "target-vuln-direct",
}


@dataclass(frozen=True)
class Combo:
    cve: str
    model_alias: str
    level: str
    max_iters: int
    model_spec: str
    seed_profile: str = "default"


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    output: str
    timed_out: bool


def log(msg: str) -> None:
    ts = dt.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def run_cmd(
    args: list[str],
    cwd: Path,
    dry_run: bool,
    capture_output: bool = False,
    timeout_sec: int | None = None,
    env: dict[str, str] | None = None,
) -> CmdResult:
    cmd_text = " ".join(args)
    if dry_run:
        log(f"DRY-RUN cmd: {cmd_text}")
        return CmdResult(returncode=0, output="", timed_out=False)

    try:
        if capture_output:
            # Stream stdout/stderr in real-time while also capturing them.
            proc = subprocess.Popen(
                args,
                cwd=str(cwd),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                env=env,
            )
            stdout_chunks: list[str] = []
            stderr_chunks: list[str] = []

            def _pump(pipe, sink: list[str], to_stderr: bool = False) -> None:
                if pipe is None:
                    return
                try:
                    for line in iter(pipe.readline, ""):
                        sink.append(line)
                        if to_stderr:
                            print(line, end="", file=sys.stderr, flush=True)
                        else:
                            print(line, end="", flush=True)
                finally:
                    try:
                        pipe.close()
                    except Exception:
                        pass

            t_out = threading.Thread(target=_pump, args=(proc.stdout, stdout_chunks, False), daemon=True)
            t_err = threading.Thread(target=_pump, args=(proc.stderr, stderr_chunks, True), daemon=True)
            t_out.start()
            t_err.start()

            try:
                proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                return CmdResult(returncode=124, output=f"{''.join(stdout_chunks)}\n{''.join(stderr_chunks)}", timed_out=True)
            except KeyboardInterrupt:
                # On Ctrl+C, terminate child and return partial output so callers
                # can still extract diagnostics before aborting the batch.
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        pass
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                partial = f"{''.join(stdout_chunks)}\n{''.join(stderr_chunks)}"
                if partial and not partial.endswith("\n"):
                    partial += "\n"
                partial += "[run_pending_models] keyboard interrupt captured\n"
                return CmdResult(returncode=130, output=partial, timed_out=False)

            t_out.join(timeout=2)
            t_err.join(timeout=2)
            return CmdResult(
                returncode=proc.returncode if proc.returncode is not None else 1,
                output=f"{''.join(stdout_chunks)}\n{''.join(stderr_chunks)}",
                timed_out=False,
            )

        proc = subprocess.run(args, cwd=str(cwd), text=True, check=False, timeout=timeout_sec, env=env)
        return CmdResult(returncode=proc.returncode, output="", timed_out=False)
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        if stdout:
            print(stdout, end="")
        if stderr:
            print(stderr, end="", file=sys.stderr)
        return CmdResult(returncode=124, output=f"{stdout}\n{stderr}", timed_out=True)


def require_repo_root(repo_root: Path) -> None:
    required = [
        repo_root / ".git",
        repo_root / "runs",
        repo_root / "agents" / "openhands_llm" / "run.py",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise RuntimeError(f"No parece la raiz del repo. Faltan rutas: {missing}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ejecuta solo combinaciones pendientes CVE+modelo+nivel y normaliza resultados.",
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help="Modo real (por defecto es dry-run).",
    )
    p.add_argument(
        "--cve",
        action="append",
        default=[],
        help="Filtrar por CVE concreta. Repetible.",
    )
    p.add_argument(
        "--model",
        action="append",
        choices=sorted(MODEL_SPECS.keys()),
        default=[],
        help="Filtrar por modelo alias. Repetible.",
    )
    p.add_argument(
        "--level",
        action="append",
        choices=LEVEL_ORDER,
        default=[],
        help="Filtrar por nivel. Repetible.",
    )
    p.add_argument(
        "--no-push",
        action="store_true",
        help="No hacer git push al final.",
    )
    p.add_argument(
        "--commit-message",
        default="chore(runs): add pending CVE model runs",
        help="Mensaje del commit final.",
    )
    p.add_argument(
        "--run-timeout-sec",
        type=int,
        default=3600,
        help="Timeout por run del pipeline en segundos (default: 3600).",
    )
    p.add_argument(
        "--abort-on-timeout",
        action="store_true",
        help="Aborta el batch completo al primer timeout.",
    )
    p.add_argument(
        "--max-stage-file-mb",
        type=int,
        default=DEFAULT_MAX_STAGE_FILE_MB,
        help=f"Tamanio maximo por archivo para git add en runs/ (default: {DEFAULT_MAX_STAGE_FILE_MB} MB).",
    )
    p.add_argument(
        "--no-generate-diagnostics",
        action="store_true",
        help=(
            "Compatibilidad legacy: la observabilidad GENERATE se muestra en "
            "consola y ya no guarda reportes RUN_PENDING_MODELS_GENERATE_DIAGNOSTICS_*."
        ),
    )
    p.add_argument(
        "--provider-failure-streak-limit",
        type=int,
        default=None,
        help=(
            "Aborta el batch cuando se detectan >= N senales de fallo "
            "proveedor/cuota en un combo. Default dinamico por nivel: "
            "L3/15iters=20, L2/L1=30, L0=40. 0=desactivar."
        ),
    )
    return p.parse_args()


def safe_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _chunks(items: list[str], n: int) -> list[list[str]]:
    return [items[i : i + n] for i in range(0, len(items), n)]


def _legacy_task_layout_enabled(cve: str) -> bool:
    return cve in LEGACY_TASK_LAYOUT_ALLOWLIST


def _task_has_legacy_min_layout(task_dir: Path) -> bool:
    return (
        (task_dir / "compose.yml").is_file()
        and (task_dir / "levels").is_dir()
        and (task_dir / "seeds").is_dir()
    )


def task_descriptor_exists(task_dir: Path) -> bool:
    if (task_dir / "task.yml").is_file():
        return True
    cve = task_dir.name
    if _legacy_task_layout_enabled(cve) and _task_has_legacy_min_layout(task_dir):
        return True
    return False


def _seed_profile_cfg(cve: str, seed_profile: str) -> dict[str, Any] | None:
    if seed_profile == "default":
        return None
    return CVE_SEED_PROFILES.get(cve, {}).get(seed_profile)


def _seed_profile_dirname(cve: str, seed_profile: str) -> str | None:
    cfg = _seed_profile_cfg(cve, seed_profile)
    if not cfg:
        return None
    dirname = str(cfg.get("dir", "")).strip()
    return dirname or seed_profile


def stage_run_files_safely(
    repo_root: Path,
    run_path: Path,
    max_stage_file_mb: int,
    dry_run: bool,
) -> tuple[bool, str, list[str]]:
    if not run_path.exists():
        return False, "run-path-missing", []
    if not safe_relative_to(run_path, repo_root):
        return False, "unsafe-run-path", []

    max_bytes = max_stage_file_mb * 1024 * 1024
    files: list[Path] = []
    if run_path.is_file():
        files = [run_path]
    else:
        files = [p for p in run_path.rglob("*") if p.is_file()]

    if not files:
        return False, "run-path-has-no-files", []

    stageable: list[str] = []
    skipped_large: list[str] = []
    for f in files:
        try:
            size = f.stat().st_size
        except OSError:
            continue
        rel = f.relative_to(repo_root).as_posix()
        if size > max_bytes:
            skipped_large.append(rel)
        else:
            stageable.append(rel)

    if not stageable:
        return False, f"all-files-exceed-limit:{max_stage_file_mb}MB", []

    if skipped_large:
        log(
            f"WARNING se omiten {len(skipped_large)} archivo(s) > {max_stage_file_mb}MB para evitar rechazo en push."
        )
        for p in skipped_large[:6]:
            log(f"  omitiendo: {p}")
        if len(skipped_large) > 6:
            log(f"  ... y {len(skipped_large) - 6} mas")

    if dry_run:
        for chunk in _chunks(stageable, 120):
            log(f"DRY-RUN git add: git add -f -- {' '.join(chunk)}")
        return True, "staged-dry-run", stageable

    for chunk in _chunks(stageable, 120):
        add_res = run_cmd(["git", "add", "-f", "--", *chunk], cwd=repo_root, dry_run=False, capture_output=True)
        if add_res.returncode != 0:
            return False, "git-add-failed", []
    return True, "staged", stageable


def list_cves(runs_root: Path) -> list[str]:
    """Discover CVEs from both runs/ and tasks/ directories.

    On Kali the runs/ tree may not have all CVE dirs yet, so we also
    scan tasks/ to pick up every CVE that has a valid task descriptor
    (task.yml or allowlisted legacy task layout), excluding *_DISCARDED.
    """
    cves: set[str] = set()
    tasks_root = runs_root.parent / "tasks"
    # From runs/  (only if the CVE also has a valid task.yml)
    if runs_root.is_dir():
        for p in runs_root.iterdir():
            if p.is_dir() and p.name.startswith("CVE-"):
                if tasks_root.is_dir() and task_descriptor_exists(tasks_root / p.name):
                    cves.add(p.name)
    if tasks_root.is_dir():
        for p in tasks_root.iterdir():
            if (
                p.is_dir()
                and p.name.startswith("CVE-")
                and "DISCARDED" not in p.name
                and task_descriptor_exists(p)
            ):
                cves.add(p.name)
    return sorted(cves)


def read_summary_from_run_dir(run_dir: Path, cve: str) -> dict | None:
    candidates = [run_dir / "summary.json", run_dir / cve / "summary.json"]
    for c in candidates:
        if c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception:
                return None
    return None


def canonical_dest(
    runs_root: Path,
    cve: str,
    model_alias: str,
    level: str,
    seed_profile: str = "default",
) -> Path:
    model_dir = runs_root / cve / model_alias
    profile_dir = _seed_profile_dirname(cve, seed_profile)
    if profile_dir:
        model_dir = model_dir / profile_dir
    run_name_suffix = RUN_NAME_SUFFIX_BY_CVE.get(cve, "")
    return model_dir / f"{level}_{cve}{run_name_suffix}"


def canonical_dest_variants(
    runs_root: Path,
    cve: str,
    model_alias: str,
    level: str,
    seed_profile: str = "default",
) -> list[Path]:
    """
    Canonical run-dir candidate names.
    Supports plain canonical and prefixed variants introduced for labeling.
    """
    base = canonical_dest(runs_root, cve, model_alias, level, seed_profile=seed_profile)
    names = [
        base.name,
        f"sucess_{base.name}",
        f"failure_{base.name}",
        f"success_{base.name}",
    ]
    seen: set[str] = set()
    out: list[Path] = []
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        out.append(base.parent / n)
    return out


def _path_is_tracked_in_git(repo_root: Path, path: Path) -> bool:
    """
    Return True when at least one tracked file exists under `path` in git index.
    This helps keep scheduling stable even if the local working tree copy of
    runs/ was deleted to free disk space.
    """
    try:
        rel = path.relative_to(repo_root).as_posix()
    except Exception:
        return False
    proc = subprocess.run(
        ["git", "ls-files", "--", rel],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    if proc.returncode != 0:
        return False
    return any(line.strip() for line in proc.stdout.splitlines())


def find_existing_level_run(
    runs_root: Path,
    cve: str,
    model_alias: str,
    level: str,
    seed_profile: str = "default",
    expected_model: str | None = None,
    expected_max_iters: int | None = None,
) -> tuple[bool, str]:
    model_dir = runs_root / cve / model_alias
    profile_dir = _seed_profile_dirname(cve, seed_profile)
    if profile_dir:
        model_dir = model_dir / profile_dir
    for dest in canonical_dest_variants(
        runs_root,
        cve,
        model_alias,
        level,
        seed_profile=seed_profile,
    ):
        if dest.is_dir():
            ok, why = validate_run_dir(
                dest,
                cve,
                level,
                expected_model=expected_model,
                expected_max_iters=expected_max_iters,
            )
            if ok:
                return True, f"exists-canonical:{dest.name}"
            return False, f"canonical-invalid:{why}"
        # If local runs/ were cleaned up but canonical run files are still tracked
        # in git, treat them as existing to avoid false re-scheduling.
        if _path_is_tracked_in_git(runs_root.parent, dest):
            return True, f"exists-canonical-index:{dest.name}"
    if not model_dir.is_dir():
        return False, "model-dir-missing"

    for child in sorted(model_dir.iterdir()):
        if not child.is_dir():
            continue
        summary = read_summary_from_run_dir(child, cve)
        if not summary:
            continue
        if (
            summary.get("task_id") == cve
            and summary.get("level") == level
            and (expected_model is None or summary.get("model") == expected_model)
            and (expected_max_iters is None or summary.get("max_iters") == expected_max_iters)
            and has_min_run_structure(child, summary)
            and is_campaign_complete(summary)
        ):
            return True, f"exists-legacy:{child.name}"
    return False, "pending"


def parse_run_dir_from_output(output: str) -> Path | None:
    found = None
    for line in output.splitlines():
        m = RUN_DIR_RE.match(line)
        if m:
            found = m.group(1).strip()
    if not found:
        return None
    return Path(found)


def has_min_run_structure(run_dir: Path, summary: dict[str, Any]) -> bool:
    """Run valida por estructura minima, independiente del oracle/success."""
    iter_dirs = [p for p in run_dir.iterdir() if p.is_dir() and p.name.startswith("iter_")] if run_dir.is_dir() else []
    total_iters = summary.get("total_iters")
    if not isinstance(total_iters, int) or total_iters < 0:
        return False
    # Compatible con CVEs especiales: una run puede fallar sin crash, pero debe persistir artefactos.
    if total_iters == 0:
        return (run_dir / "summary.json").is_file() or (run_dir / str(summary.get("task_id", "")) / "summary.json").is_file()
    return len(iter_dirs) >= total_iters


def is_campaign_complete(summary: dict[str, Any]) -> bool:
    """
    A run is complete if:
    - it found a confirmed success early, or
    - it consumed the full scheduled max_iters budget.
    """
    success = summary.get("success")
    total_iters = summary.get("total_iters")
    max_iters = summary.get("max_iters")
    if success is True:
        return True
    if isinstance(total_iters, int) and isinstance(max_iters, int):
        return total_iters >= max_iters
    return False


def has_partial_run_structure(run_dir: Path) -> bool:
    """
    Best-effort structure check for partially persisted runs when summary is missing/corrupted.
    """
    if not run_dir.is_dir():
        return False
    iter_dirs = [p for p in run_dir.iterdir() if p.is_dir() and p.name.startswith("iter_")]
    if not iter_dirs:
        return False
    for it in iter_dirs:
        if (it / "generate.json").is_file() or (it / "verify.json").is_file() or (it / "analysis.json").is_file():
            return True
    return False


def validate_run_dir(run_dir: Path, cve: str, level: str, expected_model: str | None = None, expected_max_iters: int | None = None) -> tuple[bool, str]:
    summary = read_summary_from_run_dir(run_dir, cve)
    if not summary:
        return False, f"summary-missing-or-invalid:{run_dir}"
    required_keys = {"task_id", "level", "max_iters", "total_iters", "success", "timestamp"}
    missing = [k for k in required_keys if k not in summary]
    if missing:
        return False, f"summary-missing-keys:{missing}"
    if summary.get("task_id") != cve:
        return False, f"summary-task-mismatch:{summary.get('task_id')}"
    if summary.get("level") != level:
        return False, f"summary-level-mismatch:{summary.get('level')}"
    if expected_model and summary.get("model") != expected_model:
        return False, f"summary-model-mismatch:{summary.get('model')}"
    if expected_max_iters is not None and summary.get("max_iters") != expected_max_iters:
        return False, f"summary-max-iters-mismatch:{summary.get('max_iters')}"
    if not has_min_run_structure(run_dir, summary):
        return False, "summary-structure-invalid"
    if not is_campaign_complete(summary):
        return False, f"summary-incomplete-iters:{summary.get('total_iters')}/{summary.get('max_iters')}"
    return True, "ok"


def resolve_new_run_dir(
    repo_root: Path,
    combo: Combo,
    model_dir: Path,
    before_dirs: set[str],
    output: str,
) -> tuple[Path | None, str]:
    parsed = parse_run_dir_from_output(output)
    if parsed:
        run_dir = parsed if parsed.is_absolute() else (repo_root / parsed)
        if run_dir.is_dir():
            if run_dir.name in before_dirs:
                return None, f"parsed-dir-existed-before:{run_dir.name}"
            ok, why = validate_run_dir(
                run_dir,
                combo.cve,
                combo.level,
                expected_model=combo.model_spec,
                expected_max_iters=combo.max_iters,
            )
            if ok:
                return run_dir, "from-output"
            if has_partial_run_structure(run_dir):
                return run_dir, f"from-output-partial:{why}"
            return None, why

    if not model_dir.is_dir():
        return None, "model-dir-missing-post-run"

    after_dirs = {p.name for p in model_dir.iterdir() if p.is_dir()}
    added = sorted(after_dirs - before_dirs)
    candidates: list[Path] = []
    partial_candidates: list[tuple[Path, str]] = []
    for name in added:
        p = model_dir / name
        ok, why = validate_run_dir(
            p,
            combo.cve,
            combo.level,
            expected_model=combo.model_spec,
            expected_max_iters=combo.max_iters,
        )
        if ok:
            candidates.append(p)
            continue
        if has_partial_run_structure(p):
            partial_candidates.append((p, why))

    if len(candidates) == 1:
        return candidates[0], "from-diff"
    if len(candidates) == 0:
        if len(partial_candidates) == 1:
            p, why = partial_candidates[0]
            return p, f"from-diff-partial:{why}"
        if len(partial_candidates) > 1:
            return None, f"ambiguous-partial-run-dirs:{[c[0].name for c in partial_candidates]}"
        return None, "no-new-valid-run-dir"
    return None, f"ambiguous-new-run-dirs:{[c.name for c in candidates]}"


def ensure_tools(repo_root: Path, require_docker: bool) -> None:
    required_cmds = [["git", "--version"], ["python", "--version"]]
    if require_docker:
        required_cmds.append(["docker", "--version"])
    for cmd in required_cmds:
        proc = subprocess.run(cmd, cwd=str(repo_root), text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"Comando requerido no disponible: {' '.join(cmd)}")
    if require_docker:
        # Docker binary can exist while daemon is down; fail fast in that case.
        dproc = subprocess.run(
            ["docker", "info"],
            cwd=str(repo_root),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if dproc.returncode != 0:
            detail = (dproc.stderr or dproc.stdout or "").strip()
            raise RuntimeError(
                "Docker daemon no disponible en esta terminal. "
                "Inicia Docker y reintenta. "
                f"Detalle: {detail[:200]}"
            )
    proc = subprocess.run(
        ["python", "-m", "agents.openhands_llm.run", "--help"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError("No se puede invocar el pipeline: python -m agents.openhands_llm.run --help")


def ensure_repo_state_clean_for_batch(repo_root: Path, execute: bool) -> None:
    proc = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or proc.stdout.strip() != "true":
        raise RuntimeError("El directorio actual no es un repo git valido.")

    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if staged.returncode != 0:
        raise RuntimeError("No se pudo inspeccionar staged changes.")
    staged_lines = [ln.strip() for ln in staged.stdout.splitlines() if ln.strip()]
    if execute and staged_lines:
        raise RuntimeError(
            "Hay cambios staged previos. Abortando por seguridad para evitar commit contaminado.\n"
            f"Staged detectados: {staged_lines[:20]}"
        )


def combo_key(combo: Combo) -> str:
    return f"{combo.cve}|{combo.model_alias}|{combo.level}|{combo.seed_profile}"


def combo_in_hardcoded_baseline(combo: Combo) -> bool:
    if (combo.cve, combo.model_alias, combo.level) in FORCE_PENDING_COMBOS:
        return False
    # CVE-2024-4323 has two seed profiles. For L0, keep seed_new_op schedulable
    # even if L0 is hardcoded from seed_crash completion.
    if (
        combo.cve == "CVE-2024-4323_fluentbit"
        and combo.level == "L0"
        and combo.seed_profile == "seed_new_op"
    ):
        return False
    return (combo.cve, combo.model_alias, combo.level) in HARDCODED_EXISTING_COMBOS


def combo_is_forced_pending(combo: Combo) -> bool:
    return (combo.cve, combo.model_alias, combo.level) in FORCE_PENDING_COMBOS


def combo_requires_canonical_only(combo: Combo) -> bool:
    return (combo.cve, combo.model_alias, combo.level) in CANONICAL_REQUIRED_COMBOS


def find_existing_canonical_only_run(
    runs_root: Path,
    cve: str,
    model_alias: str,
    level: str,
    seed_profile: str = "default",
    expected_model: str | None = None,
    expected_max_iters: int | None = None,
) -> tuple[bool, str]:
    for dest in canonical_dest_variants(
        runs_root,
        cve,
        model_alias,
        level,
        seed_profile=seed_profile,
    ):
        if dest.is_dir():
            ok, why = validate_run_dir(
                dest,
                cve,
                level,
                expected_model=expected_model,
                expected_max_iters=expected_max_iters,
            )
            if ok:
                return True, f"exists-canonical:{dest.name}"
            return False, f"canonical-invalid:{why}"
        if _path_is_tracked_in_git(runs_root.parent, dest):
            return True, f"exists-canonical-index:{dest.name}"
    return False, "canonical-missing"


def resolve_service_for_combo(combo: Combo) -> str:
    return SERVICE_OVERRIDES_BY_CVE_LEVEL.get((combo.cve, combo.level), "target-vuln")


def _extract_cve_from_parts(parts: tuple[str, ...] | list[str]) -> str | None:
    for part in parts:
        if part.startswith("CVE-"):
            return part
    return None


def _paired_fixed_service_name(vuln_service: str) -> str:
    if vuln_service.startswith("target-vuln"):
        return vuln_service.replace("target-vuln", "target-fixed", 1)
    return "target-fixed"


def discover_markdown_policy_signals(repo_root: Path) -> tuple[list[str], list[str]]:
    """
    Return (service_overrides_detected, warnings) from known high-signal .md docs.
    This does not auto-mutate policy; it only audits and reports consistency.
    """
    overrides_detected: list[str] = []
    warnings: list[str] = []

    # Detect direct-harness methodology notes.
    for md in (repo_root / "runs").rglob("justification_L2_vs_L3.md"):
        txt = _read_text_if_exists(md).lower()
        if "target-vuln-direct" in txt:
            cve = _extract_cve_from_parts(md.parts)
            if cve:
                key = (cve, "L3")
                configured = SERVICE_OVERRIDES_BY_CVE_LEVEL.get(key)
                if configured == "target-vuln-direct":
                    overrides_detected.append(
                        f"{cve} L3 -> target-vuln-direct (aligned:{md.relative_to(repo_root).as_posix()})"
                    )
                else:
                    warnings.append(
                        f"{cve} L3 mentions target-vuln-direct but policy differs/missing "
                        f"(configured={configured!r}) at {md.relative_to(repo_root).as_posix()}"
                    )

    # Cross-check that configured service overrides are actually realizable with compose services.
    for (cve, level), vuln_service in sorted(SERVICE_OVERRIDES_BY_CVE_LEVEL.items()):
        compose = _read_text_if_exists(repo_root / "tasks" / cve / "compose.yml").lower()
        if not compose:
            warnings.append(
                f"{cve} {level} override={vuln_service} but compose.yml is missing/unreadable."
            )
            continue
        if f"{vuln_service}:" not in compose:
            warnings.append(
                f"{cve} {level} override={vuln_service} not found in compose.yml services."
            )
        fixed_service = _paired_fixed_service_name(vuln_service)
        if f"{fixed_service}:" not in compose:
            warnings.append(
                f"{cve} {level} fixed pair service {fixed_service} not found in compose.yml."
            )

    # Detect explicit non-reproducible notes and verify exclusion policy alignment.
    non_repro_markers = (
        "no reproducido",
        "not reproduc",
        "reproduction is not reliable",
        "cannot be reliably reproduced",
        "cannot reproduce",
        "no se pudo reproducir",
        "failure to reproduce",
        "failed to reproduce",
        "persistent failure to reproduce",
        "was not achieved",
    )
    for md in (repo_root / "runs").rglob("reproduction_analysis.md"):
        txt = _read_text_if_exists(md).lower()
        if any(marker in txt for marker in non_repro_markers):
            cve = _extract_cve_from_parts(md.parts)
            if not cve:
                continue
            configured_reason = EXCLUDED_CVES.get(cve, "")
            if configured_reason:
                overrides_detected.append(
                    f"{cve} excluded (aligned:{configured_reason}; source:{md.relative_to(repo_root).as_posix()})"
                )
            else:
                warnings.append(
                    f"{cve} has non-repro note in {md.relative_to(repo_root).as_posix()} "
                    "but is not in EXCLUDED_CVES."
                )

    # Detect oracle-broken notes (informational only; no hard exclusion by default).
    for md in (repo_root / "tasks").rglob("ORACLE_BROKEN.md"):
        cve = _extract_cve_from_parts(md.parts)
        if cve:
            warnings.append(
                f"{cve} has ORACLE_BROKEN note ({md.relative_to(repo_root).as_posix()}); "
                "review before large campaign scheduling."
            )

    return sorted(set(overrides_detected)), sorted(set(warnings))


def hardcoded_baseline_alignment_stats() -> tuple[int, int]:
    """
    Return (aligned, legacy) counts for hardcoded baseline entries against
    currently active model aliases.
    """
    active_aliases = set(MODEL_SPECS.keys())
    aligned = 0
    legacy = 0
    for _, model_alias, _ in HARDCODED_EXISTING_COMBOS:
        if model_alias in active_aliases:
            aligned += 1
        else:
            legacy += 1
    return aligned, legacy


def combo_is_policy_excluded(combo: Combo) -> tuple[bool, str]:
    combo_reason = EXCLUDED_COMBOS.get((combo.cve, combo.model_alias, combo.level, combo.seed_profile))
    if combo_reason:
        return True, combo_reason
    reason = EXCLUDED_CVES.get(combo.cve)
    if reason:
        return True, reason
    allowed_levels = MODEL_LEVEL_ALLOWLIST.get(combo.model_alias)
    if allowed_levels is not None and combo.level not in allowed_levels:
        return True, f"excluded-policy:model-level-scope-{combo.model_alias}"
    return False, ""


def classify_pipeline_failure(output: str) -> str | None:
    """
    Classify known pipeline failures from stdout/stderr text.
    Returns a short failure code or None if not recognized.
    """
    text = (output or "").lower()
    if "failed to solve" in text or "did not complete successfully: exit code" in text:
        return "pipeline-build-failed"
    if "error: build failed" in text or "docker compose build" in text and "failed" in text:
        return "pipeline-build-failed"
    if "images not ready" in text:
        return "pipeline-images-not-ready"
    if "seed file not found" in text:
        return "pipeline-seed-not-found"
    if "oci runtime create failed" in text or "failed to create shim task" in text:
        return "pipeline-container-start-failed"
    if "permission denied: unknown" in text:
        return "pipeline-container-permission-denied"
    if "invalid port: '11434:generatecontent'" in text:
        return "pipeline-vertex-api-base-leak"
    return None


def detect_run_anomalies(output: str) -> list[str]:
    """
    Detect suspicious runtime behaviors that should be manually reviewed,
    even when the run produced/staged artifacts.
    """
    text = (output or "").lower()
    anomalies: list[str] = []

    def add(code: str) -> None:
        if code not in anomalies:
            anomalies.append(code)

    # Seed/harness semantic mismatches
    if "seed contains nul byte" in text or "use text argument seeds for this task" in text:
        add("seed-nul-rejected")
    if "seed not found at" in text:
        add("harness-seed-not-found")
    if "target binary not found or not executable" in text:
        add("harness-target-not-executable")
    if "invalid port: '11434:generatecontent'" in text:
        add("vertex-api-base-leak")
    # Treat as anomaly only if the stop request was not explicitly ignored.
    if "llm requested early stop" in text and "ignored by policy; continuing" not in text:
        add("llm-stop-early")

    # Container runtime errors that can still leave partial artifacts
    if "oci runtime create failed" in text or "failed to create shim task" in text:
        add("container-runtime-create-failed")
    if "permission denied: unknown" in text:
        add("container-permission-denied")

    # Keep this focused: transient LLM parse/mutation retries are intentionally ignored.
    return anomalies


def extract_generate_diagnostics(output: str) -> dict[str, int]:
    """
    Non-blocking diagnostics focused on ANALYZE/GENERATE quality so long batches
    can be audited quickly without manually reading each run log.
    """
    text = (output or "").lower()
    metrics: dict[str, int] = {
        "empty_response_warnings": text.count("warning: empty response from llm"),
        "json_parse_errors": text.count("json parse error"),
        "generate_no_mutations": (
            text.count("warning: generate payload has no mutations")
            + text.count("no mutations proposed")
        ),
        "mutation_application_errors": text.count("mutation application error:"),
        "unknown_mutation_ops": (
            text.count("unknown mutation operation:")
            + text.count("unsupported op '")
        ),
        "llm_generation_failed": text.count("error: llm generation failed:"),
        "llm_timeout_errors": (
            text.count("litellm.timeout")
            + text.count("connection timed out after")
        ),
        "xml_parser_errors": text.count("parser error :"),
        "seed_validation_failures": text.count("validation failed:"),
        "task_guard_failures": text.count("task guard failed:"),
        "generate_retry_attempts": len(re.findall(r"retry attempt \d+/\d+", text)),
        "max_token_response_hits": 0,
        "max_token_observed": 0,
    }

    token_matches = re.findall(r"llm responded \((\d+)\s+tokens\)", text)
    if token_matches:
        token_vals = []
        for raw in token_matches:
            try:
                token_vals.append(int(raw))
            except ValueError:
                continue
        if token_vals:
            max_tok = max(token_vals)
            metrics["max_token_observed"] = max_tok
            if max_tok >= 1800:
                metrics["max_token_response_hits"] = sum(1 for v in token_vals if v == max_tok)
    return metrics


def provider_failure_signal_count(output: str) -> int:
    """
    Count likely provider-side failure signals (quota/credit exhaustion and
    repeated empty-generation loops) in captured pipeline output.
    """
    text = (output or "").lower()

    explicit_markers = [
        "insufficient credit",
        "insufficient credits",
        "insufficient quota",
        "quota exceeded",
        "rate limit exceeded",
        "payment required",
        "credit balance",
        "resource has been exhausted",
        "402 payment required",
        "429 too many requests",
    ]
    # Strong evidence of exhausted credits/quota: abort quickly.
    explicit_hits = sum(text.count(marker) for marker in explicit_markers)
    if explicit_hits > 0:
        return min(explicit_hits * 50, 300)

    # No explicit quota markers:
    # - DO NOT count max-token/empty loops toward provider exhaustion cutoff.
    # - Only count harder provider/network failure patterns.
    gen_fail_hits = min(text.count("error: llm generation failed:"), 8)
    api_conn_hits = min(text.count("litellm.apiconnectionerror"), 8)
    timeout_hits = min(
        text.count("litellm.timeout")
        + text.count("connection timed out after")
        + text.count("read timed out"),
        12,
    )
    retry_hits = min(len(re.findall(r"retry attempt \d+/\d+", text)), 8)
    score = gen_fail_hits + (api_conn_hits * 2) + (timeout_hits * 2) + max(0, retry_hits - 4)
    return min(score, 24)


def default_provider_failure_limit_for_combo(combo: Combo) -> int:
    """
    Dynamic cutoff tuned by campaign depth to avoid over-sensitive aborts.
    Requested policy:
    - L3 / 15 iterations -> 20
    - L2 / L1 -> 30
    - L0 -> 40
    """
    if combo.level == "L0":
        return 40
    if combo.level in {"L1", "L2"}:
        return 30
    if combo.max_iters <= 15:
        return 20
    return 30


def effective_provider_failure_limit(
    combo: Combo,
    cli_limit: int | None,
) -> tuple[int, str]:
    """
    Resolve effective failure limit for a combo.
    Returns (limit, source), where source is "cli" or "dynamic".
    """
    if cli_limit is None:
        return default_provider_failure_limit_for_combo(combo), "dynamic"
    return int(cli_limit), "cli"


def generate_diag_score(metrics: dict[str, int]) -> int:
    """
    Weighted score to rank combos by generate instability severity.
    """
    return (
        metrics.get("empty_response_warnings", 0)
        + metrics.get("json_parse_errors", 0)
        + metrics.get("generate_no_mutations", 0)
        + metrics.get("mutation_application_errors", 0) * 2
        + metrics.get("unknown_mutation_ops", 0) * 3
        + metrics.get("llm_generation_failed", 0) * 3
        + metrics.get("llm_timeout_errors", 0) * 3
        + metrics.get("xml_parser_errors", 0)
        + metrics.get("seed_validation_failures", 0) * 2
        + metrics.get("task_guard_failures", 0) * 2
    )


def has_generate_diag_signal(metrics: dict[str, int]) -> bool:
    tracked = [
        "empty_response_warnings",
        "json_parse_errors",
        "generate_no_mutations",
        "mutation_application_errors",
        "unknown_mutation_ops",
        "llm_generation_failed",
        "llm_timeout_errors",
        "xml_parser_errors",
        "seed_validation_failures",
        "task_guard_failures",
        "generate_retry_attempts",
    ]
    return any(metrics.get(k, 0) > 0 for k in tracked)


def normalize_run_anomalies(repo_root: Path, cve: str, anomalies: list[str], output: str) -> list[str]:
    """
    Reduce false-positive anomaly noise.
    For text-semantics tasks, `seed-nul-rejected` can appear in early retries and still
    converge to valid seeds that reach VERIFY. In that case, do not mark the full run as anomalous.
    """
    uniq = list(dict.fromkeys(anomalies))
    text = output or ""
    text_l = text.lower()

    # False-positive guard:
    # - Some logs contain "LLM requested early stop (ignored by policy; continuing)".
    # - In those cases the run is NOT an early stop and may still complete all iterations.
    if "llm-stop-early" in uniq:
        ignored_by_policy = "ignored by policy; continuing" in text_l
        reached_max_iters = False
        m_max = re.search(r"^\s*max iters:\s*(\d+)\s*$", text, flags=re.IGNORECASE | re.MULTILINE)
        m_done = re.search(r"^\s*iterations:\s*(\d+)\s*$", text, flags=re.IGNORECASE | re.MULTILINE)
        if m_max and m_done:
            try:
                reached_max_iters = int(m_done.group(1)) >= int(m_max.group(1))
            except ValueError:
                reached_max_iters = False
        if ignored_by_policy or reached_max_iters:
            uniq = [code for code in uniq if code != "llm-stop-early"]

    if (
        len(uniq) == 1
        and uniq[0] == "seed-nul-rejected"
        and _task_prefers_text_seed(repo_root, cve)
        and "Testing vulnerable version..." in text
    ):
        return []
    return uniq


def save_state(state_path: Path, data: dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(state_path)


def update_combo_state(state: dict[str, Any], combo: Combo, status: str, detail: str) -> None:
    state.setdefault("combos", {})
    state["combos"][combo_key(combo)] = {
        "cve": combo.cve,
        "model_alias": combo.model_alias,
        "model_spec": combo.model_spec,
        "level": combo.level,
        "seed_profile": combo.seed_profile,
        "max_iters": combo.max_iters,
        "status": status,
        "detail": detail,
        "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
    }


def task_exists(repo_root: Path, cve: str) -> bool:
    return task_descriptor_exists(repo_root / "tasks" / cve)


def task_harness_exists(repo_root: Path, cve: str) -> tuple[bool, str]:
    """
    Detect whether the task has an executable harness definition.
    Some tasks use `harness/run.sh`; others define execution directly in task.yml
    (`run.argv_template`) and rely on Docker entrypoints.
    """
    task_dir = repo_root / "tasks" / cve
    run_sh = task_dir / "harness" / "run.sh"
    if run_sh.is_file():
        return True, "harness/run.sh"

    harness_sh = task_dir / "harness" / "harness.sh"
    if harness_sh.is_file():
        return True, "harness/harness.sh"

    task_yml = _read_text_if_exists(task_dir / "task.yml").lower()
    if "run:" in task_yml and "argv_template:" in task_yml:
        return True, "task.yml:run.argv_template"

    compose_yml = _read_text_if_exists(task_dir / "compose.yml").lower()
    if "entrypoint:" in compose_yml and "/harness" in compose_yml:
        return True, "compose.yml:entrypoint:/harness"

    return False, f"tasks/{cve}/harness/run.sh"


def _read_text_if_exists(p: Path) -> str:
    if not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _task_prefers_text_seed(repo_root: Path, cve: str) -> bool:
    task_dir = repo_root / "tasks" / cve
    yml = _read_text_if_exists(task_dir / "task.yml").lower()
    harness = _read_text_if_exists(task_dir / "harness" / "run.sh").lower()
    if "<arg_from_seed>" in yml:
        return True
    text_markers = [
        "treats seeds as text arguments",
        "utf-8 jq program text",
        "outdir=\"$(cat \"$seed\")\"",
    ]
    return any(m in harness for m in text_markers)


def _pick_seed_candidate(repo_root: Path, cve: str, seeds_dir: Path) -> tuple[Path | None, str]:
    candidates = (
        SEED_CANDIDATES_TEXT_FIRST
        if _task_prefers_text_seed(repo_root, cve)
        else SEED_CANDIDATES_DEFAULT
    )
    for name in candidates:
        p = seeds_dir / name
        if p.is_file():
            return p, f"seed-selected:{name}"
    return None, "seed-not-found"


def _list_seed_generators(seeds_dir: Path) -> list[Path]:
    scripts: list[Path] = []
    seen: set[Path] = set()
    for pattern in SEED_GENERATOR_GLOBS:
        for p in sorted(seeds_dir.glob(pattern)):
            if p.is_file() and p not in seen:
                scripts.append(p)
                seen.add(p)
    return scripts


def _run_seed_generator(repo_root: Path, script: Path) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(repo_root),
            text=True,
            capture_output=True,
            check=False,
            timeout=SEED_GENERATOR_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return False, f"timeout:{script.name}:{SEED_GENERATOR_TIMEOUT_SEC}s"

    if proc.returncode == 0:
        return True, f"ok:{script.name}"

    out = (proc.stdout or "").strip().replace("\n", " ")[:140]
    err = (proc.stderr or "").strip().replace("\n", " ")[:140]
    detail = err or out or f"rc={proc.returncode}"
    return False, f"fail:{script.name}:{detail}"


def _validate_locked_seed(cve: str, seed_path: Path) -> tuple[bool, str]:
    lock = LOCKED_BASE_SEEDS.get(cve)
    if not lock:
        return True, ""

    expected_name = lock.get("filename", "")
    expected_sha = lock.get("sha256", "").lower()
    if expected_name and seed_path.name != expected_name:
        return False, f"seed-lock-name-mismatch:expected:{expected_name}:got:{seed_path.name}"

    digest = hashlib.sha256(seed_path.read_bytes()).hexdigest().lower()
    expected_hashes = [h.strip().lower() for h in expected_sha.split(",") if h.strip()]
    if expected_hashes and digest not in expected_hashes:
        return False, (
            f"seed-lock-hash-mismatch:{seed_path.name}:{digest}:"
            f"expected:{'|'.join(expected_hashes)}"
        )

    shown = expected_hashes[0] if expected_hashes else expected_sha
    return True, f"seed-locked:{seed_path.name}:{shown[:12]}"


def _validate_seed_expected(seed_path: Path, expected_name: str, expected_sha: str) -> tuple[bool, str]:
    if expected_name and seed_path.name != expected_name:
        return False, f"seed-lock-name-mismatch:expected:{expected_name}:got:{seed_path.name}"
    if expected_sha:
        digest = hashlib.sha256(seed_path.read_bytes()).hexdigest().lower()
        expected_hashes = [h.strip().lower() for h in expected_sha.split(",") if h.strip()]
        if expected_hashes and digest not in expected_hashes:
            return False, (
                f"seed-lock-hash-mismatch:{seed_path.name}:{digest}:"
                f"expected:{'|'.join(expected_hashes)}"
            )
        shown = expected_hashes[0] if expected_hashes else expected_sha
        return True, f"seed-locked:{seed_path.name}:{shown[:12]}"
    return True, f"seed-locked:{seed_path.name}:nohash"


def choose_seed_for_task(
    repo_root: Path,
    cve: str,
    level: str | None = None,
    seed_profile: str = "default",
    auto_generate: bool = False,
) -> tuple[Path | None, str]:
    seeds_dir = repo_root / "tasks" / cve / "seeds"
    if not seeds_dir.is_dir():
        return None, "seed-dir-missing"

    profile_cfg = _seed_profile_cfg(cve, seed_profile)
    if profile_cfg:
        override_name = str(profile_cfg.get("filename", "")).strip()
        override_sha = str(profile_cfg.get("sha256", "")).strip().lower()
        override_path = seeds_dir / override_name
        if not override_path.is_file():
            return None, f"seed-profile-missing:{seed_profile}:{override_name}"
        ok_profile, lock_reason_profile = _validate_seed_expected(
            override_path, override_name, override_sha
        )
        if not ok_profile:
            return None, f"seed-selected:{override_name}({lock_reason_profile})"
        return (
            override_path,
            f"seed-selected:{override_name}({lock_reason_profile})(seed-profile:{seed_profile})",
        )

    if level:
        override = SEED_OVERRIDE_BY_CVE_LEVEL.get((cve, level))
    else:
        override = None
    if override:
        override_name = override.get("filename", "").strip()
        override_sha = override.get("sha256", "").strip().lower()
        override_path = seeds_dir / override_name
        if not override_path.is_file():
            return None, f"seed-override-missing:{override_name}"
        ok_override, lock_reason_override = _validate_seed_expected(
            override_path, override_name, override_sha
        )
        if not ok_override:
            return None, f"seed-selected:{override_name}({lock_reason_override})"
        return override_path, f"seed-selected:{override_name}({lock_reason_override})(seed-mode-override:{level})"

    seed, reason = _pick_seed_candidate(repo_root, cve, seeds_dir)
    if seed:
        ok, lock_reason = _validate_locked_seed(cve, seed)
        if ok:
            if lock_reason:
                return seed, f"{reason}({lock_reason})"
            return seed, reason
        reason = f"{reason}({lock_reason})"

    generators = _list_seed_generators(seeds_dir)
    if not generators:
        return None, reason

    if not auto_generate:
        return None, f"{reason}(generator-available:{','.join(g.name for g in generators)})"

    generator_results: list[str] = []
    for script in generators:
        ok, detail = _run_seed_generator(repo_root, script)
        generator_results.append(detail)
        if ok:
            seed, reason = _pick_seed_candidate(repo_root, cve, seeds_dir)
            if seed:
                lock_ok, lock_reason = _validate_locked_seed(cve, seed)
                if lock_ok:
                    suffix = f"(generated-by:{script.name})"
                    if lock_reason:
                        suffix += f"({lock_reason})"
                    return seed, f"{reason}{suffix}"
                reason = f"{reason}(generated-by:{script.name})({lock_reason})"

    return None, f"{reason}(generator-attempted:{';'.join(generator_results)})"


def _parse_local_env_file(path: Path) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        parsed[key] = value
    return parsed


def load_local_llm_env(repo_root: Path) -> tuple[dict[str, str], Path | None]:
    env_file = repo_root / LOCAL_ENV_FILENAME
    if not env_file.is_file():
        return {}, None
    return _parse_local_env_file(env_file), env_file


def _compact_sanitized_env_entries(entries: list[str]) -> list[str]:
    """
    Keep only the last effective value per KEY for `KEY=VALUE` entries while
    preserving first-seen key order. Bare keys (without '=') are kept unique.
    """
    key_order: list[str] = []
    key_values: dict[str, str] = {}
    bare: list[str] = []
    for item in entries:
        if "=" in item:
            key, value = item.split("=", 1)
            key = key.strip()
            if key and key not in key_values:
                key_order.append(key)
            if key:
                key_values[key] = value
            else:
                bare.append(item)
            continue
        if item not in bare:
            bare.append(item)
    compacted = [f"{k}={key_values[k]}" for k in key_order]
    compacted.extend(bare)
    return compacted


def build_run_env(
    model_spec: str,
    local_llm_env: dict[str, str],
    *,
    cve: str | None = None,
    level: str | None = None,
) -> tuple[dict[str, str], list[str]]:
    env = os.environ.copy()
    for key, value in local_llm_env.items():
        if key not in env or not env.get(key):
            env[key] = value

    # Allow storing only OLLAMA_API_KEY in local env and map to the key used
    # by the OpenHands client wrapper.
    if model_spec.startswith("ollama/") and not env.get("LLM_API_KEY") and env.get("OLLAMA_API_KEY"):
        env["LLM_API_KEY"] = env["OLLAMA_API_KEY"]

    sanitized: list[str] = []
    if model_spec.startswith("ollama/"):
        effective_timeout = env.get("LLM_TIMEOUT", "").strip()
        if effective_timeout != OLLAMA_EFFECTIVE_LLM_TIMEOUT_SEC:
            env["LLM_TIMEOUT"] = OLLAMA_EFFECTIVE_LLM_TIMEOUT_SEC
            sanitized.append(f"LLM_TIMEOUT={OLLAMA_EFFECTIVE_LLM_TIMEOUT_SEC}")
        effective_attempts = env.get("LLM_MAX_GENERATE_ATTEMPTS", "").strip()
        if effective_attempts != OLLAMA_EFFECTIVE_MAX_GENERATE_ATTEMPTS:
            env["LLM_MAX_GENERATE_ATTEMPTS"] = OLLAMA_EFFECTIVE_MAX_GENERATE_ATTEMPTS
            sanitized.append(f"LLM_MAX_GENERATE_ATTEMPTS={OLLAMA_EFFECTIVE_MAX_GENERATE_ATTEMPTS}")
        effective_generate_timeout = env.get("LLM_GENERATE_TIMEOUT", "").strip()
        if effective_generate_timeout != OLLAMA_EFFECTIVE_GENERATE_TIMEOUT_SEC:
            env["LLM_GENERATE_TIMEOUT"] = OLLAMA_EFFECTIVE_GENERATE_TIMEOUT_SEC
            sanitized.append(f"LLM_GENERATE_TIMEOUT={OLLAMA_EFFECTIVE_GENERATE_TIMEOUT_SEC}")
        effective_generate_max_tokens = env.get("LLM_GENERATE_MAX_TOKENS", "").strip()
        if effective_generate_max_tokens != OLLAMA_EFFECTIVE_GENERATE_MAX_TOKENS:
            env["LLM_GENERATE_MAX_TOKENS"] = OLLAMA_EFFECTIVE_GENERATE_MAX_TOKENS
            sanitized.append(f"LLM_GENERATE_MAX_TOKENS={OLLAMA_EFFECTIVE_GENERATE_MAX_TOKENS}")
        effective_generate_json_retries = env.get("LLM_GENERATE_JSON_RETRIES", "").strip()
        if effective_generate_json_retries != OLLAMA_EFFECTIVE_GENERATE_JSON_RETRIES:
            env["LLM_GENERATE_JSON_RETRIES"] = OLLAMA_EFFECTIVE_GENERATE_JSON_RETRIES
            sanitized.append(f"LLM_GENERATE_JSON_RETRIES={OLLAMA_EFFECTIVE_GENERATE_JSON_RETRIES}")
        effective_generate_format_json = env.get("OLLAMA_GENERATE_FORMAT_JSON", "").strip()
        if effective_generate_format_json != OLLAMA_EFFECTIVE_GENERATE_FORMAT_JSON:
            env["OLLAMA_GENERATE_FORMAT_JSON"] = OLLAMA_EFFECTIVE_GENERATE_FORMAT_JSON
            sanitized.append(f"OLLAMA_GENERATE_FORMAT_JSON={OLLAMA_EFFECTIVE_GENERATE_FORMAT_JSON}")
        desired_reasoning_effort = OLLAMA_EFFECTIVE_GENERATE_REASONING_EFFORT
        if "gpt-oss" in model_spec:
            desired_reasoning_effort = OLLAMA_GPT_OSS_EFFECTIVE_GENERATE_REASONING_EFFORT
        effective_generate_reasoning_effort = env.get("OLLAMA_GENERATE_REASONING_EFFORT", "").strip().lower()
        if effective_generate_reasoning_effort != desired_reasoning_effort:
            env["OLLAMA_GENERATE_REASONING_EFFORT"] = desired_reasoning_effort
            sanitized.append(
                f"OLLAMA_GENERATE_REASONING_EFFORT={desired_reasoning_effort}"
            )
        # Apply model-specific overrides after generic defaults.
        per_model_overrides = OLLAMA_MODEL_ENV_OVERRIDES.get(model_spec, {})
        for key, value in per_model_overrides.items():
            effective_value = env.get(key, "").strip()
            if effective_value != value:
                env[key] = value
                sanitized.append(f"{key}={value}")
        if cve:
            cve_overrides = OLLAMA_CVE_ENV_OVERRIDES.get(cve, {})
            for key, value in cve_overrides.items():
                effective_value = env.get(key, "").strip()
                if effective_value != value:
                    env[key] = value
                    sanitized.append(f"{key}={value}")
            per_task_overrides: dict[str, str] = {}
            model_candidates = [model_spec]
            if model_spec.startswith("ollama/"):
                model_candidates.append(model_spec.split("/", 1)[1])
            model_alias = next(
                (alias for alias, spec in MODEL_SPECS.items() if spec == model_spec),
                None,
            )
            if model_alias:
                model_candidates.append(model_alias)
            for model_key in model_candidates:
                per_task_overrides = OLLAMA_CVE_MODEL_ENV_OVERRIDES.get((cve, model_key), {})
                if per_task_overrides:
                    break
            for key, value in per_task_overrides.items():
                effective_value = env.get(key, "").strip()
                if effective_value != value:
                    env[key] = value
                    sanitized.append(f"{key}={value}")
            if level:
                per_task_level_overrides: dict[str, str] = {}
                for model_key in model_candidates:
                    per_task_level_overrides = OLLAMA_CVE_MODEL_LEVEL_ENV_OVERRIDES.get(
                        (cve, model_key, level),
                        {},
                    )
                    if per_task_level_overrides:
                        break
                for key, value in per_task_level_overrides.items():
                    effective_value = env.get(key, "").strip()
                    if effective_value != value:
                        env[key] = value
                        sanitized.append(f"{key}={value}")

    # If caller sets OLLAMA_API_BASE in local file, avoid accidental override by
    # stale global LLM_BASE_URL from shell/session.
    if model_spec.startswith("ollama/") and "OLLAMA_API_BASE" in local_llm_env and "LLM_BASE_URL" not in local_llm_env:
        if env.get("LLM_BASE_URL"):
            env.pop("LLM_BASE_URL", None)
            sanitized.append("LLM_BASE_URL")

    if model_spec.startswith("vertex_ai/"):
        for key in ("LLM_BASE_URL", "OLLAMA_API_BASE", "OLLAMA_HOST"):
            if env.get(key):
                env.pop(key, None)
                sanitized.append(key)
    return env, _compact_sanitized_env_entries(sanitized)


def apply_service_sensitive_env_overrides(
    env: dict[str, str],
    sanitized: list[str],
    *,
    cve: str,
    model_spec: str,
    service: str,
) -> list[str]:
    """
    Apply extra env guardrails for sensitive CVEs only when using
    the standard target-vuln service.
    """
    if service != "target-vuln":
        return _compact_sanitized_env_entries(sanitized)
    if not model_spec.startswith("ollama/"):
        return _compact_sanitized_env_entries(sanitized)
    overrides = SERVICE_SENSITIVE_ENV_OVERRIDES_BY_CVE.get(cve, {})
    for key, value in overrides.items():
        normalized_value = value
        if (
            key == "OLLAMA_GENERATE_REASONING_EFFORT"
            and "gpt-oss" in model_spec
            and str(value).strip().lower() == "none"
        ):
            normalized_value = "low"
        effective_value = env.get(key, "").strip()
        if effective_value != normalized_value:
            env[key] = normalized_value
            sanitized.append(f"{key}={normalized_value}")
    return _compact_sanitized_env_entries(sanitized)


def build_combos(
    runs_root: Path,
    cves_filter: set[str],
    models_filter: set[str],
    levels_filter: set[str],
) -> tuple[list[Combo], list[str]]:
    all_cves = list_cves(runs_root)
    selected_cves = [c for c in all_cves if not cves_filter or c in cves_filter]
    if cves_filter:
        unknown = sorted(cves_filter - set(all_cves))
    else:
        unknown = []

    ordered_models = [m for m in MODEL_ORDER if m in MODEL_SPECS]
    ordered_models += [m for m in MODEL_SPECS.keys() if m not in ordered_models]
    models = [m for m in ordered_models if not models_filter or m in models_filter]
    levels = [l for l in LEVEL_ORDER if not levels_filter or l in levels_filter]

    # Global priority order:
    # 1) all L3 first, then L2, then L1, then L0
    # 2) within each level, heavier models first
    # 3) for each model, sweep all selected CVEs
    combos: list[Combo] = []
    for level in levels:
        for model_alias in models:
            for cve in selected_cves:
                seed_profiles = CVE_SEED_PROFILES.get(cve)
                if not seed_profiles:
                    combos.append(
                        Combo(
                            cve=cve,
                            model_alias=model_alias,
                            level=level,
                            max_iters=LEVEL_ITERS[level],
                            model_spec=MODEL_SPECS[model_alias],
                        )
                    )
                    continue

                for seed_profile, cfg in seed_profiles.items():
                    allowed_levels = set(cfg.get("levels", set(LEVEL_ORDER)))
                    if level not in allowed_levels:
                        continue
                    profile_level_iters = cfg.get("level_max_iters", {})
                    max_iters = int(profile_level_iters.get(level, LEVEL_ITERS[level]))
                    combos.append(
                        Combo(
                            cve=cve,
                            model_alias=model_alias,
                            level=level,
                            max_iters=max_iters,
                            model_spec=MODEL_SPECS[model_alias],
                            seed_profile=seed_profile,
                        )
                    )
    return combos, unknown


def main() -> int:
    args = parse_args()
    dry_run = not args.execute
    repo_root = Path.cwd()
    runs_root = repo_root / "runs"

    try:
        require_repo_root(repo_root)
        ensure_tools(repo_root, require_docker=not dry_run)
        ensure_repo_state_clean_for_batch(repo_root, execute=not dry_run)
    except RuntimeError as e:
        log(f"ERROR preflight: {e}")
        return 2

    if args.run_timeout_sec <= 0:
        log("ERROR preflight: --run-timeout-sec debe ser > 0")
        return 2

    local_llm_env, local_llm_env_path = load_local_llm_env(repo_root)
    if local_llm_env_path:
        log(f"INFO local-llm-env cargado: {local_llm_env_path.name}")
    else:
        log(f"INFO local-llm-env no encontrado ({LOCAL_ENV_FILENAME}); usando entorno del sistema")

    md_overrides, md_warnings = discover_markdown_policy_signals(repo_root)
    for msg in md_overrides:
        log(f"INFO md-policy aligned: {msg}")
    for msg in md_warnings:
        log(f"WARNING md-policy: {msg}")

    hardcoded_aligned, hardcoded_legacy = hardcoded_baseline_alignment_stats()
    if hardcoded_legacy:
        log(
            "WARNING baseline hardcoded contiene entradas con aliases legacy "
            f"no activos (aligned={hardcoded_aligned}, legacy={hardcoded_legacy})"
        )

    cves_filter = set(args.cve)
    models_filter = set(args.model)
    levels_filter = set(args.level)

    combos, unknown_cves = build_combos(runs_root, cves_filter, models_filter, levels_filter)
    if unknown_cves:
        log(f"WARNING CVEs no encontradas en runs/: {unknown_cves}")

    existing: list[tuple[Combo, str]] = []
    pending: list[Combo] = []
    for combo in combos:
        excluded, excluded_reason = combo_is_policy_excluded(combo)
        if excluded:
            existing.append((combo, excluded_reason))
            continue
        if combo_requires_canonical_only(combo):
            done, reason = find_existing_canonical_only_run(
                runs_root,
                combo.cve,
                combo.model_alias,
                combo.level,
                seed_profile=combo.seed_profile,
                expected_model=combo.model_spec,
                expected_max_iters=combo.max_iters,
            )
            if done:
                existing.append((combo, reason))
            else:
                pending.append(combo)
            continue
        if combo_is_forced_pending(combo):
            pending.append(combo)
            continue
        done, reason = find_existing_level_run(
            runs_root,
            combo.cve,
            combo.model_alias,
            combo.level,
            seed_profile=combo.seed_profile,
            expected_model=combo.model_spec,
            expected_max_iters=combo.max_iters,
        )
        if done:
            existing.append((combo, reason))
        else:
            if combo_in_hardcoded_baseline(combo):
                existing.append((combo, "exists-hardcoded-baseline"))
            else:
                pending.append(combo)

    log(f"Modo: {'DRY-RUN' if dry_run else 'EJECUCION REAL'}")
    log(f"Total combinaciones inspeccionadas: {len(combos)}")
    log(f"Ya existentes: {len(existing)}")
    log(f"Pendientes a ejecutar: {len(pending)}")

    state_path = runs_root / STATE_FILE
    state: dict[str, Any] = {
        "session_id": dt.datetime.now().strftime("%Y%m%d_%H%M%S"),
        "started_at": dt.datetime.now().isoformat(timespec="seconds"),
        "mode": "dry-run" if dry_run else "execute",
        "args": vars(args),
        "level_iters": LEVEL_ITERS,
        "model_specs": MODEL_SPECS,
        "combos": {},
    }
    for combo, reason in existing:
        update_combo_state(state, combo, "existing", reason)
    for combo in pending:
        update_combo_state(state, combo, "pending", "not-started")
    save_state(state_path, state)

    staged_paths: list[str] = []
    executed_ok: list[Combo] = []
    failed: list[tuple[Combo, str]] = []
    skipped: list[tuple[Combo, str]] = []
    anomalous: list[tuple[Combo, list[str], str]] = []
    generate_diag_records: list[dict[str, Any]] = []
    blocked_cves_runtime: dict[str, str] = {}

    for combo in pending:
        if combo.cve in blocked_cves_runtime:
            reason = f"runtime-cve-blocked:{blocked_cves_runtime[combo.cve]}"
            skipped.append((combo, reason))
            update_combo_state(state, combo, "skipped", reason)
            save_state(state_path, state)
            log(
                f"SKIP {combo.cve} {combo.model_alias} {combo.level} "
                f"({combo.seed_profile}) por bloqueo runtime del CVE: {blocked_cves_runtime[combo.cve]}"
            )
            continue

        model_dir = runs_root / combo.cve / combo.model_alias
        dest = canonical_dest(
            runs_root, combo.cve, combo.model_alias, combo.level, seed_profile=combo.seed_profile
        )
        source_existed_before = False
        log(
            f"Pendiente -> CVE={combo.cve} model={combo.model_alias} "
            f"level={combo.level} max_iters={combo.max_iters} seed_profile={combo.seed_profile}"
        )
        provider_failure_limit, provider_failure_limit_source = effective_provider_failure_limit(
            combo, args.provider_failure_streak_limit
        )
        if provider_failure_limit > 0:
            log(
                "INFO provider-failure-limit:"
                f"{provider_failure_limit} ({provider_failure_limit_source}) "
                f"para {combo.cve} {combo.model_alias} {combo.level}"
            )

        if dry_run:
            log(f"DRY-RUN plan: run + rename -> {dest}")
            seed_path, seed_reason = choose_seed_for_task(
                repo_root,
                combo.cve,
                combo.level,
                seed_profile=combo.seed_profile,
                auto_generate=False,
            )
            seed_fragment = f" --seed {seed_path}" if seed_path else ""
            service = resolve_service_for_combo(combo)
            cmd = (
                f"python -m agents.openhands_llm.run --task-id {combo.cve} --level {combo.level} "
                f"--max-iters {combo.max_iters} --model {combo.model_spec} "
                f"--service {service} --kill-running-containers-after-iter{seed_fragment}"
            )
            log(f"DRY-RUN run-cmd: {cmd}")
            log(f"DRY-RUN seed-policy: {seed_reason}")
            if service != "target-vuln":
                log(f"DRY-RUN service-override: {combo.cve} {combo.level} -> {service}")
            env_preview, sanitized = build_run_env(
                combo.model_spec,
                local_llm_env,
                cve=combo.cve,
                level=combo.level,
            )
            sanitized = apply_service_sensitive_env_overrides(
                env_preview,
                sanitized,
                cve=combo.cve,
                model_spec=combo.model_spec,
                service=service,
            )
            if sanitized:
                log(f"DRY-RUN env-sanitize: {','.join(sanitized)}")
            log(f"DRY-RUN mv: <new_run_dir> -> {dest}")
            log(f"DRY-RUN git add: git add -f -- {dest.relative_to(repo_root).as_posix()}")
            update_combo_state(state, combo, "planned", "dry-run")
            save_state(state_path, state)
            continue

        if not task_exists(repo_root, combo.cve):
            msg = (
                f"task-missing: tasks/{combo.cve}/task.yml "
                f"(or legacy compose+levels+seeds bundle)"
            )
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR {msg}")
            continue
        harness_ok, harness_probe = task_harness_exists(repo_root, combo.cve)
        if not harness_ok:
            msg = f"harness-missing: {harness_probe}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR {msg}")
            continue
        if harness_probe != "harness/run.sh":
            log(f"INFO harness-detected:{harness_probe} para {combo.cve}")

        seed_path, seed_reason = choose_seed_for_task(
            repo_root,
            combo.cve,
            combo.level,
            seed_profile=combo.seed_profile,
            auto_generate=True,
        )
        if seed_path is None:
            msg = f"{seed_reason}: tasks/{combo.cve}/seeds"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR {msg}")
            continue

        model_dir.mkdir(parents=True, exist_ok=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        before_dirs = {p.name for p in model_dir.iterdir() if p.is_dir()}
        source_existed_before = dest.name in before_dirs

        service = resolve_service_for_combo(combo)
        cmd = [
            sys.executable,
            "-u",
            "-m",
            "agents.openhands_llm.run",
            "--task-id",
            combo.cve,
            "--level",
            combo.level,
            "--max-iters",
            str(combo.max_iters),
            "--model",
            combo.model_spec,
            "--service",
            service,
            "--kill-running-containers-after-iter",
            "--seed",
            str(seed_path),
        ]
        run_env, sanitized_env = build_run_env(
            combo.model_spec,
            local_llm_env,
            cve=combo.cve,
            level=combo.level,
        )
        sanitized_env = apply_service_sensitive_env_overrides(
            run_env,
            sanitized_env,
            cve=combo.cve,
            model_spec=combo.model_spec,
            service=service,
        )
        if sanitized_env:
            log(f"INFO env sanitizado para {combo.model_spec}: {','.join(sanitized_env)}")
        log(f"INFO {seed_reason} para {combo.cve}")
        if service != "target-vuln":
            log(f"INFO service-override: {combo.cve} {combo.level} -> {service}")
        update_combo_state(state, combo, "running", "launched")
        save_state(state_path, state)
        try:
            run_res = run_cmd(
                cmd,
                cwd=repo_root,
                dry_run=False,
                capture_output=True,
                timeout_sec=args.run_timeout_sec,
                env=run_env,
            )
        except KeyboardInterrupt:
            msg = "keyboard-interrupt-during-run"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log("Interrupcion manual detectada (Ctrl+C). Abortando batch de forma segura.")
            break
        output = run_res.output
        provider_signals = provider_failure_signal_count(output)
        if (
            provider_failure_limit > 0
            and provider_signals >= provider_failure_limit
        ):
            msg = (
                "provider-failure-streak-limit:"
                f"{provider_signals}/{provider_failure_limit}"
            )
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(
                "ERROR posible fin de creditos/cuota proveedor: "
                f"score={provider_signals} (limite={provider_failure_limit}, "
                f"source={provider_failure_limit_source}). "
                "Abortando batch para evitar saturar salida."
            )
            break
        generate_metrics = extract_generate_diagnostics(output)
        if has_generate_diag_signal(generate_metrics):
            score = generate_diag_score(generate_metrics)
            generate_diag_records.append(
                {
                    "cve": combo.cve,
                    "model_alias": combo.model_alias,
                    "model_spec": combo.model_spec,
                    "level": combo.level,
                    "seed_profile": combo.seed_profile,
                    "score": score,
                    "metrics": generate_metrics,
                }
            )
            log(
                "WARNING generate-signal:"
                f"{combo.cve} {combo.model_alias} {combo.level} ({combo.seed_profile}) "
                f"score={score} empty={generate_metrics['empty_response_warnings']} "
                f"json={generate_metrics['json_parse_errors']} "
                f"unknown_ops={generate_metrics['unknown_mutation_ops']} "
                f"gen_fail={generate_metrics['llm_generation_failed']} "
                f"timeouts={generate_metrics['llm_timeout_errors']}"
            )
        run_anomalies = normalize_run_anomalies(
            repo_root=repo_root,
            cve=combo.cve,
            anomalies=detect_run_anomalies(output),
            output=output,
        )
        if run_res.timed_out:
            msg = f"pipeline-timeout:{args.run_timeout_sec}s"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR {msg}")
            if args.abort_on_timeout:
                log("Abortando batch por --abort-on-timeout")
                break
            continue
        if run_res.returncode == 130:
            msg = "keyboard-interrupt-during-run"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log("Interrupcion manual detectada (Ctrl+C). Abortando batch de forma segura.")
            break
        if run_res.returncode not in (0, 1):
            msg = f"pipeline-command-exit:{run_res.returncode}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR run command rc={run_res.returncode}")
            continue

        run_dir, src_reason = resolve_new_run_dir(repo_root, combo, model_dir, before_dirs, output)
        if not run_dir:
            classified = classify_pipeline_failure(output)
            if classified:
                msg = classified
                # CVE-level hard blocker in this session:
                # if Docker image build fails for a task, retrying same CVE across
                # seed profiles/models/levels is usually wasted time.
                if classified in {"pipeline-build-failed", "pipeline-images-not-ready"}:
                    blocked_cves_runtime[combo.cve] = classified
                    log(
                        f"WARNING runtime-cve-blocked:{combo.cve} "
                        f"por fallo estructural ({classified}); se omiten sus combinaciones restantes."
                    )
            else:
                msg = f"cannot-resolve-run-dir:{src_reason}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR no se pudo identificar run dir: {src_reason}")
            continue

        if "partial" in src_reason:
            if "run-dir-partial" not in run_anomalies:
                run_anomalies.append("run-dir-partial")
            if "summary-missing-or-invalid" in src_reason and "summary-missing-or-invalid" not in run_anomalies:
                run_anomalies.append("summary-missing-or-invalid")

        if not safe_relative_to(run_dir, model_dir):
            msg = f"unsafe-source-path:{run_dir}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log("ERROR fuente fuera del directorio esperado, se aborta esta combinacion")
            continue

        critical_anomalies = {"run-dir-partial", "summary-missing-or-invalid", "llm-stop-early"}
        critical_hits = [code for code in run_anomalies if code in critical_anomalies]
        if critical_hits:
            msg = f"critical-run-anomaly:{','.join(critical_hits)}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(
                "ERROR run descartada por anomalia critica: "
                f"{combo.cve} {combo.model_alias} {combo.level} -> {critical_hits}"
            )
            continue

        if run_dir.resolve() == dest.resolve() and not source_existed_before:
            rel = dest.relative_to(repo_root).as_posix()
            ok_stage, stage_reason, staged_rel_files = stage_run_files_safely(
                repo_root=repo_root,
                run_path=dest,
                max_stage_file_mb=args.max_stage_file_mb,
                dry_run=False,
            )
            if not ok_stage:
                msg = f"git-add-failed:{rel}:{stage_reason}"
                failed.append((combo, msg))
                update_combo_state(state, combo, "failed", msg)
                save_state(state_path, state)
                log(f"ERROR git add fallo: {rel}")
                continue
            staged_paths.extend(staged_rel_files)
            executed_ok.append(combo)
            if run_anomalies:
                anomalous.append((combo, run_anomalies, rel))
                update_combo_state(state, combo, "staged-anomalous", f"{rel}|{','.join(run_anomalies)}")
                log(f"WARNING run staged con comportamiento anomalo: {combo.cve} {combo.model_alias} {combo.level} -> {run_anomalies}")
            else:
                update_combo_state(state, combo, "staged", f"source-already-canonical:{rel}")
            save_state(state_path, state)
            log(f"OK source-already-canonical + git add -f {rel}")
            continue

        if dest.exists():
            dest_ok, dest_why = validate_run_dir(
                dest,
                combo.cve,
                combo.level,
                expected_model=combo.model_spec,
                expected_max_iters=combo.max_iters,
            )
            if not dest_ok and safe_relative_to(dest, model_dir):
                quarantine_name = f"{dest.name}_DISCARDED_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                quarantine_path = model_dir / quarantine_name
                try:
                    shutil.move(str(dest), str(quarantine_path))
                    log(
                        "WARNING destino canonico invalido movido a cuarentena: "
                        f"{dest.name} -> {quarantine_name} ({dest_why})"
                    )
                except Exception as q_e:
                    msg = f"quarantine-invalid-canonical-failed:{q_e}"
                    failed.append((combo, msg))
                    update_combo_state(state, combo, "failed", msg)
                    save_state(state_path, state)
                    log(f"ERROR no se pudo poner en cuarentena destino invalido: {q_e}")
                    continue
            else:
                skipped.append((combo, f"destination-exists:{dest.name}"))
                update_combo_state(state, combo, "skipped", f"destination-exists:{dest.name}")
                save_state(state_path, state)
                log(f"SKIP destino ya existe: {dest}")
                continue

        try:
            shutil.move(str(run_dir), str(dest))
            log(f"OK rename: {run_dir.name} -> {dest.name} ({src_reason})")
        except Exception as e:
            msg = f"rename-failed:{e}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR renombrado fallido: {e}")
            continue

        rel = dest.relative_to(repo_root).as_posix()
        ok_stage, stage_reason, staged_rel_files = stage_run_files_safely(
            repo_root=repo_root,
            run_path=dest,
            max_stage_file_mb=args.max_stage_file_mb,
            dry_run=False,
        )
        if not ok_stage:
            rollback_detail = "rollback-not-attempted"
            # Rollback best-effort to avoid partial state after move+add failure
            if safe_relative_to(dest, model_dir) and safe_relative_to(run_dir, model_dir) and dest.exists() and not run_dir.exists():
                try:
                    shutil.move(str(dest), str(run_dir))
                    rollback_detail = "rollback-ok"
                except Exception as rb_e:
                    rollback_detail = f"rollback-failed:{rb_e}"
            msg = f"git-add-failed:{rel}:{stage_reason}:{rollback_detail}"
            failed.append((combo, msg))
            update_combo_state(state, combo, "failed", msg)
            save_state(state_path, state)
            log(f"ERROR git add fallo: {rel}")
            continue

        staged_paths.extend(staged_rel_files)
        executed_ok.append(combo)
        if run_anomalies:
            anomalous.append((combo, run_anomalies, rel))
            update_combo_state(state, combo, "staged-anomalous", f"{rel}|{','.join(run_anomalies)}")
            log(f"WARNING run staged con comportamiento anomalo: {combo.cve} {combo.model_alias} {combo.level} -> {run_anomalies}")
        else:
            update_combo_state(state, combo, "staged", rel)
        save_state(state_path, state)
        log(f"OK git add -f {rel}")

    # Final summary (before commit/push)
    print("\n" + "=" * 78)
    print("RESUMEN")
    print("=" * 78)
    print(f"Modo: {'DRY-RUN' if dry_run else 'EJECUCION REAL'}")
    print(f"Inspeccionadas: {len(combos)}")
    print(f"Ya existentes: {len(existing)}")
    print(f"Pendientes: {len(pending)}")
    print(f"Ejecutadas OK: {len(executed_ok)}")
    print(f"Anomalas (staged): {len(anomalous)}")
    print(f"Omitidas: {len(skipped)}")
    print(f"Fallidas: {len(failed)}")
    print(f"Staged paths: {len(staged_paths)}")

    if executed_ok:
        print(f"\nCompletadas y staged ({len(executed_ok)}):")
        for combo in executed_ok:
            dest = canonical_dest(
                runs_root,
                combo.cve,
                combo.model_alias,
                combo.level,
                seed_profile=combo.seed_profile,
            )
            rel = dest.relative_to(repo_root).as_posix() if safe_relative_to(dest, repo_root) else str(dest)
            print(f"  ✔ {combo.cve} {combo.model_alias} {combo.level} -> {rel}")

    if existing:
        print(f"\nYa existentes (muestra):")
        for combo, reason in existing[:12]:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} ({combo.seed_profile}) [{reason}]")
        if len(existing) > 12:
            print(f"- ... ({len(existing) - 12} mas)")

    if skipped:
        print("\nOmitidas:")
        for combo, reason in skipped:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} ({combo.seed_profile}) [{reason}]")

    if anomalous:
        print("\nAnomalas (revisar antes de commit):")
        for combo, codes, rel in anomalous:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} ({combo.seed_profile}) [{','.join(codes)}] -> {rel}")

    if failed:
        print("\nFallidas:")
        for combo, reason in failed:
            print(f"- {combo.cve} {combo.model_alias} {combo.level} ({combo.seed_profile}) [{reason}]")

    print("\nObservabilidad GENERATE:")
    print(f"- Combos con senales: {len(generate_diag_records)}")
    print("- Persistencia de reportes: desactivada (solo consola).")
    if generate_diag_records:
        print("- Top senales (score desc):")
        ranked = sorted(generate_diag_records, key=lambda r: int(r.get("score", 0)), reverse=True)
        for rec in ranked[:10]:
            m = rec["metrics"]
            print(
                "  * "
                f"{rec['cve']} {rec['model_alias']} {rec['level']} ({rec['seed_profile']}): "
                f"score={rec['score']} "
                f"empty={m['empty_response_warnings']} json={m['json_parse_errors']} "
                f"no_mut={m['generate_no_mutations']} unknown_ops={m['unknown_mutation_ops']} "
                f"gen_fail={m['llm_generation_failed']} timeouts={m['llm_timeout_errors']} "
                f"xml_err={m['xml_parser_errors']}"
            )
    state["generate_diagnostics"] = {
        "combos_with_signal": len(generate_diag_records),
        "persisted_artifacts": False,
        "legacy_flag_no_generate_diagnostics": bool(args.no_generate_diagnostics),
    }

    if dry_run:
        print("\nComandos finales (dry-run):")
        print(f"- git commit -m \"{args.commit_message}\"")
        if args.no_push:
            print("- git push (omitido por --no-push)")
        else:
            print("- git push")
        print("\nDry-run completado. No se hicieron cambios.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "dry-run-complete"
        save_state(state_path, state)
        return 0

    # Ctrl+C outside subprocess or interrupcion general
    if failed and any(reason in {"keyboard-interrupt-during-run", "pipeline-interrupted-130"} for _, reason in failed):
        print("\nEjecucion interrumpida por usuario. NO se hara commit/push automatico.")
        if executed_ok:
            print(f"\n  ℹ {len(executed_ok)} run(s) completada(s) y staged antes de la interrupcion.")
            if anomalous:
                print(f"  WARNING: {len(anomalous)} run(s) staged con comportamiento anomalo: revisar/limpiar antes de commit.")
            print("  Puedes hacer commit manual con:")
            print(f'    git commit -m "{args.commit_message}"')
        else:
            print("\n  No habia runs completadas antes de la interrupcion.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "interrupted-by-user"
        save_state(state_path, state)
        return 130

    # No commit/push on severe errors
    if failed:
        print("\nSe detectaron fallos. Por seguridad NO se hara commit ni push.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-no-commit"
        save_state(state_path, state)
        return 1

    # If anomalous runs were staged, force manual review before commit/push.
    if anomalous:
        print("\nSe detectaron runs anomalas ya staged. Se omite commit/push automatico para revision manual.")
        print("Revisa estas rutas y, si procede, retira del stage antes de commitear:")
        print("  git restore --staged <ruta>")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "anomalous-no-auto-commit"
        save_state(state_path, state)
        return 3

    # Commit and push once at the end
    rc_diff = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    ).returncode
    if rc_diff == 0:
        print("\nNo hay cambios staged. Se omite commit/push.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "no-staged-changes"
        save_state(state_path, state)
        return 0

    staged_now = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=str(repo_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if staged_now.returncode != 0:
        print("\nERROR: no se pudo leer staged final. Abortando commit.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-read-staged"
        save_state(state_path, state)
        return 1
    unexpected = []
    for p in [ln.strip() for ln in staged_now.stdout.splitlines() if ln.strip()]:
        if not p.startswith("runs/"):
            unexpected.append(p)
        if p == f"runs/{STATE_FILE}":
            unexpected.append(p)
    if unexpected:
        print("\nERROR: staged contiene rutas fuera de runs/. Abortando commit por seguridad.")
        print(f"Rutas inesperadas: {unexpected[:20]}")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-contaminated-staged"
        save_state(state_path, state)
        return 1

    commit_res = run_cmd(
        ["git", "commit", "-m", args.commit_message],
        cwd=repo_root,
        dry_run=False,
        capture_output=True,
    )
    if commit_res.returncode != 0:
        print("\nERROR: fallo el commit final. Revisa estado y haz commit manual.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-commit"
        save_state(state_path, state)
        return 1

    if args.no_push:
        print("\nCommit final hecho. Push omitido por --no-push.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "commit-only"
        save_state(state_path, state)
        return 0

    push_res = run_cmd(["git", "push"], cwd=repo_root, dry_run=False, capture_output=True)
    if push_res.returncode != 0:
        print("\nERROR: fallo el push final. El commit local quedo hecho.")
        state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
        state["final_status"] = "failed-push"
        save_state(state_path, state)
        return 1

    print("\nCommit + push final completados.")
    state["finished_at"] = dt.datetime.now().isoformat(timespec="seconds")
    state["final_status"] = "success"
    save_state(state_path, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())

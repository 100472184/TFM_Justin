# Pipeline and Auto-Scheduler Technical Reference (2026-05-14)

- Generated on: 2026-05-14T16:02:21
- Scope: `agents/openhands_llm` runtime pipeline + `scripts/run_pending_models.py` automation.
- Goal: document how the system works today, why recent decisions were made, and what controls affect reproducibility/throughput.

## 1. System Components

| Component | Path | Responsibility |
|---|---|---|
| Core iterative pipeline | `agents/openhands_llm/src/pipeline.py` | Orchestrates ANALYZE -> GENERATE -> VERIFY loop per CVE run. |
| LLM client adapter | `agents/openhands_llm/src/openhands_client.py` | Handles model requests, retries, JSON parsing/repair, Ollama/Gemini quirks. |
| Mutation prompt | `agents/openhands_llm/prompt_templates/generate.j2` | Defines strict JSON/mutation contract and strategy constraints sent to models. |
| Auto scheduler/batch runner | `scripts/run_pending_models.py` | Selects pending combos, applies policy guards, executes runs, stages artifacts, controls commit/push flow. |
| Task definitions | `tasks/<CVE>/...` | Build/run harness, seeds, and level context per CVE. |
| Output artifacts | `runs/<CVE>/<model_alias>/<Lx_CVE>/...` | Iteration-level artifacts and final `summary.json`/`run_report.md`. |

## 2. End-to-End Execution Flow

1. Scheduler builds the candidate matrix (`CVE x model x level`) with configured priorities.
2. Scheduler filters out existing and excluded combos using canonical validation and baseline state.
3. For each pending combo, scheduler launches `python -m agents.openhands_llm.run ...` with sanitized env.
4. Pipeline executes iterative loop:
   - ANALYZE: model produces vulnerability strategy summary.
   - GENERATE: model returns JSON mutation plan, with retries/repair when malformed.
   - VERIFY: mutated seed tested against vulnerable and fixed images, with differential oracle.
5. Scheduler validates produced run directory, renames to canonical `Lx_<CVE>`, and stages files.
6. Scheduler updates run state file (`runs/.run_pending_models_state.json`) throughout lifecycle.
7. On completion/interruption, scheduler emits campaign summary and optional commit/push actions.

## 3. Model/Level Strategy in Scheduler

### 3.1 Levels and budgets

- Defined in `LEVEL_ITERS` (`L3=15`, `L2=30`, `L1=45`, `L0=50`).
- Higher context level receives lower iteration budget because expected success probability is higher.

### 3.2 Active model set

- `glm-5.1`, `qwen3-coder-next`, `gpt-oss-20b`, `ministral-3-8b`.
- Execution priority (`MODEL_ORDER`): `glm-5.1` -> `qwen3-coder-next` -> `gpt-oss-20b` -> `ministral-3-8b`.
- Level sweep order (`LEVEL_ORDER`): `L3`, `L2`, `L1`, `L0` (high-context-first throughput policy).

### 3.3 Baseline skip mechanism

- `HARDCODED_EXISTING_COMBOS` is an explicit skip list for already validated combos.
- Used to avoid rescheduling when host `runs/` is not fully synchronized (common Kali/Windows split workflow).
- New combos are appended only after structural and completion validity checks.

## 4. Seed Policy and Special Cases

### 4.1 Seed discovery

- Seed candidates include `base.*`, `seed.*`, plus specific known names (`seed_pipeline.xml`).
- Optional text-first preference exists for text argument tasks.

### 4.2 Locked seed enforcement

- `LOCKED_BASE_SEEDS` pins known-good historical seeds by filename+sha256 for reproducibility parity.
- Important for CVEs where mutation success is highly seed-shape dependent.

### 4.3 CVE-level seed mode override (json-c)

- `SEED_OVERRIDE_BY_CVE_LEVEL` for `CVE-2021-32292_jsonc`:
  - `L0/L1`: open seed (`base.json`, prefix `{"a":"`).
  - `L2/L3`: closed seed (`seed.json`, prefix `{"a":""}`).
- This preserves methodological comparability with historical Gemini open-seed findings.

### 4.4 Service override case

- `SERVICE_OVERRIDES_BY_CVE_LEVEL` sets `CVE-2023-29469_libxml2` at `L3` to `target-vuln-direct`.
- Fixed-side service pairing is auto-derived in pipeline (`target-fixed-direct`).

## 5. Exclusions, Quarantine, and Policy Signals

### 5.1 Hard exclusions

- `EXCLUDED_CVES` currently includes:
  - `CVE-2016-5314_libtiff` (`reproduction-unreliable`).
  - `CVE-2023-29469_libxml2` (`temporary-quarantine-libxml2-2026-05-13`).
  - `CVE-2024-57970_libarchive` (`temporary-quarantine-libarchive-2026-05-13`).

### 5.2 Markdown-policy introspection

Scheduler scans high-signal docs and emits alignment warnings:

- `justification_L2_vs_L3.md` for harness override consistency.
- `reproduction_analysis.md` for exclusion policy alignment.
- `ORACLE_BROKEN.md` as warning signal before large campaign scheduling.

This creates a governance loop where method notes can be detected and enforced in automation.

## 6. Run Validity Semantics (Critical)

Validation logic in scheduler is intentionally strict and now central to campaign integrity:

1. `summary.json` must exist and match expected CVE/level/model/max-iters.
2. Minimal run structure must exist (`iter_*` count coherent with `total_iters`).
3. Completion rule must hold:
   - success-early (`success=true`), or
   - full-budget failure (`total_iters >= max_iters`).

Practical effect: partial runs, interrupted artifacts, and early-stop false completions are kept out of canonical baseline.

## 7. Anomaly Detection and Failure Taxonomy

Scheduler classifies failures and anomalies from output text to prevent silent contamination.

### 7.1 Failure classes (examples)

- `pipeline-build-failed`
- `pipeline-images-not-ready`
- `pipeline-seed-not-found`
- `pipeline-container-start-failed`
- `pipeline-container-permission-denied`
- `pipeline-vertex-api-base-leak`

### 7.2 Runtime anomalies (examples)

- `seed-nul-rejected`
- `harness-seed-not-found`
- `harness-target-not-executable`
- `vertex-api-base-leak`
- `llm-stop-early`
- container runtime anomalies

Critical anomalies are blocked from normal "completed+staged" flow.

## 8. LLM I/O Reliability Controls

### 8.1 Scheduler-side env sanitization

For Ollama runs, scheduler enforces effective values such as:

- `LLM_TIMEOUT=180`
- `LLM_MAX_GENERATE_ATTEMPTS=6`
- `LLM_GENERATE_TIMEOUT=90`
- `LLM_GENERATE_MAX_TOKENS=2200`
- `LLM_GENERATE_JSON_RETRIES=2`
- `OLLAMA_GENERATE_FORMAT_JSON=0`
- Reasoning effort policy with `gpt-oss` override (`medium` currently).

### 8.2 Client-side JSON robustness (`completion_json`)

- Exponential backoff retries.
- Schema-specific timeout/max-token overrides (`LLM_<SCHEMA>_*`).
- Optional Ollama JSON mode fallback path.
- Empty-response detection and fallback completion without `format=json`.
- Multi-step response cleanup: fence stripping, comment stripping, trailing comma repair, control-char escape, invalid-backslash repair, numeric expression normalization.
- Optional `ast.literal_eval` fallback for Python-like JSON-ish outputs.

### 8.3 gpt-oss "think" compatibility

Recent incident pattern:

- `none` and string `false` were rejected by endpoint in some runs (`invalid think value`).
- `low/medium/high/max` are accepted values for `gpt-oss` compatibility path.
- Current scheduler policy sets `OLLAMA_GPT_OSS_EFFECTIVE_GENERATE_REASONING_EFFORT=medium`.

Net effect: failures shifted from hard parameter rejection to normal mutation/guard quality issues, which are recoverable.

## 9. Task-Specific Deterministic Guardrails

`pipeline.py` includes CVE-specific seed guards where trigger envelopes are well defined.

Example: `CVE-2021-32292_jsonc` guard enforces:

- extension `.json`,
- seed size range `32768..65536`,
- L0/L1 open-prefix `{"a":"`,
- first NUL byte exactly at offset `32767`.

This is intentionally model-agnostic and reduces low-signal invalid mutations.

## 10. Git Safety and Batch State Guarantees

Scheduler provides transactional safety around batch runs:

- Refuses execute mode when pre-existing staged changes are present.
- Stores per-combo and campaign status in `runs/.run_pending_models_state.json`.
- On file-move/stage errors, performs best-effort rollback to avoid partial state drift.
- Auto-commit/push is skipped on interruption, anomalies, or contamination checks.

## 11. Why Current Decisions Were Taken

### 11.1 Throughput protection

- Quarantine of low-signal CVEs (`libxml2`, `libarchive`) prevents queue starvation.
- Strong completion/structure validation prevents fake "done" states.

### 11.2 Reproducibility protection

- Seed locks and per-level overrides maintain methodological parity across models.
- Canonical naming + hardcoded validated baseline stabilize reruns across machines.

### 11.3 Model compatibility protection

- Env sanitization and client normalization mitigate endpoint-specific behavior changes (timeouts, empty JSON, think parameter incompatibility).

## 12. Operational Runbook (Current Recommended Defaults)

1. Keep scheduler defaults for generate robustness (`attempts=6`, `json_retries=2`, `max_tokens=2200`).
2. Keep `gpt-oss` reasoning at `medium` unless a controlled A/B experiment says otherwise.
3. Use clean validity policy before adding to hardcoded baseline.
4. Keep quarantined CVEs excluded until task-specific oracle/guard improvements are merged.
5. Pull/rebase frequently and avoid carrying local unstaged changes during long batches.

## 13. Open Risks and Known Gaps

- Cross-period comparability: some Gemini runs used different historical budgets/guards.
- Large hardcoded baseline set can drift if not periodically revalidated against canonical dirs.
- Some CVEs still depend on oracle quality more than mutation strategy quality.
- Mixed OS workflows (Windows/Kali) increase conflict risk in `scripts/run_pending_models.py` unless pull discipline is strict.

## 14. Appendix: Key Files to Read First

- `scripts/run_pending_models.py`
- `agents/openhands_llm/src/pipeline.py`
- `agents/openhands_llm/src/openhands_client.py`
- `agents/openhands_llm/prompt_templates/generate.j2`
- `runs/new_approach.md`
- `runs/new_approach_2026-05-12_batch_audit.md`
- `runs/CVE-2021-32292_jsonc/gemini-2.0-flash/experiment_report.md`
- `runs/CVE-2025-26623_exiv2/gemini-2.5-flash/CVE-2025-26623_exiv2_consolidated_findings_2026-04-11.md`
- `tasks/CVE-2024-57970_libarchive/ORACLE_BROKEN.md`
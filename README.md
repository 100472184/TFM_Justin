# Evaluating Large Language Models for Automated Software Exploit Generation

This repository contains the implementation, experimental artifacts, and evaluation framework developed for the Master's Thesis:

**Evaluating Large Language Models for Automated Software Exploit Generation**

Author: Justin López Benítez  
Supervisor: Lorena González Manzano  
Universidad Carlos III de Madrid

---

## Overview

Software vulnerabilities are often documented through security alerts, bug reports, patches, and technical notes. However, reproducing those vulnerabilities in a controlled environment remains a challenging task.

This project evaluates whether Large Language Models (LLMs) can assist in automated exploit generation by proposing input mutations that trigger known vulnerabilities. Unlike many previous approaches, success is not determined by the model itself. Every candidate input is validated through real execution against both vulnerable and fixed versions of the target software.

The framework combines:

- OpenHands as the agent execution environment
- Multiple frontier and open-source LLMs
- Docker-based reproducible environments
- Differential verification through vulnerable/fixed program comparison
- Automated campaign scheduling and result collection

---

## Evaluated Models

The following models were evaluated:

- gemini-3-flash-preview
- deepseek-v4-pro
- glm-5.1
- qwen3-coder-next
- gpt-oss-20b
- ministral-3-8b

---

## Evaluation Workflow

The general workflow is:

1. Select a CVE reproduction task.
2. Provide a seed input and task context.
3. The LLM analyzes the task.
4. The LLM proposes structured mutations.
5. Mutations are validated and applied.
6. The candidate input is executed against:
   - Vulnerable version
   - Fixed version
7. A differential oracle determines success.
8. If unsuccessful, verification history is added and the process repeats until the iteration budget is exhausted.

```
Task Context + Seed
        |
        v
     ANALYZE
        |
        v
     GENERATE
        |
        v
Apply Mutations + Guards
        |
        v
  Vulnerable Execution
        |
        +------+
               |
               v
     Differential Oracle
               ^
               |
        +------+
        |
  Fixed Execution
        |
        v
 Success / Continue
```

---

## Information Levels

Four information levels are supported:

| Level | Information Available |
|---------|---------|
| L0 | Seed only |
| L1 | Vulnerability description |
| L2 | Description + stack trace |
| L3 | Description + stack trace + patch |

These levels simulate progressively more realistic vulnerability disclosure scenarios.

---

## Repository Structure

```text
agents/
├── openhands_llm/

docs/
├── methodology.md
├── info_levels.md

scripts/
├── run_pending_models.py
├── lib/

tasks/
├── CVE-*/

conclusions_tfm/
├── context.md
├── models.md
├── special_cases.md
```

---

## Running an Experiment

Example:

```bash
python scripts/run_pending_models.py
```

The scheduler automatically:

- Loads pending tasks
- Selects the appropriate model
- Launches OpenHands
- Executes the mutation loop
- Stores artifacts and logs
- Generates summary reports

---

## Verification Strategy

A run is considered successful only when:

1. The generated input triggers the vulnerability in the vulnerable version.
2. The same input does not trigger the vulnerability in the fixed version.

This differential verification strategy reduces false positives and prevents the model from self-reporting success.

---

## Reproducibility

To improve reproducibility:

- All executions run inside Docker containers.
- Vulnerable and fixed versions are isolated.
- Verification is execution-based.
- Results are stored as structured artifacts.
- Campaign summaries are generated automatically.

---

## Thesis Contributions

This work provides:

- A reproducible framework for CVE reproduction.
- An evaluation of six LLMs under identical conditions.
- A comparison across four information disclosure levels.
- An execution-verified methodology based on differential oracles.
- An analysis of model performance across multiple real-world vulnerabilities.

---

## Disclaimer

This repository is intended exclusively for academic and research purposes.

The evaluated vulnerabilities are executed in isolated environments and are used solely to study automated vulnerability reproduction and exploit generation techniques.

Do not use this framework against systems without explicit authorization.

---

## Citation

If you use this repository, please cite:

```text
Justin López Benítez.
Evaluating Large Language Models for Automated Software Exploit Generation.
Master's Thesis.
Universidad Carlos III de Madrid.
2026.
```

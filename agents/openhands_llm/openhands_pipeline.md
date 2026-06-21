# OpenHands Pipeline - Technical Methodology

## 🎯 Overview

This pipeline implements an LLM-guided seed generation system designed to trigger vulnerabilities in real CVEs. Unlike traditional fuzzing (brute force), the LLM acts as a "strategic assistant" that proposes intelligent mutations based on analysis of vulnerable code.

## 🔄 Pipeline Architecture

### Iterative Loop: ANALYZE → GENERATE → VERIFY

```
┌─────────────────────────────────────────────────────────────┐
│                     INITIALIZATION                          │
│  - Load task context (levels L0-L3)                        │
│  - Load/generate initial seed                              │
│  - Setup run directory                                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: ANALYZE                         │
│  Input:  Task context + verify_history                     │
│  LLM:    Analyze vulnerability characteristics             │
│  Output: {summary, hypotheses, input_strategy, stop_early} │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │  stop_early? │──Yes──► EXIT (no solution)
                     └──────────────┘
                            │ No
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   PHASE 2: GENERATE                         │
│  Input:  analysis + current_seed + verify_history          │
│  LLM:    Propose byte-level mutations                      │
│  Output: {mutations: [...], rationale}                     │
│  Apply:  mutations.py applies ops to seed                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 3: VERIFY                          │
│  Run:    python -m scripts.bench run <task> --seed <file>  │
│  Oracle: Detect sanitizer keywords in stderr/stdout        │
│  Output: {exit_code, stdout, stderr, success_signal}       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ success? OR  │──Yes──► EXIT (success!)
                     │ max_iters?   │
                     └──────────────┘
                            │ No
                            │
                            └──► LOOP to ANALYZE (with updated history)
```

## 📊 Information Levels (Context Levels)

The pipeline supports 4 context levels for the LLM:

| Level | Description | Files included |
|-------|-------------|----------------|
| **L0** | Basic | `description.txt` |
| **L1** | + Patch | L0 + `patch.diff` |
| **L2** | + Vulnerable file | L1 + `vulnerable_file.txt` |
| **L3** | + Full context | L2 + `harness_code.txt`, `docs.txt`, `build_commands.txt` |

**Recommendation**: Use L3 for best results, L0-L1 only for quick tests.

### Context loading example (L3)

```python
context = {
    "sections": [
        {"filename": "description.txt", "content": "CVE-2023-4863..."},
        {"filename": "patch.diff", "content": "diff --git..."},
        {"filename": "vulnerable_file.txt", "content": "// libwebp code..."},
        {"filename": "harness_code.txt", "content": "#!/bin/bash..."},
        {"filename": "docs.txt", "content": "Additional notes..."}
    ]
}
```

## 🔧 Mutation Operations

The LLM proposes mutations in JSON format which are applied by `mutations.py`:

### 1. append_bytes

Appends bytes to the end of the seed.

```json
{"op": "append_bytes", "hex": "deadbeef"}
```

**Typical use**: Extend files, add malformed chunks.

### 2. flip_bit

Flips a specific bit at an offset.

```json
{"op": "flip_bit", "offset": 123, "bit": 5}
```

- `offset`: position in bytes (0-indexed)
- `bit`: bit index within the byte (0-7, where 7 is MSB)

**Typical use**: Corrupt flags, magic numbers, checksums.

### 3. overwrite_range

Replaces bytes at a specific offset.

```json
{"op": "overwrite_range", "offset": 10, "hex": "cafebabe"}
```

**Typical use**: Modify headers, sizes, offsets in file structures.

### 4. truncate

Shortens the seed to a new length.

```json
{"op": "truncate", "new_len": 200}
```

**Typical use**: Test handling of incomplete/truncated files.

### 5. repeat_range

Repeats a byte range N times.

```json
{"op": "repeat_range", "offset": 20, "length": 40, "times": 3}
```

**Typical use**: Create inputs with repeated data (DoS, heap exhaustion).

### Security Constraints

- **MAX_SEED_SIZE**: 1 MB (avoid local DoS)
- **Strict validation**: All offsets/ranges are verified before applying
- **No RCE**: Mutations limited to byte manipulation, no shellcode generation

## 🎨 Prompt Templates (Jinja2)

### analyze.j2

**Purpose**: The LLM analyzes the CVE and the current pipeline state.

**Inputs**:
- `task_id`: CVE identifier
- `level`: Information level (L0-L3)
- `iteration`: Current iteration
- `max_iters`: Maximum iterations
- `context`: Dictionary with context sections
- `verify_history`: List of last 3 VERIFY results

**Expected output**:
```json
{
  "summary": "Buffer overflow in libwebp when processing oversized VP8X chunks",
  "hypotheses": [
    "The crash occurs when the 'canvas_width' field exceeds MAX_CANVAS_SIZE",
    "Size validation fails for values near UINT32_MAX"
  ],
  "input_strategy": {
    "file_type_guess": "WebP",
    "mutation_focus": ["VP8X chunk", "canvas dimensions", "chunk size field"]
  },
  "stop_early": false
}
```

**`stop_early` logic**:
- `true`: If the LLM determines there's no way to trigger the CVE with seed mutations
- `false`: Continue iterating

### generate.j2

**Purpose**: The LLM proposes concrete mutations based on the analysis.

**Inputs**:
- `task_id`: CVE identifier
- `iteration`: Current iteration
- `analysis`: Output from the ANALYZE phase
- `seed_length`: Current seed size in bytes
- `seed_preview`: First 256 bytes in hexadecimal
- `verify_history`: List of last 3 results

**Expected output**:
```json
{
  "mutations": [
    {"op": "overwrite_range", "offset": 12, "hex": "ffffffff"},
    {"op": "flip_bit", "offset": 30, "bit": 7}
  ],
  "rationale": "Overwrite canvas_width field with UINT32_MAX and corrupt validation bit"
}
```

**Recommended strategy for the LLM**:
- **1-5 mutations per iteration**: Incremental, not drastic
- **Build on verify_history**: Don't repeat mutations that already failed
- **Consider file format**: Headers, chunks, metadata

### verify.j2 (optional)

**Purpose**: The LLM interprets benchmark results and suggests adjustments.

**Inputs**:
- `task_id`: CVE identifier
- `iteration`: Current iteration
- `exit_code`: Benchmark exit code
- `success_signal`: Bool indicating if crash was detected
- `stdout_preview`: First 2000 chars of stdout
- `stderr_preview`: First 2000 chars of stderr

**Expected output**:
```json
{
  "interpretation": "AddressSanitizer detected heap-buffer-overflow in ReadVP8XChunk+0x42",
  "next_steps": [
    "Try more extreme values in canvas_height as well",
    "Test width/height combinations that cause integer overflow"
  ],
  "confidence": "high"
}
```

**Note**: This output does NOT affect pipeline logic, it's only added to context for the next ANALYZE iteration.

## 🔍 Detection Oracle

The pipeline detects crashes/sanitizers through keyword searching:

```python
CRASH_KEYWORDS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "heap-use-after-free",
    "SEGV",
    "SIGSEGV",
    "SIGABRT",
    "double-free",
    "use-after-free",
    "out-of-bounds",
    "ASAN",
    "UBSAN"
]
```

**Function**: `detect_success_signal(stdout, stderr, exit_code) -> bool`

**Returns `True` if**:
- Any keyword appears in stdout OR stderr (case-insensitive)
- The exit_code indicates crash (typically != 0, but depends on harness)

**Benchmark integration**:
```python
result = subprocess.run(
    ["python", "-m", "scripts.bench", "run", task_id, 
     "--service", service, "--seed", seed_path],
    capture_output=True,
    text=True,
    timeout=300
)
success = detect_success_signal(result.stdout, result.stderr, result.returncode)
```

## 💾 Persistence and Logs

### runs/ directory structure

```
runs/
└── {timestamp}_{task_id}/
    └── {task_id}/
        ├── iter_001/
        │   ├── seed.bin          # Mutated seed for this iteration
        │   ├── command.txt       # Exact command executed
        │   ├── analysis.json     # ANALYZE output
        │   ├── generate.json     # GENERATE output
        │   └── verify.json       # VERIFY output (stdout, stderr, exit_code)
        ├── iter_002/
        │   └── ...
        └── summary.json          # Final execution summary
```

### summary.json format

```json
{
  "task_id": "CVE-2023-4863_libwebp",
  "level": "L3",
  "max_iters": 10,
  "total_iters": 7,
  "success": true,
  "success_iter": 7,
  "run_dir": "runs/20250202_143022_CVE-2023-4863_libwebp/CVE-2023-4863_libwebp",
  "timestamp": "20250202_143022"
}
```

### verify.json format (per iteration)

```json
{
  "exit_code": 1,
  "stdout": "Processing input file...\n...",
  "stderr": "=================================================================\n==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7f1234567890...",
  "success_signal": true,
  "timestamp": "2025-02-02T14:30:45"
}
```

## 🔐 Security Considerations

### 1. Ethical Research Only

- **Empty seeds by default**: The `tasks/*/seeds/` directories do NOT contain exploits
- **No RCE**: The pipeline does NOT generate shellcode or offensive payloads
- **Docker isolation**: All tests run in isolated containers

### 2. Rate Limiting

- **LLM_TIMEOUT**: Prevents LLM calls from hanging indefinitely
- **LLM_NUM_RETRIES**: Retry limit for errors
- **MAX_SEED_SIZE**: 1 MB maximum to avoid local DoS

### 3. Prompt Safety

The Jinja2 templates include explicit disclaimers:

```
**IMPORTANT RULES:**
- This is for controlled vulnerability research in isolated containers
- Do NOT provide exploit code or offensive payloads
- Focus on seed mutation strategies to trigger crashes/sanitizers
```

## 🧪 Use Cases

### 1. Guided fuzzing for known CVEs

**Objective**: Validate that a CVE is reproducible with an automatically generated seed.

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2023-4863_libwebp ^
    --level L3 ^
    --max-iters 20
```

### 2. LLM model comparison

**Objective**: Evaluate which model generates better seeds.

```powershell
# Local LLaMA 3
LLM_MODEL=ollama/llama3 python -m agents.openhands_llama3.run --task-id ...

# GPT-4o
LLM_MODEL=gpt-4o python -m agents.openhands_llama3.run --task-id ...

# Gemini
LLM_MODEL=gemini/gemini-1.5-pro python -m agents.openhands_llama3.run --task-id ...
```

Compare:
- Success rate (% of tasks that trigger the CVE)
- Iterations needed until first crash
- Quality of analysis in `analysis.json`

### 3. Information level benchmarking

**Objective**: Determine if more context improves results.

```powershell
# L0 (minimum context)
python -m agents.openhands_llama3.run --task-id ... --level L0 --max-iters 50

# L3 (maximum context)
python -m agents.openhands_llama3.run --task-id ... --level L3 --max-iters 50
```

Compare success rates and convergence speed.

### 4. Patch verification

**Objective**: Confirm that the patched version does NOT crash with the same seed.

```powershell
# 1. Generate seed with target-vuln
python -m agents.openhands_llama3.run ^
    --task-id CVE-2023-4863_libwebp ^
    --service target-vuln ^
    --max-iters 10

# 2. If successful, copy the seed from the successful iter
copy runs\<timestamp>\<task>\iter_007\seed.bin exploit_seed.bin

# 3. Test against target-fixed
python -m scripts.bench run CVE-2023-4863_libwebp ^
    --service target-fixed ^
    --seed exploit_seed.bin
```

**Expected result**: `target-fixed` should return exit_code=0 without crashes.

## 🚧 Limitations

### 1. LLMs are not fuzzing experts

- **Imprecise hypotheses**: The LLM may propose mutations based on incorrect assumptions
- **Lack of precise feedback**: Only sees stdout/stderr, not the internal process state
- **Training biases**: May favor common patterns over edge cases

### 2. Context dependency

- **L0/L1**: Very little context → random mutations
- **L2/L3**: Significant improvement, but requires quality documentation

### 3. Limited CVE types

This approach works best for:
- **Memory corruption**: Buffer overflows, use-after-free, double-free
- **Logic errors**: Incorrect validations, integer overflows

**Does NOT work well for**:
- **Race conditions**: Require precise timing, not just malformed inputs
- **Side-channel attacks**: Outside the scope of traditional fuzzing

## 🔮 Future Improvements

### 1. Improved feedback loop

- **Stacktrace symbolization**: Pass the LLM exact lines of code where crashes occur
- **Code coverage**: Instrument with gcov/llvm-cov to guide the LLM

### 2. Multi-agent

- **ANALYZE agent**: Specialized in code analysis
- **GENERATE agent**: Specialized in fuzzing strategies
- **VERIFY agent**: Interprets sanitizer outputs

### 3. Learning from history

- Store in database which mutations worked for similar CVEs
- Use embeddings to find patterns in successful CVEs

### 4. Prompt optimization

- A/B testing of different templates
- Fine-tuning models on CVE + successful seed datasets

## 📚 References

### Relevant Papers

- **"Fuzzing with LLMs"** (multiple recent works in 2023-2024)
- **"ChatGPT for Vulnerability Discovery"** - Analysis of current capabilities
- **"PwnGPT"** - Inspiration for this pipeline

### Related Tools

- **AFL++**: Traditional fuzzer with mutation strategies
- **LibFuzzer**: In-process fuzzing (LLVM)
- **Syzkaller**: Linux kernel syscall fuzzer

### Datasets

- **OSS-Fuzz**: Bugs found in open source projects
- **CVE Details**: CVE database
- **Exploit-DB**: Published exploits (PoC)

## 📄 License

MIT License - This pipeline is for academic research and security education.

**DISCLAIMER**: The use of this tool for malicious activities is the sole responsibility of the user. The authors are not responsible for misuse.

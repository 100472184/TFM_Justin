# OpenHands LLM Pipeline for TFM-Justin

Automated pipeline for CVE vulnerability analysis and seed generation using LLMs (local LLaMA 3 or other models).

## 🎯 Objective

Implement an iterative **ANALYZE → GENERATE → VERIFY** loop that leverages an LLM to:

1. **ANALYZE**: Analyze the CVE vulnerability and task context
2. **GENERATE**: Propose seed mutations based on the analysis
3. **VERIFY**: Execute the benchmark and verify if the vulnerability was triggered

The LLM acts as an intelligent "fuzzing assistant" that proposes strategic mutations instead of brute-force approaches.

## 📋 Requirements

### Python 3.12+ (IMPORTANT)

OpenHands SDK requires Python 3.12 or higher. **DO NOT use the same environment as the base repository**.

```powershell
# Create separate environment for OpenHands
python -m venv .venv-oh
.venv-oh\Scripts\activate

# Install dependencies
pip install -r requirements-openhands.txt
```

### Ollama + LLaMA 3 (Recommended for local deployment)

1. Download and install Ollama: https://ollama.ai/download
2. Open terminal and run:

```powershell
# Pull LLaMA 3 model
ollama pull llama3

# Start server (default port 11434)
ollama serve
```

3. Verify installation:

```powershell
ollama run llama3 "Hello"
```

### Docker Desktop

Required to run task containers:

```powershell
# Verify installation
docker --version
docker compose version
```

## ⚙️ Configuration

### 1. Copy configuration file

```powershell
cp agents\openhands_llama3\config\example.env agents\openhands_llama3\.env
```

### 2. Edit `.env` according to your LLM provider

#### For local LLaMA 3 (Ollama):

```bash
LLM_MODEL=ollama/llama3
LLM_BASE_URL=http://localhost:11434
LLM_TIMEOUT=120
LLM_NUM_RETRIES=3
```

#### For OpenAI GPT-4:

```bash
LLM_MODEL=gpt-4o
LLM_API_KEY=sk-...
LLM_BASE_URL=https://api.openai.com/v1
LLM_TIMEOUT=60
LLM_NUM_RETRIES=3
```

#### For Google Gemini:

```bash
LLM_MODEL=gemini/gemini-1.5-pro
LLM_API_KEY=...
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta
LLM_TIMEOUT=60
LLM_NUM_RETRIES=3
```

### 3. Build Docker image for the task

```powershell
# Example: CVE-2023-4863_libwebp
python -m scripts.bench build CVE-2023-4863_libwebp
```

## 🚀 Usage

### Basic command

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2023-4863_libwebp ^
    --level L3 ^
    --max-iters 10 ^
    --service target-vuln
```

### Parameters

- `--task-id`: CVE task ID (required)
  - Example: `CVE-2023-4863_libwebp`, `CVE-2023-52425_expat`, etc.
  
- `--level`: Information level for the LLM (default: L3)
  - `L0`: Basic CVE description
  - `L1`: + Patch/diff
  - `L2`: + Vulnerable file
  - `L3`: + Complete context (harness, docs)
  
- `--max-iters`: Maximum iterations (default: 10)
  
- `--service`: Docker service to test (default: target-vuln)
  - `target-vuln`: Vulnerable version
  - `target-fixed`: Patched version (sanity check)
  
- `--seed`: Initial seed file (optional)
  - If not provided, a random seed will be generated

### Examples

#### 1. Basic analysis with 5 iterations

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2023-4863_libwebp ^
    --level L2 ^
    --max-iters 5
```

#### 2. Use custom seed

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2024-57970_libarchive ^
    --level L3 ^
    --max-iters 15 ^
    --seed myseeds\archive.tar
```

#### 3. Verify that the patch works (target-fixed)

```powershell
python -m agents.openhands_llama3.run ^
    --task-id CVE-2023-52425_expat ^
    --level L3 ^
    --max-iters 5 ^
    --service target-fixed
```

## 📊 Output Structure

Each execution creates a directory in `runs/`:

```
runs/
└── 20250202_143022_CVE-2023-4863_libwebp/
    └── CVE-2023-4863_libwebp/
        ├── iter_001/
        │   ├── seed.bin          # Mutated seed
        │   ├── command.txt       # Executed command
        │   ├── analysis.json     # ANALYZE output
        │   ├── generate.json     # GENERATE output
        │   └── verify.json       # VERIFY output
        ├── iter_002/
        │   └── ...
        └── summary.json          # Execution summary
```

### `summary.json` file

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

## 🔍 Result Verification

### 1. View benchmark output

```powershell
type runs\20250202_143022_CVE-2023-4863_libwebp\CVE-2023-4863_libwebp\iter_007\command.txt
```

### 2. Inspect proposed mutations

```powershell
type runs\20250202_143022_CVE-2023-4863_libwebp\CVE-2023-4863_libwebp\iter_007\generate.json
```

Example:

```json
{
  "mutations": [
    {"op": "overwrite_range", "offset": 12, "hex": "ffffffff"},
    {"op": "flip_bit", "offset": 30, "bit": 7}
  ],
  "rationale": "Corrupting WebP chunk size to trigger overflow"
}
```

### 3. View sanitizer output

Benchmark logs are in the `.json` files for each iteration:

```powershell
type runs\...\iter_007\verify.json | jq .stderr
```

## 🐛 Troubleshooting

### Error: "OpenHands SDK not found"

```powershell
# Make sure you're in the correct environment
.venv-oh\Scripts\activate
pip install -r requirements-openhands.txt
```

### Error: "Connection refused to Ollama"

```powershell
# Verify that Ollama is running
ollama serve

# In another terminal, verify connectivity
curl http://localhost:11434/api/tags
```

### Error: "Task not found"

```powershell
# List available tasks
python -m scripts.bench list

# Verify that the task_id is spelled correctly (case-sensitive)
```

### Error: "Docker service not running"

```powershell
# Build the image first
python -m scripts.bench build <task_id>

# Verify it was created
docker images | findstr <task_id>
```

### LLM is not proposing good mutations

- **Increase information level**: `--level L3` provides more context
- **Increase iterations**: `--max-iters 20`
- **Try another model**: GPT-4o or Gemini are usually more accurate than LLaMA 3
- **Review templates**: Prompts are in `prompt_templates/`

### Pipeline is very slow

- **Reduce timeout**: `LLM_TIMEOUT=60` in `.env`
- **Use faster model**: LLaMA 3 8B instead of 70B
- **Reduce iterations**: `--max-iters 5`

## 📚 Methodology

See [openhands_pipeline.md](openhands_pipeline.md) for technical details on:

- Pipeline architecture
- Jinja2 prompt format
- Supported mutation operations
- Crash detection strategies
- Benchmark integration

## 🔗 References

- **OpenHands SDK**: https://github.com/All-Hands-AI/OpenHands
- **LiteLLM** (OpenHands backend): https://docs.litellm.ai/
- **Ollama**: https://ollama.ai/
- **TFM-Justin Benchmark**: See main README.md

## 📄 License

MIT License - See LICENSE file in the root directory.

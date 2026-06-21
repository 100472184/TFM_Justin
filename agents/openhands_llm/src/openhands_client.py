"""OpenHands LLM client wrapper."""
from __future__ import annotations
import os
import json
from typing import Any, Dict, Optional


def _read_env_int(name: str, minimum: int | None = None, maximum: int | None = None) -> int | None:
    """Read an integer env var with optional bounds; return None when invalid."""
    raw = os.getenv(name)
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if minimum is not None and value < minimum:
        return None
    if maximum is not None and value > maximum:
        return None
    return value


def _read_env_bool(name: str, default: bool = False) -> bool:
    """Read boolean env var values like 1/true/yes/on and 0/false/no/off."""
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def _safe_eval_int_expr(expr: str) -> int | None:
    """
    Safely evaluate a very small integer arithmetic expression.
    Accepted tokens: digits, spaces, + - * / // % parentheses.
    Returns None when expression is invalid or unsafe.
    """
    import ast

    expr = expr.strip()
    if not expr:
        return None
    # Keep this strict: no names, no quotes, no commas, no dots/exponents.
    allowed_chars = set("0123456789+-*/()% \t")
    if any(ch not in allowed_chars for ch in expr):
        return None
    if len(expr) > 120:
        return None

    try:
        node = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None

    def _eval(n: ast.AST) -> int:
        if isinstance(n, ast.Expression):
            return _eval(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.UAdd, ast.USub)):
            v = _eval(n.operand)
            return v if isinstance(n.op, ast.UAdd) else -v
        if isinstance(n, ast.BinOp):
            left = _eval(n.left)
            right = _eval(n.right)
            if isinstance(n.op, ast.Add):
                return left + right
            if isinstance(n.op, ast.Sub):
                return left - right
            if isinstance(n.op, ast.Mult):
                return left * right
            if isinstance(n.op, ast.FloorDiv):
                if right == 0:
                    raise ValueError("division by zero")
                return left // right
            if isinstance(n.op, ast.Div):
                if right == 0:
                    raise ValueError("division by zero")
                # Keep JSON numeric fields integral.
                if left % right != 0:
                    raise ValueError("non-integer division")
                return left // right
            if isinstance(n.op, ast.Mod):
                if right == 0:
                    raise ValueError("mod by zero")
                return left % right
        raise ValueError(f"Unsupported expression node: {type(n).__name__}")

    try:
        value = _eval(node)
    except Exception:
        return None

    # Guardrails: avoid absurd values from hallucinated huge expressions.
    if not isinstance(value, int):
        return None
    if abs(value) > 10_000_000_000:
        return None
    return value


def _normalize_json_numeric_expressions(text: str) -> str:
    """
    Normalize JSON numeric fields that hallucinate arithmetic expressions:
      "offset": 17 + (12000 * 2)
    -> "offset": 24017

    Only rewrites values in object fields (after ':') while outside strings.
    """
    out: list[str] = []
    n = len(text)
    i = 0
    in_string = False
    escaped = False

    while i < n:
        ch = text[i]

        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch != ":":
            out.append(ch)
            i += 1
            continue

        # Copy ":" and following whitespace
        out.append(ch)
        i += 1
        while i < n and text[i].isspace():
            out.append(text[i])
            i += 1

        if i >= n:
            break

        # Only attempt normalization for unquoted numeric-like starts
        if text[i] not in "0123456789+-(":
            continue

        expr_start = i
        depth = 0
        j = i
        while j < n:
            c = text[j]
            if c == "(":
                depth += 1
                j += 1
                continue
            if c == ")":
                depth = max(0, depth - 1)
                j += 1
                continue
            if depth == 0 and c in ",}]":
                break
            # Stop if we hit a newline and there is no arithmetic hint.
            if c in "\r\n" and all(op not in text[expr_start:j] for op in "+-*/()%"):
                break
            j += 1

        expr = text[expr_start:j].strip()
        if expr and any(op in expr for op in "+-*/()%"):
            evaluated = _safe_eval_int_expr(expr)
            if evaluated is not None:
                out.append(str(evaluated))
                i = j
                continue

        # Keep original when we cannot safely evaluate
        out.append(text[expr_start:j])
        i = j

    return "".join(out)


def _compact_for_repair_prompt(text: str, max_chars: int = 1800) -> str:
    """
    Keep repair prompts bounded when the previous model output is huge.
    This reduces secondary timeout risk during JSON-repair retries.
    """
    if text is None:
        return ""
    text = str(text)
    if len(text) <= max_chars:
        return text
    head = max_chars // 2
    tail = max_chars - head
    return text[:head] + "\n...[truncated]...\n" + text[-tail:]


def _strip_json_comments_safe(text: str) -> str:
    """Remove // and /* */ comments only when outside JSON strings."""
    out = []
    in_string = False
    escaped = False
    in_line_comment = False
    in_block_comment = False
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch in ("\n", "\r"):
                in_line_comment = False
                out.append(ch)
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        # Outside strings
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _escape_unescaped_control_chars_in_strings(text: str) -> str:
    """
    Escape raw control characters inside JSON strings.
    This repairs common LLM output issues like unescaped newlines/tabs in string values.
    """
    out = []
    in_string = False
    escaped = False

    for ch in text:
        if in_string:
            if escaped:
                out.append(ch)
                escaped = False
                continue

            if ch == "\\":
                out.append(ch)
                escaped = True
                continue

            if ch == '"':
                out.append(ch)
                in_string = False
                continue

            # Escape illegal raw control chars inside JSON string values
            if ch == "\n":
                out.append("\\n")
                continue
            if ch == "\r":
                out.append("\\r")
                continue
            if ch == "\t":
                out.append("\\t")
                continue
            if ord(ch) < 0x20:
                out.append(f"\\u{ord(ch):04x}")
                continue

            out.append(ch)
            continue

        out.append(ch)
        if ch == '"':
            in_string = True
            escaped = False

    return "".join(out)


def _escape_invalid_backslashes_in_strings(text: str) -> str:
    """
    Escape invalid backslash sequences inside JSON strings.
    Example: "\\(" -> "\\\\(" so json.loads() can parse it.
    """
    out: list[str] = []
    in_string = False
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]

        if not in_string:
            out.append(ch)
            if ch == '"':
                in_string = True
            i += 1
            continue

        # Inside string
        if ch == '"':
            out.append(ch)
            in_string = False
            i += 1
            continue

        if ch != "\\":
            out.append(ch)
            i += 1
            continue

        # Backslash inside string
        if i + 1 >= n:
            # Trailing "\" -> escape it
            out.append("\\\\")
            i += 1
            continue

        nxt = text[i + 1]
        if nxt in '"\\/bfnrt':
            out.append("\\")
            out.append(nxt)
            i += 2
            continue

        if nxt == "u":
            # Keep valid \uXXXX, otherwise escape the backslash and continue.
            if i + 5 < n:
                hex4 = text[i + 2 : i + 6]
                if all(c in "0123456789abcdefABCDEF" for c in hex4):
                    out.append("\\u")
                    out.append(hex4)
                    i += 6
                    continue
            out.append("\\\\")
            i += 1
            continue

        # Invalid escape sequence like \(
        out.append("\\\\")
        i += 1

    return "".join(out)


def _has_generate_mutations(payload: object) -> bool:
    """
    Check whether a parsed GENERATE payload contains at least one mutation op.
    """
    if isinstance(payload, list):
        return len(payload) > 0
    if not isinstance(payload, dict):
        return False

    muts = payload.get("mutations")
    if isinstance(muts, list) and len(muts) > 0:
        return True

    alias_keys = ("mutation", "ops", "operations", "changes", "edits", "payload")
    for key in alias_keys:
        candidate = payload.get(key)
        if isinstance(candidate, list) and len(candidate) > 0:
            return True
        if isinstance(candidate, dict) and candidate.get("op"):
            return True

    if payload.get("op"):
        return True

    return False


def _canonicalize_generate_op_name(raw_op: Any) -> str:
    """Normalize common op aliases emitted by LLMs."""
    op = str(raw_op or "").strip()
    if not op:
        return ""
    alias_map = {
        "overwrite": "overwrite_range",
        "append": "append_bytes",
        "pad": "pad_file",
        "pad_end": "pad_file",
        "pad_to": "pad_file",
        "flip": "flip_bit",
        "set_value": "set_json_value",
        "replace_text": "replace",
        "replace_string": "replace",
    }
    return alias_map.get(op, op)


def _normalize_generate_mutation_object(mutation: object) -> object:
    """Best-effort canonicalization for one mutation object."""
    if not isinstance(mutation, dict):
        return mutation

    norm = dict(mutation)

    # Common alias keys for operation name.
    if "op" not in norm:
        for key in ("operation", "action", "type", "name", "method"):
            value = norm.get(key)
            if isinstance(value, str) and value.strip():
                norm["op"] = value.strip()
                break

    # Merge nested params often emitted as {"params": {...}} or {"data": {...}}.
    for key in ("params", "parameters", "args", "data", "payload"):
        nested = norm.get(key)
        if isinstance(nested, dict):
            for sub_k, sub_v in nested.items():
                norm.setdefault(sub_k, sub_v)

    op = _canonicalize_generate_op_name(norm.get("op"))
    if op:
        norm["op"] = op

    # Generic field aliases.
    if "offset" not in norm:
        for key in ("index", "pos", "position"):
            if key in norm:
                norm["offset"] = norm[key]
                break

    if "hex" not in norm:
        for key in ("bytes", "value_hex", "payload_hex"):
            value = norm.get(key)
            if isinstance(value, str) and value.strip():
                norm["hex"] = value.strip()
                break

    if isinstance(norm.get("hex"), str) and norm["hex"].startswith("0x"):
        norm["hex"] = norm["hex"][2:]

    # Op-specific aliases.
    if op == "pad_file":
        if "target_len" not in norm:
            for key in ("length", "size", "target", "new_len"):
                if key in norm:
                    norm["target_len"] = norm[key]
                    break
        if "char" not in norm and "fill" in norm:
            norm["char"] = norm["fill"]

    if op == "overwrite_range":
        if "hex" not in norm and isinstance(norm.get("value"), str):
            norm["hex"] = norm["value"]

    if op == "insert_repeated_bytes":
        if "times" not in norm:
            norm["times"] = 1

    return norm


def _normalize_generate_payload(payload: object) -> object:
    """
    Best-effort canonicalization for GENERATE payload schema.
    Keeps behavior model-agnostic while tolerating frequent format drift.
    """
    if isinstance(payload, list):
        normalized = [_normalize_generate_mutation_object(m) for m in payload]
        return {"mutations": normalized, "rationale": "normalized-from-array"}

    if not isinstance(payload, dict):
        return payload

    # Direct single-mutation object -> wrap.
    if payload.get("op") or payload.get("operation") or payload.get("action"):
        single = _normalize_generate_mutation_object(payload)
        rationale = payload.get("rationale")
        if not isinstance(rationale, str):
            rationale = "normalized-single-mutation"
        return {"mutations": [single], "rationale": rationale}

    normalized: dict[str, Any] = dict(payload)
    muts: list[Any] | None = None

    if isinstance(normalized.get("mutations"), list):
        muts = normalized.get("mutations")
    else:
        for key in ("mutation", "ops", "operations", "changes", "edits", "actions", "payload"):
            candidate = normalized.get(key)
            if isinstance(candidate, list):
                muts = candidate
                break
            if isinstance(candidate, dict):
                muts = [candidate]
                break

    if muts is not None:
        normalized["mutations"] = [_normalize_generate_mutation_object(m) for m in muts]

    if not isinstance(normalized.get("rationale"), str):
        # Keep compact and deterministic; rationale is optional for pipeline logic.
        normalized["rationale"] = "normalized-generate-payload"

    return normalized


def _extract_balanced_json_fragment(text: str) -> str | None:
    """
    Extract first balanced JSON object/array fragment from arbitrary text.
    Helps recover valid payloads when LLM appends trailing prose.
    """
    if not text:
        return None
    start = -1
    opener = ""
    for i, ch in enumerate(text):
        if ch in "{[":
            start = i
            opener = ch
            break
    if start < 0:
        return None

    closer = "}" if opener == "{" else "]"
    stack = [opener]
    in_string = False
    escaped = False

    for i in range(start + 1, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch in "{[":
            stack.append(ch)
            continue
        if ch in "}]":
            if not stack:
                return None
            top = stack[-1]
            if (top == "{" and ch == "}") or (top == "[" and ch == "]"):
                stack.pop()
                if not stack:
                    frag = text[start : i + 1].strip()
                    return frag if frag else None
            else:
                return None

    return None


class OpenHandsLLMClient:
    """Wrapper around OpenHands SDK LLM for JSON completions."""
    
    def __init__(self, model: str = None):
        """Initialize LLM client from environment variables.
        
        Args:
            model: Optional model override (takes priority over LLM_MODEL env var).
                   Example: 'ollama/qwen2.5:7b', 'vertex_ai/gemini-2.0-flash-001'
        """
        self.model = model or os.getenv("LLM_MODEL", "vertex_ai/gemini-2.0-flash-001")
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.base_url = os.getenv("LLM_BASE_URL", "")
        self.timeout = int(os.getenv("LLM_TIMEOUT", "120"))
        self.num_retries = int(os.getenv("LLM_NUM_RETRIES", "2"))
        
        # Auto-set base_url for ollama models
        # Priority: LLM_BASE_URL > OLLAMA_API_BASE > OLLAMA_HOST > fallback localhost
        if self.model.startswith("ollama/") and not self.base_url:
            self.base_url = os.getenv("OLLAMA_API_BASE") or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
            
        # Determine if this is a Vertex AI model
        is_vertex = self.model.startswith("vertex_ai/")
        
        # Map generic LLM_* vars to Vertex specific vars (only for Vertex models)
        vertex_project = os.getenv("LLM_PROJECT") if is_vertex else None
        vertex_location = os.getenv("LLM_LOCATION") if is_vertex else None
        
        if vertex_project:
            os.environ["VERTEX_PROJECT"] = vertex_project
        if vertex_location:
            os.environ["VERTEX_LOCATION"] = vertex_location
        
        # Initialize LiteLLM directly (OpenHands uses it internally)
        try:
            import litellm
            
            # Configure LiteLLM
            litellm.set_verbose = False
            
            # Store config for completion calls
            self.llm_kwargs = {
                "model": self.model,
                "timeout": self.timeout,
            }
            
            # Only pass Vertex credentials for Vertex AI models
            if is_vertex:
                if vertex_project:
                    self.llm_kwargs["vertex_project"] = vertex_project
                if vertex_location:
                    self.llm_kwargs["vertex_location"] = vertex_location
            
            if self.api_key:
                self.llm_kwargs["api_key"] = self.api_key
            
            # IMPORTANT:
            # Vertex AI models should not inherit Ollama/custom api_base values
            # from env vars (e.g., LLM_BASE_URL=http://...:11434), because LiteLLM
            # builds Vertex URLs differently and this breaks with errors like:
            # "Invalid port: '11434:generateContent'".
            if is_vertex:
                if self.base_url:
                    print("Note: ignoring LLM_BASE_URL/OLLAMA_* for vertex_ai model")
            elif self.base_url:
                self.llm_kwargs["api_base"] = self.base_url
            
            # Debug: log effective LLM configuration (helps validate LLM_BASE_URL usage)
            try:
                # Avoid leaking large secrets in logs by masking api_key if present
                logged_kwargs = dict(self.llm_kwargs)
                if "api_key" in logged_kwargs and logged_kwargs["api_key"]:
                    logged_kwargs["api_key"] = "<redacted>"
                print(f"LLM client config: {logged_kwargs}")
            except Exception:
                pass
        except ImportError as e:
            raise RuntimeError(
                "Failed to import litellm. "
                "Install with: pip install litellm"
            ) from e
    
    def completion_json(
        self,
        schema_name: str,
        system_prompt: str,
        user_prompt: str,
        max_retries: int = 2  # Increased from 1 to 2
    ) -> Dict:
        """
        Get JSON completion from LLM.
        
        Args:
            schema_name: Name of the expected schema (for logging)
            system_prompt: System message
            user_prompt: User message
            max_retries: Number of JSON repair attempts
        
        Returns:
            Parsed JSON dict
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        schema_key = (schema_name or "").strip().upper()
        schema_kind = (schema_name or "").strip().lower()
        env_retry_override = _read_env_int(
            f"LLM_{schema_key}_JSON_RETRIES",
            minimum=0,
            maximum=10,
        )
        effective_max_retries = env_retry_override if env_retry_override is not None else max_retries

        for attempt in range(effective_max_retries + 1):
            try:
                # Call LiteLLM
                import litellm
                import time
                
                # Add delay between retries (exponential backoff)
                if attempt > 0:
                    delay = 2 ** attempt  # 2s, 4s, 8s...
                    print(f"  Waiting {delay}s before retry...")
                    time.sleep(delay)
                
                # Only log retry attempts, not every call
                pass  # Removed verbose kwargs logging

                request_kwargs = dict(self.llm_kwargs)
                schema_timeout = _read_env_int(
                    f"LLM_{schema_key}_TIMEOUT",
                    minimum=1,
                    maximum=3600,
                )
                if schema_timeout is not None:
                    request_kwargs["timeout"] = schema_timeout
                schema_max_tokens = _read_env_int(
                    f"LLM_{schema_key}_MAX_TOKENS",
                    minimum=64,
                    maximum=131072,
                )
                if schema_max_tokens is not None:
                    request_kwargs["max_tokens"] = schema_max_tokens
                use_ollama_generate_json_mode = (
                    schema_kind == "generate"
                    and self.model.startswith("ollama/")
                    and _read_env_bool("OLLAMA_GENERATE_FORMAT_JSON", default=False)
                )
                if schema_kind == "generate" and self.model.startswith("ollama/"):
                    reasoning_effort = os.getenv("OLLAMA_GENERATE_REASONING_EFFORT", "").strip().lower()
                    # Ollama cloud gpt-oss via OpenAI-compatible endpoint may reject
                    # non-effort values and prefers explicit effort levels.
                    # Keep "none" for non-gpt-oss models to disable thinking.
                    if "gpt-oss" in self.model and reasoning_effort in {"false", "off", "0", "", "none"}:
                        reasoning_effort = "low"
                    if reasoning_effort:
                        # OpenAI-compatible field supported by Ollama /v1/chat/completions.
                        request_kwargs.setdefault("reasoning_effort", reasoning_effort)
                if use_ollama_generate_json_mode:
                    # Optional: enable only when explicitly requested.
                    request_kwargs.setdefault("format", "json")

                response = litellm.completion(
                    messages=messages,
                    **request_kwargs
                )

                # Extract content from response
                content = response.choices[0].message.content
                
                # Brief token count for monitoring
                usage = getattr(response, 'usage', None)
                completion_tokens = None
                if usage:
                    completion_tokens = getattr(usage, "completion_tokens", None)
                    print(f"  ✓ LLM responded ({completion_tokens} tokens)")
                max_tokens_limit = None
                try:
                    raw_max_tokens = request_kwargs.get("max_tokens")
                    if raw_max_tokens is not None:
                        max_tokens_limit = int(raw_max_tokens)
                except Exception:
                    max_tokens_limit = None
                likely_token_capped_empty = (
                    completion_tokens is not None
                    and max_tokens_limit is not None
                    and int(completion_tokens) >= int(max_tokens_limit)
                )

                # Debug: log empty responses
                if not content or content.strip() == "":
                    # Some Ollama models can return empty/whitespace in JSON mode.
                    # If enabled, do a one-shot fallback without format=json.
                    if use_ollama_generate_json_mode and request_kwargs.get("format") == "json":
                        fallback_kwargs = dict(request_kwargs)
                        fallback_kwargs.pop("format", None)
                        fallback_messages = [
                            {
                                "role": "system",
                                "content": (
                                    f"{system_prompt}\n"
                                    "Return exactly one valid JSON object. "
                                    "No markdown. No code fences. No prose."
                                ),
                            },
                            {"role": "user", "content": user_prompt},
                        ]
                        fallback_response = litellm.completion(
                            messages=fallback_messages,
                            **fallback_kwargs,
                        )
                        fallback_content = fallback_response.choices[0].message.content
                        if fallback_content and str(fallback_content).strip():
                            content = str(fallback_content)
                        else:
                            content = ""
                    # Thinking-capable Ollama models can spend the full
                    # completion budget in hidden reasoning and emit empty
                    # visible content. Before declaring empty, try one-shot
                    # non-thinking fallback for GENERATE.
                    if (
                        (not content or not str(content).strip())
                        and schema_kind == "generate"
                        and self.model.startswith("ollama/")
                    ):
                        nonthink_kwargs = dict(request_kwargs)
                        nonthink_kwargs["reasoning_effort"] = "none"
                        reasoning_obj = nonthink_kwargs.get("reasoning")
                        if isinstance(reasoning_obj, dict):
                            reasoning_obj = dict(reasoning_obj)
                        else:
                            reasoning_obj = {}
                        reasoning_obj["effort"] = "none"
                        nonthink_kwargs["reasoning"] = reasoning_obj
                        try:
                            nonthink_response = litellm.completion(
                                messages=fallback_messages if use_ollama_generate_json_mode else messages,
                                **nonthink_kwargs,
                            )
                            nonthink_content = nonthink_response.choices[0].message.content
                            if nonthink_content and str(nonthink_content).strip():
                                content = str(nonthink_content)
                            else:
                                content = ""
                        except Exception:
                            # Keep baseline retry behavior if provider/model
                            # rejects this fallback.
                            pass
                    if likely_token_capped_empty:
                        print(
                            f"  Note: empty response hit max_tokens={max_tokens_limit}; "
                            "likely spent budget before final content."
                        )
                    print(
                        f"  Warning: Empty response from LLM "
                        f"(attempt {attempt + 1}/{effective_max_retries + 1})"
                    )
                    if attempt < effective_max_retries:
                        continue
                    else:
                        raise RuntimeError("LLM returned empty response after all retries")
                
                # Try to parse JSON with aggressive cleaning
                content = content.strip()
                content = content.replace("\ufeff", "").replace("\x00", "")

                # Prefer extracting JSON inside triple-backtick fences first
                try:
                    import re as _re
                    m = _re.search(r'```(?:json\s*)?(\{.*?\}|\[.*?\])```', content, _re.DOTALL | _re.IGNORECASE)
                    if m:
                        content = m.group(1).strip()
                    else:
                        # Remove markdown code fences as fallback
                        if content.startswith("```json"):
                            content = content[7:]
                        if content.startswith("```"):
                            content = content[3:]
                        if content.endswith("```"):
                            content = content[:-3]
                        content = content.strip()
                except Exception:
                    # On any regex error, fall back to naive fence removal
                    if content.startswith("```json"):
                        content = content[7:]
                    if content.startswith("```"):
                        content = content[3:]
                    if content.endswith("```"):
                        content = content[:-3]
                    content = content.strip()
                
                # Remove comments safely (outside strings only)
                content = _strip_json_comments_safe(content)
                
                # Try to extract JSON if embedded in text
                import re
                if not content.startswith('{') and not content.startswith('['):
                    # Try to find JSON object
                    match = re.search(r'(\{.*\}|\[.*\])', content, re.DOTALL)
                    if match:
                        content = match.group(1)
                
                # Remove trailing commas before closing braces/brackets
                content = re.sub(r',(\s*[}\]])', r'\1', content)
                
                # Repair invalid raw control chars inside string values
                content = _escape_unescaped_control_chars_in_strings(content)

                # Repair invalid escape sequences inside string values
                content = _escape_invalid_backslashes_in_strings(content)

                # Normalize non-JSON arithmetic in numeric fields (common LLM issue):
                # {"offset": 17 + (12000 * 2)} -> {"offset": 24017}
                content = _normalize_json_numeric_expressions(content)

                content = content.strip()
                
                # Pre-process: Handle common LLM "math in string" hallucination
                # Matches: "A" * 123 or 'A' * 123
                try:
                    def replace_math(match):
                        quote = match.group(1)
                        char = match.group(2)
                        times = int(match.group(3))
                        # Limit to reasonable size to prevent DoS (e.g. 20MB)
                        if times > 20 * 1024 * 1024: return match.group(0)
                        return f'{quote}{char * times}{quote}'
                    
                    content = re.sub(r'(["\'])(.)\1\s*\*\s*(\d+)', replace_math, content)
                except Exception:
                    pass  # If regex fails, just proceed to json.loads

                # Try parsing original content and, if needed, a balanced fragment.
                parse_candidates = [content]
                balanced = _extract_balanced_json_fragment(content)
                if balanced and balanced not in parse_candidates:
                    parse_candidates.append(balanced)

                parsed = None
                parsed_from = None
                parse_exc: Exception | None = None
                for candidate in parse_candidates:
                    try:
                        parsed = json.loads(candidate)
                        parsed_from = candidate
                        break
                    except json.JSONDecodeError as e:
                        parse_exc = e
                        continue

                if parsed is not None:
                    if schema_kind == "generate":
                        parsed = _normalize_generate_payload(parsed)
                    if schema_kind == "generate" and not _has_generate_mutations(parsed):
                        print(
                            f"  Warning: Generate payload has no mutations "
                            f"(attempt {attempt + 1}/{effective_max_retries + 1})"
                        )
                        if attempt < effective_max_retries:
                            compact_original = _compact_for_repair_prompt(parsed_from or content)
                            repair_prompt = (
                                "Previous JSON had no usable mutations. "
                                "Return ONLY one valid JSON object with this exact schema: "
                                "{\"mutations\":[{\"op\":\"...\"}],\"rationale\":\"...\"}. "
                                "Include 1-4 mutations. Do NOT return an empty list. "
                                "Use key `op` (not action/operation/type).\n"
                                f"Original response:\n{compact_original}"
                            )
                            messages = [
                                {
                                    "role": "system",
                                    "content": (
                                        "Respond with JSON only. "
                                        "Required schema: {\"mutations\":[...],\"rationale\":\"...\"}. "
                                        "Every mutation object MUST include key `op`."
                                    ),
                                },
                                {"role": "user", "content": repair_prompt},
                            ]
                            continue
                    return parsed

                # Fallback: Try ast.literal_eval for Python-style dicts/lists
                # This handles:
                # - Single quotes: {'key': 'val'}
                # - Trailing commas: [1, 2,]
                try:
                    import ast
                    evaluated = ast.literal_eval(content)
                    if isinstance(evaluated, (dict, list)):
                        if schema_kind == "generate":
                            evaluated = _normalize_generate_payload(evaluated)
                        if schema_kind == "generate" and not _has_generate_mutations(evaluated):
                            if attempt < effective_max_retries:
                                compact_original = _compact_for_repair_prompt(content)
                                repair_prompt = (
                                    "Previous response was parseable but had no usable mutations. "
                                    "Return ONLY one valid JSON object: "
                                    "{\"mutations\":[{\"op\":\"...\"}],\"rationale\":\"...\"}. "
                                    "Include 1-4 mutations and do not return an empty list.\n"
                                    f"Original response:\n{compact_original}"
                                )
                                messages = [
                                    {
                                        "role": "system",
                                        "content": (
                                            "Respond with JSON only. "
                                            "Required schema: {\"mutations\":[...],\"rationale\":\"...\"}. "
                                            "Each mutation must include key `op`."
                                        ),
                                    },
                                    {"role": "user", "content": repair_prompt},
                                ]
                                continue
                        return evaluated
                except (ValueError, SyntaxError):
                    pass

                # Re-raise original parse error to trigger retry logic
                if parse_exc is not None:
                    raise parse_exc
                raise json.JSONDecodeError("invalid JSON payload", content, 0)

            except json.JSONDecodeError as e:
                # Minimal error logging - show only error type and position
                error_msg = str(e).split(':')[0] if ':' in str(e) else str(e)
                print(f"  ⚠ JSON parse error: {error_msg[:60]}")
                
                if attempt < effective_max_retries:
                    # Try to repair JSON
                    compact_original = _compact_for_repair_prompt(content)
                    if schema_kind == "generate":
                        repair_prompt = (
                            "Previous response was invalid JSON for GENERATE. "
                            f"Error: {str(e)}. "
                            "Return ONLY one compact JSON object with exact schema: "
                            "{\"mutations\":[{\"op\":\"...\"}],\"rationale\":\"...\"}. "
                            "Use key `op` (not operation/action/type). "
                            "Include 1-4 mutations. No markdown, no prose.\n"
                            f"Original response:\n{compact_original}"
                        )
                        messages = [
                            {
                                "role": "system",
                                "content": (
                                    "Respond with valid JSON only. "
                                    "Required schema: {\"mutations\":[...],\"rationale\":\"...\"}. "
                                    "Each mutation object must contain key `op`."
                                ),
                            },
                            {"role": "user", "content": repair_prompt},
                        ]
                    else:
                        repair_prompt = (
                            f"The previous response was not valid JSON. "
                            f"Error: {str(e)}. "
                            "Please provide ONLY valid JSON without any markdown formatting. "
                            f"Original response:\n{compact_original}"
                        )
                        messages = [
                            {"role": "system", "content": "You must respond with valid JSON only."},
                            {"role": "user", "content": repair_prompt}
                        ]
                else:
                    raise RuntimeError(
                        f"Failed to parse JSON response after {effective_max_retries + 1} attempts. "
                        f"Last error: {str(e)}\n"
                        f"Problematic content: {content[:500]}"
                    ) from e

    def completion_text(
        self,
        system_prompt: str,
        user_prompt: str,
        max_retries: int = 1,
        timeout_sec: Optional[int] = None,
    ) -> str:
        """
        Get plain-text completion from LLM (used for markdown summaries).

        Returns:
            Raw text content from assistant message.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        import litellm
        import time

        last_error = None
        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    delay = min(2 ** attempt, 8)
                    time.sleep(delay)

                kwargs = dict(self.llm_kwargs)
                if timeout_sec is not None and timeout_sec > 0:
                    kwargs["timeout"] = int(timeout_sec)

                response = litellm.completion(messages=messages, **kwargs)
                content = response.choices[0].message.content
                if content is None:
                    content = ""
                text = str(content).strip()
                if text:
                    return text
                last_error = "empty response"
            except Exception as e:
                last_error = str(e)

            if attempt >= max_retries:
                break

        raise RuntimeError(f"completion_text failed: {last_error}")

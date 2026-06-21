"""Seed mutation operations for fuzzing."""
from __future__ import annotations
from typing import List, Dict
import struct

MAX_SEED_SIZE = 20 * 1024 * 1024  # 20MB limit (needed for CVE-2023-39804)


def validate_hex_string(hex_str: str, operation: str) -> None:
    """Validate hex string has even length before fromhex()."""
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Invalid hex in {operation}: {hex_str} (odd length: {len(hex_str)} chars)")


def _normalize_make(make: object) -> bytes:
    """Normalize camera make marker to a 4-byte inline ASCII field."""
    if not isinstance(make, str):
        make = "CAM"
    make_ascii = make.encode("ascii", errors="ignore")[:3]
    if not make_ascii:
        make_ascii = b"CAM"
    return (make_ascii + b"\x00")[:4].ljust(4, b"\x00")


def _build_exif_subifd_loop_segment(subifd_count: int, loop_target_offset: int, make: object) -> bytes:
    """
    Build APP1/Exif with IFD0 containing a SubIFDs array where each entry points to loop_target_offset.
    """
    if subifd_count < 1:
        subifd_count = 1
    if subifd_count > 128:
        subifd_count = 128
    if loop_target_offset < 8 or loop_target_offset > 0xFFFFFFFF:
        loop_target_offset = 8

    make_inline = _normalize_make(make)
    tiff_header = b"II*\x00\x08\x00\x00\x00"

    # IFD0: SubIFDs + Make
    entry_count = 2
    ifd0_size = 2 + (entry_count * 12) + 4
    subifd_array_offset = 8 + ifd0_size
    entry_subifd = struct.pack("<HHII", 0x014A, 4, subifd_count, subifd_array_offset)
    entry_make = struct.pack("<HHI", 0x010F, 2, 4) + make_inline
    ifd0 = struct.pack("<H", entry_count) + entry_subifd + entry_make + struct.pack("<I", 0)
    subifd_array = b"".join(struct.pack("<I", loop_target_offset) for _ in range(subifd_count))

    exif_body = b"Exif\x00\x00" + tiff_header + ifd0 + subifd_array
    app1_len = len(exif_body) + 2
    if app1_len > 0xFFFF:
        raise ValueError(f"add_exif_subifd_loop produced APP1 segment too large: {app1_len}")
    return b"\xFF\xE1" + struct.pack(">H", app1_len) + exif_body


def _build_ifd_with_next(software_ascii: bytes, next_ifd_offset: int) -> bytes:
    """Build a single-entry child IFD with a controlled next pointer."""
    entry_count = 1
    tag_software = struct.pack("<HHI", 0x0131, 2, 4) + software_ascii[:4].ljust(4, b"\x00")
    return struct.pack("<H", entry_count) + tag_software + struct.pack("<I", next_ifd_offset)


def _build_exif_subifd_chain_segment(subifd_count: int, next_mode: str, make: object) -> bytes:
    """
    Build APP1/Exif with SubIFD array pointing to tiny child IFDs.
    next_mode controls each child IFD "next" pointer:
    - "zero": every child next pointer is 0
    - "chain": child[i] -> child[i+1], last -> 0
    - "loop": child[i] -> child[i+1], last -> child[0]
    """
    if subifd_count < 1:
        subifd_count = 1
    if subifd_count > 64:
        subifd_count = 64

    make_inline = _normalize_make(make)
    tiff_header = b"II*\x00\x08\x00\x00\x00"

    # IFD0: SubIFDs + Make
    entry_count = 2
    ifd0_size = 2 + entry_count * 12 + 4
    subifd_array_offset = 8 + ifd0_size
    child0_offset = subifd_array_offset + (4 * subifd_count)
    entry_subifd = struct.pack("<HHII", 0x014A, 4, subifd_count, subifd_array_offset)
    entry_make = struct.pack("<HHI", 0x010F, 2, 4) + make_inline
    ifd0 = struct.pack("<H", entry_count) + entry_subifd + entry_make + struct.pack("<I", 0)

    child_size = 2 + 12 + 4  # single-entry child IFD
    child_offsets = [child0_offset + i * child_size for i in range(subifd_count)]
    subifd_array = b"".join(struct.pack("<I", off) for off in child_offsets)

    if next_mode not in {"zero", "chain", "loop"}:
        next_mode = "chain"

    children = []
    for i in range(subifd_count):
        if next_mode == "zero":
            nxt = 0
        elif next_mode == "loop":
            nxt = child_offsets[i + 1] if i < subifd_count - 1 else child_offsets[0]
        else:  # chain
            nxt = child_offsets[i + 1] if i < subifd_count - 1 else 0
        children.append(_build_ifd_with_next(b"SW\x00\x00", nxt))

    exif_body = b"Exif\x00\x00" + tiff_header + ifd0 + subifd_array + b"".join(children)
    app1_len = len(exif_body) + 2
    if app1_len > 0xFFFF:
        raise ValueError(f"add_exif_subifd_chain produced APP1 segment too large: {app1_len}")
    return b"\xFF\xE1" + struct.pack(">H", app1_len) + exif_body


def _inject_app1_segment(seed: bytes, app1_segment: bytes) -> bytes:
    """Inject APP1 after SOI (or after first APPn when present)."""
    if len(seed) >= 2 and seed[0] == 0xFF and seed[1] == 0xD8:
        insert_at = 2
        if len(seed) >= 6 and seed[2] == 0xFF and 0xE0 <= seed[3] <= 0xEF:
            seg_len = (seed[4] << 8) | seed[5]
            seg_end = 2 + 2 + seg_len
            if seg_len >= 2 and seg_end <= len(seed):
                insert_at = seg_end
        return bytes(seed[:insert_at]) + app1_segment + bytes(seed[insert_at:])
    # Fallback for non-JPEG seeds: build minimal envelope.
    return b"\xFF\xD8" + app1_segment + b"\xFF\xD9"


def apply_mutations(seed_bytes: bytes, mutations: List[Dict]) -> bytes:
    """
    Apply a list of mutation operations to seed bytes.
    
    Supported operations:
    - append_bytes: {"op": "append_bytes", "hex": "deadbeef"}
    - flip_bit: {"op": "flip_bit", "offset": 123, "bit": 5}
    - overwrite_range: {"op": "overwrite_range", "offset": 10, "hex": "cafebabe"}
    - truncate: {"op": "truncate", "new_len": 200}
    - repeat_range: {"op": "repeat_range", "offset": 20, "length": 40, "times": 3}
    - insert_repeated_bytes: {"op": "insert_repeated_bytes", "offset": 20, "hex": "41", "times": 1000}
    - replace: {"op": "replace", "find": "old", "replace": "new", "count": 1}
    - replace_fragment: alias of replace
    - replace_word: alias of replace
    - add_exif_subifd_loop: {"op": "add_exif_subifd_loop", "subifd_count": 4, "loop_target_offset": 8}
    - add_exif_subifd_chain: {"op": "add_exif_subifd_chain", "subifd_count": 8, "close_loop": true, "next_mode": "loop"}
    """
    result = bytearray(seed_bytes)
    
    for mut in mutations:
        op = mut.get("op", "")
        
        if op == "append_bytes":
            hex_str = mut.get("hex", "").replace(" ", "")
            if not hex_str:
                continue
            if len(hex_str) % 2 != 0:
                raise ValueError(f"Invalid hex in append_bytes: {hex_str} (odd length: {len(hex_str)} chars)")
            try:
                new_bytes = bytes.fromhex(hex_str)
                result.extend(new_bytes)
            except ValueError as e:
                raise ValueError(f"Invalid hex in append_bytes: {hex_str}") from e
        
        elif op == "flip_bit":
            offset = mut.get("offset", 0)
            bit = mut.get("bit", 0)
            if offset < 0 or offset >= len(result):
                raise ValueError(f"flip_bit offset {offset} out of range [0, {len(result)})")
            if bit < 0 or bit > 7:
                raise ValueError(f"flip_bit bit {bit} must be in [0, 7]")
            result[offset] ^= (1 << bit)
        
        elif op == "overwrite_range":
            offset = mut.get("offset", 0)
            hex_str = mut.get("hex", "").replace(" ", "")
            if not hex_str:
                continue
            if len(hex_str) % 2 != 0:
                raise ValueError(f"Invalid hex in overwrite_range: {hex_str} (odd length: {len(hex_str)} chars)")
            try:
                new_bytes = bytes.fromhex(hex_str)
            except ValueError as e:
                raise ValueError(f"Invalid hex in overwrite_range: {hex_str}") from e
            
            # Auto-expand: If offset is past end, fill with nulls
            if offset > len(result):
                result.extend(b'\x00' * (offset - len(result)))
            
            # Allow offset to be at end of file (for appending) or within file
            if offset < 0: # Still reject negative
                raise ValueError(f"overwrite_range offset {offset} must be >= 0")
            
            # FIXED: Extend file if new_bytes goes beyond current size
            # This allows LLM to create larger payloads from small seeds
            end_offset = offset + len(new_bytes)
            if end_offset > len(result):
                # Extend the file to accommodate new bytes
                result.extend(b'\x00' * (end_offset - len(result)))
            result[offset:offset + len(new_bytes)] = new_bytes
        
        elif op == "truncate":
            new_len = mut.get("new_len", 0)
            if new_len < 0:
                raise ValueError(f"truncate new_len {new_len} must be >= 0")
            if new_len < len(result):
                result = result[:new_len]
            elif new_len > len(result):
                # Extend with null bytes
                result.extend(b'\x00' * (new_len - len(result)))
        
        elif op == "repeat_range":
            offset = mut.get("offset", 0)
            length = mut.get("length", 0)
            times = mut.get("times", 1)
            
            if offset < 0 or offset >= len(result):
                raise ValueError(f"repeat_range offset {offset} out of range")
            if length <= 0:
                continue
            if times < 1:
                continue
            
            end = min(offset + length, len(result))
            chunk = bytes(result[offset:end])
            
            # Repeat the chunk
            for _ in range(times - 1):
                result.extend(chunk)
        
        elif op == "insert_repeated_bytes":
            offset = mut.get("offset", 0)
            hex_str = mut.get("hex", "").replace(" ", "")
            times = mut.get("times", 1)
            
            if offset < 0 or offset > len(result):
                raise ValueError(f"insert_repeated_bytes offset {offset} out of range [0, {len(result)}]")
            if times < 1:
                continue
            
            if not hex_str:
                continue
            if len(hex_str) % 2 != 0:
                raise ValueError(f"Invalid hex in insert_repeated_bytes: {hex_str} (odd length)")
            
            try:
                new_bytes = bytes.fromhex(hex_str)
            except ValueError as e:
                raise ValueError(f"Invalid hex in insert_repeated_bytes: {hex_str}") from e
                
            # Create the payload
            payload = new_bytes * times
            
            # Insert at offset using slice assignment (efficient)
            result[offset:offset] = payload

        elif op == "add_exif_subifd_loop":
            subifd_count = int(mut.get("subifd_count", 4))
            loop_target_offset = int(mut.get("loop_target_offset", 8))  # TIFF-relative
            make = mut.get("make", "CAM")
            app1_segment = _build_exif_subifd_loop_segment(
                subifd_count=subifd_count,
                loop_target_offset=loop_target_offset,
                make=make,
            )
            result = bytearray(_inject_app1_segment(bytes(result), app1_segment))

        elif op == "add_exif_subifd_chain":
            # Build a SubIFD chain (optionally cyclic) to better emulate graph-like traversal stress.
            subifd_count = int(mut.get("subifd_count", 8))
            close_loop_raw = mut.get("close_loop", True)
            if isinstance(close_loop_raw, str):
                close_loop = close_loop_raw.strip().lower() in {"1", "true", "yes", "y"}
            else:
                close_loop = bool(close_loop_raw)
            next_mode_raw = mut.get("next_mode")
            if isinstance(next_mode_raw, str):
                next_mode = next_mode_raw.strip().lower()
            else:
                next_mode = "loop" if close_loop else "chain"
            if next_mode not in {"zero", "chain", "loop"}:
                next_mode = "loop" if close_loop else "chain"
            make = mut.get("make", "CAM")
            app1_segment = _build_exif_subifd_chain_segment(
                subifd_count=subifd_count,
                next_mode=next_mode,
                make=make,
            )
            result = bytearray(_inject_app1_segment(bytes(result), app1_segment))
        
        elif op == "add_pax_header":
            # Smart mutation: Uses tarfile to rebuild the archive with a new PAX header
            key = mut.get("key", "SCHILY.xattr.user.overflow")
            length = mut.get("length", 1000)
            char = mut.get("value_char", "A")
            
            import tarfile
            import io
            
            # Create payload
            value = char * length
            pax_headers = {key: value}
            
            # Create new TAR in memory
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                # Create dummy info
                info = tarfile.TarInfo("pax_payload")
                info.size = 0
                info.pax_headers = pax_headers
                tar.addfile(info, io.BytesIO(b""))
            
            # Replace the ENTIRE seed with this new valid TAR
            # This intentionally discards previous mutations to ensure validity
            result = bytearray(buf.getvalue())
        
        elif op == "add_json_nesting":
            # Smart mutation: Creates deeply nested JSON to trigger recursion limits
            # USES STRING MANIPULATION to avoid Python's json.dumps recursion limit
            layers = mut.get("layers", 100)
            key = mut.get("key", "a")
            value = mut.get("value", "leaf")
            
            # Sanitize inputs to ensure valid JSON components
            # (Basic check to avoid injection if LLM returns weird quotes)
            key = key.replace('"', '\\"')
            value = value.replace('"', '\\"')
            
            # Construct string: {"a":{"a": ... "value" ... }}
            # Each layer adds '{"key":' prefix and '}' suffix
            prefix = ('{"' + key + '":') * layers
            suffix = '}' * layers
            
            new_json_str = f'{prefix}"{value}"{suffix}'
            
            result = bytearray(new_json_str.encode("utf-8"))
            
        elif op == "add_json_field":
            # Smart mutation: Adds a field to the root JSON object
            key = mut.get("key", "payload")
            value_char = mut.get("value_char", "A")
            length = mut.get("length", 1000)
            
            import json
            
            try:
                # Try to load existing seed as JSON, or start fresh if invalid
                try:
                    data = json.loads(result.decode("utf-8", errors="ignore"))
                    if not isinstance(data, dict):
                        data = {}
                except:
                    data = {}
                
                # Add/Overwrite field
                data[key] = value_char * length
                
                new_json_bytes = json.dumps(data).encode("utf-8")
                result = bytearray(new_json_bytes)
            except Exception:
                # Fallback: just overwrite with a fresh JSON if something goes wrong
                data = {key: value_char * length}
                result = bytearray(json.dumps(data).encode("utf-8"))
        
        elif op == "set_json_value":
            # Smart mutation: Set a value at a specific JSON path with proper type handling
            # This allows changing types (string -> int, etc.) while keeping valid JSON
            # Examples:
            #   {"op": "set_json_value", "path": "inputs[0]", "value": 1234567890}
            #   {"op": "set_json_value", "path": "inputs", "value": [123, 456]}
            #   {"op": "set_json_value", "path": "data.nested.key", "value": true}
            path = mut.get("path", "")
            value = mut.get("value")  # Can be any JSON type: int, float, bool, null, string, array, object
            
            import json
            import re
            
            if not path:
                raise ValueError("set_json_value requires a 'path' argument")
            
            try:
                # Parse existing JSON
                data = json.loads(result.decode("utf-8", errors="ignore"))
            except json.JSONDecodeError:
                raise ValueError("set_json_value requires valid JSON input")
            
            # Parse the path and set the value
            # Supports: "key", "key.subkey", "key[0]", "key[0].subkey", etc.
            def set_nested_value(obj, path_str, val):
                # Split path into components
                # Handle both dot notation and bracket notation
                # e.g., "inputs[0]" -> ["inputs", 0]
                # e.g., "data.nested.key" -> ["data", "nested", "key"]
                parts = []
                current = ""
                i = 0
                while i < len(path_str):
                    c = path_str[i]
                    if c == '.':
                        if current:
                            parts.append(current)
                            current = ""
                    elif c == '[':
                        if current:
                            parts.append(current)
                            current = ""
                        # Find closing bracket
                        j = i + 1
                        while j < len(path_str) and path_str[j] != ']':
                            j += 1
                        index_str = path_str[i+1:j]
                        try:
                            parts.append(int(index_str))
                        except ValueError:
                            parts.append(index_str)  # String key in brackets
                        i = j
                    else:
                        current += c
                    i += 1
                if current:
                    parts.append(current)
                
                if not parts:
                    return val  # Replace entire document
                
                # Navigate to parent and set the value
                current_obj = obj
                for idx, part in enumerate(parts[:-1]):
                    if isinstance(part, int):
                        # Array index
                        while len(current_obj) <= part:
                            current_obj.append(None)
                        if current_obj[part] is None:
                            # Determine if next part needs array or object
                            next_part = parts[idx + 1]
                            current_obj[part] = [] if isinstance(next_part, int) else {}
                        current_obj = current_obj[part]
                    else:
                        # Object key
                        if part not in current_obj:
                            next_part = parts[idx + 1]
                            current_obj[part] = [] if isinstance(next_part, int) else {}
                        current_obj = current_obj[part]
                
                # Set the final value
                final_key = parts[-1]
                if isinstance(final_key, int):
                    while len(current_obj) <= final_key:
                        current_obj.append(None)
                    current_obj[final_key] = val
                else:
                    current_obj[final_key] = val
                
                return obj
            
            try:
                data = set_nested_value(data, path, value)
                new_json_bytes = json.dumps(data, separators=(',', ':')).encode("utf-8")
                result = bytearray(new_json_bytes)
            except Exception as e:
                raise ValueError(f"set_json_value failed: {e}")
        
        elif op == "pad_file":
            target_len = mut.get("target_len", 0)
            char = mut.get("char", "A")
            
            if target_len <= len(result):
                # If already larger, do nothing or truncate? Let's just do nothing to be safe, 
                # or maybe just ensure it's at least this size.
                pass 
            else:
                # Expand
                padding_len = target_len - len(result)
                try:
                    # Handle char as string or hex
                    pad_byte = char.encode('utf-8') if len(char) == 1 else bytes.fromhex(char)
                    pad_byte = pad_byte[:1] # Ensure single byte
                except:
                    pad_byte = b'A'
                
                result.extend(pad_byte * padding_len)
        
        elif op == "insert_zlib_payload":
            # Smart mutation for CVE-2016-5314: Compresses a payload via zlib and inserts it at offset
            offset = mut.get("offset", 0)
            payload_str = mut.get("payload", "A" * 10000)
            
            import zlib
            # Compress the payload with Zlib deflate
            compressed_bytes = zlib.compress(payload_str.encode("utf-8"))
            
            # Insert the newly compressed valid binary blob at the offset
            if offset <= len(result):
                result[offset:offset] = compressed_bytes
            else:
                result.extend(b'\x00' * (offset - len(result)))
                result.extend(compressed_bytes)

        elif op == "append_swf_tag":
            # Smart mutation: Appends a tag to an SWF, patches the main file length, and preserves EOF
            tag_type = mut.get("tag_type", 24)
            payload_hex = mut.get("payload_hex", "41414141") # Hex payload WITHOUT null byte
            
            try:
                payload = bytes.fromhex(payload_hex)
            except ValueError:
                payload = b'A' * 4
                
            import struct
            # Usar Short Tag Header (asumimos payload < 63 para este exploit simple)
            tag_length = len(payload)
            tag_header = struct.pack('<H', (tag_type << 6) | tag_length)
            
            # Buscar si termina correctamente en SWF_END (00 00) y quitarlo temporalmente
            if len(result) >= 2 and result[-2:] == b'\x00\x00':
                del result[-2:]
                
            # Anexar el tag + el payload malicioso + restaurar SWF_END
            result.extend(tag_header)
            result.extend(payload)
            result.extend(b'\x00\x00')
            
            # Actualizar el atributo total length (bytes 4-7)
            if len(result) >= 8:
                struct.pack_into('<I', result, 4, len(result))

        elif op in {"replace", "replace_fragment", "replace_word"}:
            # Flexible literal replacement for text-oriented seeds (also works on raw bytes).
            # Accepted shapes:
            # 1) {"find":"abc","replace":"xyz"}
            # 2) {"find_hex":"616263","replace_hex":"78797a"}
            # Optional: {"count": 1}  # <=0 means replace all
            find_hex = mut.get("find_hex")
            repl_hex = mut.get("replace_hex")
            find_text = mut.get("find")
            repl_text = mut.get("replace")

            try:
                if isinstance(find_hex, str):
                    clean = find_hex.replace(" ", "")
                    validate_hex_string(clean, op)
                    find_bytes = bytes.fromhex(clean)
                elif isinstance(find_text, str):
                    find_bytes = find_text.encode("utf-8")
                else:
                    raise ValueError(f"{op} requires 'find' or 'find_hex'")

                if isinstance(repl_hex, str):
                    clean = repl_hex.replace(" ", "")
                    validate_hex_string(clean, op)
                    repl_bytes = bytes.fromhex(clean)
                elif isinstance(repl_text, str):
                    repl_bytes = repl_text.encode("utf-8")
                else:
                    raise ValueError(f"{op} requires 'replace' or 'replace_hex'")

                if not find_bytes:
                    raise ValueError(f"{op} find pattern cannot be empty")
            except ValueError:
                raise
            except Exception as e:
                raise ValueError(f"{op} argument error: {e}")

            count = mut.get("count", 0)
            try:
                count_i = int(count)
            except Exception:
                count_i = 0

            src = bytes(result)
            if count_i > 0:
                dst = src.replace(find_bytes, repl_bytes, count_i)
            else:
                dst = src.replace(find_bytes, repl_bytes)
            result = bytearray(dst)

        else:
            raise ValueError(f"Unknown mutation operation: {op}")
        
        # Safety check: limit total size
        if len(result) > MAX_SEED_SIZE:
            raise ValueError(f"Seed size exceeded {MAX_SEED_SIZE} bytes after mutation")
    
    return bytes(result)

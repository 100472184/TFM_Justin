#!/usr/bin/env python3
import sys
import json
from pathlib import Path

def inspect_json(filepath):
    path = Path(filepath)
    if not path.exists():
        print(f"File not found: {path}")
        return

    print(f"\n--- Inspecting: {path.name} ---")
    print(f"Size: {path.stat().st_size} bytes")
    
    try:
        data = path.read_bytes()
        
        # Check if valid JSON (allowing recursion error)
        try:
            obj = json.loads(data)
            print("Valid JSON: Yes")
            is_valid = True
        except RecursionError:
            print("Valid JSON: Yes (Recursion limit hit on load - expected for deep nesting)")
            is_valid = True
            obj = None
        except json.JSONDecodeError as e:
            if "recursion" in str(e).lower():
                print("Valid JSON: Yes (Recursion limit hit on load - expected)")
                is_valid = True
                obj = None
            else:
                print(f"Valid JSON: No ({e})")
                is_valid = False
                obj = None
        
        # Count nesting level physically (counting '{')
        # This is a rough estimation but accurate for our generated seeds
        open_braces = data.count(b'{')
        close_braces = data.count(b'}')
        print(f"Approximate Nesting Depth: ~{open_braces} levels")
        
        # Preview start/end
        preview_len = 200
        start = data[:preview_len]
        end = data[-preview_len:] if len(data) > preview_len else b""
        
        print("\n[Start Preview]")
        print(start)
        print("\n[End Preview]")
        print(end)

    except Exception as e:
        print(f"Error inspecting file: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 inspect_json.py <path_to_seed>")
        sys.exit(1)
    
    inspect_json(sys.argv[1])

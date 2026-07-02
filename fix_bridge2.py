#!/usr/bin/env python3
import re

file_path = "analysis/bytecode_analyzer/bytecode_scanner.py"

with open(file_path, 'r') as f:
    content = f.read()

# Find the current bridge code and fix it
old_code = '''            print("[BRIDGE] Calling bridge_bytecode_to_pipeline...")
            bridge_result = bridge_bytecode_to_pipeline(program_id, pattern_dicts, outdir)
            pseudo_source = bridge_result["pseudo_source"]
            print(f"[BRIDGE] Pseudo-source generated: {len(pseudo_source)} chars")'''

new_code = '''            print("[BRIDGE] Calling bridge_bytecode_to_pipeline...")
            bridge_result = bridge_bytecode_to_pipeline(program_id, pattern_dicts, outdir)
            pseudo_source_path = bridge_result["pseudo_source"]
            print(f"[BRIDGE] Pseudo-source file: {pseudo_source_path}")
            
            # Read the actual file content
            with open(pseudo_source_path, 'r') as f:
                pseudo_source = f.read()
            print(f"[BRIDGE] Pseudo-source content: {len(pseudo_source)} chars")'''

if old_code in content:
    content = content.replace(old_code, new_code)
    with open(file_path, 'w') as f:
        f.write(content)
    print("✅ Fix applied: Now reads pseudo_source file content")
else:
    print("⚠️ Could not find pattern")
    # Show current state
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'bridge_result' in line:
            print(f"Line {i+1}: {line}")

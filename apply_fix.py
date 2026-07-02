#!/usr/bin/env python3
import re

file_path = "analysis/bytecode_analyzer/bytecode_scanner.py"

with open(file_path, 'r') as f:
    content = f.read()

# The exact buggy code pattern
old_code = '''            from analysis.bytecode_analyzer.agents.pseudo_source_generator import (
                bridge_bytecode_to_pipeline
            )
            
            print("\\n[BRIDGE] Converting bytecode findings to pseudo-source...")
            pattern_dicts = [p.to_dict() for p in patterns]
            
            
            print("[BRIDGE] Running patch_agent...")
            patched = patch_contract(pseudo_source)'''

# Fixed code - call bridge_bytecode_to_pipeline and extract pseudo_source
new_code = '''            from analysis.bytecode_analyzer.agents.pseudo_source_generator import (
                bridge_bytecode_to_pipeline
            )
            
            print("\\n[BRIDGE] Converting bytecode findings to pseudo-source...")
            pattern_dicts = [p.to_dict() for p in patterns]
            
            print("[BRIDGE] Calling bridge_bytecode_to_pipeline...")
            bridge_result = bridge_bytecode_to_pipeline(program_id, pattern_dicts, outdir)
            pseudo_source = bridge_result["pseudo_source"]
            print(f"[BRIDGE] Pseudo-source generated: {len(pseudo_source)} chars")
            
            print("[BRIDGE] Running patch_agent...")
            patched = patch_contract(pseudo_source)'''

if old_code in content:
    content = content.replace(old_code, new_code)
    with open(file_path, 'w') as f:
        f.write(content)
    print("✅ Fix applied successfully!")
    print("The bridge now calls bridge_bytecode_to_pipeline() and extracts pseudo_source")
else:
    print("⚠️ Could not find exact pattern")
    print("Searching for the bug location...")
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'patched = patch_contract(pseudo_source)' in line:
            print(f"Bug at line {i+1}")
            print("Context:")
            for j in range(max(0, i-15), min(len(lines), i+5)):
                marker = ">>> " if j == i else "    "
                print(f"{marker}{j+1:4d}: {lines[j]}")

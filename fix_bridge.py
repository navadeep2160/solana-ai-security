#!/usr/bin/env python3
import os

# Fix: Update bridge_bytecode_to_pipeline to return file CONTENT, not path
psg_path = "analysis/bytecode_analyzer/agents/pseudo_source_generator.py"

with open(psg_path, "r") as f:
    content = f.read()

old_start = "def bridge_bytecode_to_pipeline(program_id: str, patterns: list, output_dir: str) -> dict:"

if old_start in content:
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if old_start in line:
            indent = "    "
            lines[i] = old_start
            lines[i+1] = indent + '"""Bridge entrypoint for bytecode_scanner._bridge_to_langgraph."""'
            lines[i+2] = indent + "generator = PseudoSourceGenerator(patterns, program_id)"
            lines[i+3] = indent + "pseudo_source_path = generator.generate(output_dir)"
            lines[i+4] = indent + "# Read the actual file content, not just the path"
            lines[i+5] = indent + 'with open(pseudo_source_path, "r") as f:'
            lines[i+6] = indent + "    pseudo_source_content = f.read()"
            lines[i+7] = indent + 'return {"pseudo_source": pseudo_source_content, "output_dir": output_dir}'
            break
    
    with open(psg_path, "w") as f:
        f.write("\n".join(lines))
    print("Fix applied: bridge_bytecode_to_pipeline now returns file CONTENT")
else:
    print("Could not find bridge_bytecode_to_pipeline function")

print("Run: python3 -m analysis.bytecode_analyzer.test_batch --test download")

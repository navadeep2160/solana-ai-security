#!/usr/bin/env python3
"""Quick debug script to verify the fix is working."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from analysis.bytecode_analyzer.disassembler import eBPFDisassembler

print("Testing disassembler fix...")
disasm = eBPFDisassembler("test_program.so")
instructions = disasm.disassemble(use_llvm=False)

print(f"\nTotal instructions: {len(instructions)}")
for i, instr in enumerate(instructions):
    print(f"  [{i}] off={instr.offset:3d}: mnem={instr.mnemonic:12} "
          f"is_call={instr.is_call} is_syscall={instr.is_syscall} "
          f"is_jump={instr.is_jump} target={instr.target_offset}")

print("\nChecking if syscalls have is_call=True...")
for i, instr in enumerate(instructions):
    if instr.mnemonic == "syscall":
        if not instr.is_call:
            print(f"  BUG: syscall at offset {instr.offset} has is_call=False!")
        else:
            print(f"  OK: syscall at offset {instr.offset} has is_call=True")
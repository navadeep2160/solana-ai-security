#!/usr/bin/env python3
"""
Auto-patcher for Solana Bytecode Analyzer
Fixes 2 bugs in disassembler.py and cfg_recovery.py
Run: python patch_bytecode_analyzer.py
"""

from pathlib import Path

BA_DIR = Path("analysis/bytecode_analyzer")
DISASM_PATH = BA_DIR / "disassembler.py"
CFG_PATH = BA_DIR / "cfg_recovery.py"


def patch_disassembler():
    """Fix _decode_jump to not overwrite is_call when detecting syscall."""
    content = DISASM_PATH.read_text()
    
    if "# Handle call/syscall (opcode 0x85) - FIXED" in content:
        print("[PATCH] disassembler.py already fixed. Skipping.")
        return True
    
    old_simple = """        # Check for call
        if self.opcode == 0x85:  # call imm
            self.mnemonic = "call"
            self.operands = f"function_{self.imm}"
            self.is_call = True
            self.target_offset = None
        
        # Check for syscall
        if self.opcode == 0x85 and self.src_reg == 1:  # callx (syscall)
            syscall_num = self.imm
            syscall_name = SOLANA_SYSCALLS.get(syscall_num, f"syscall_{syscall_num}")
            self.mnemonic = "syscall"
            self.operands = syscall_name
            self.is_syscall = True"""
    
    new_code = """        # Handle call/syscall (opcode 0x85) - FIXED: don't overwrite is_call
        if self.opcode == 0x85:
            self.is_call = True
            self.target_offset = None
            
            if self.src_reg == 1:  # Syscall
                syscall_num = self.imm
                syscall_name = SOLANA_SYSCALLS.get(syscall_num, f"syscall_{syscall_num}")
                self.mnemonic = "syscall"
                self.operands = syscall_name
                self.is_syscall = True
            else:  # Regular function call
                self.mnemonic = "call"
                self.operands = f"function_{self.imm}"""
    
    if old_simple in content:
        content = content.replace(old_simple, new_code)
        DISASM_PATH.write_text(content)
        print("[PATCH] disassembler.py fixed successfully.")
        return True
    else:
        print("[PATCH] ERROR: Could not find the pattern to replace in disassembler.py")
        print("[PATCH] Manual fix required. See instructions below.")
        return False


def patch_cfg_recovery():
    """Add syscall block boundary detection."""
    content = CFG_PATH.read_text()
    
    if "# FIXED: After syscall" in content:
        print("[PATCH] cfg_recovery.py already fixed. Skipping.")
        return True
    
    old_pattern = """            # After call: next instruction is leader (return point)
            if instr.is_call:
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].offset)
            
            # Jump targets are leaders"""
    
    new_pattern = """            # After call: next instruction is leader (return point)
            if instr.is_call:
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].offset)
            
            # FIXED: After syscall: next instruction is leader (might panic/abort)
            if instr.is_syscall:
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].offset)
            
            # Jump targets are leaders"""
    
    if old_pattern in content:
        content = content.replace(old_pattern, new_pattern)
        CFG_PATH.write_text(content)
        print("[PATCH] cfg_recovery.py fixed successfully.")
        return True
    else:
        print("[PATCH] ERROR: Could not find the pattern to replace in cfg_recovery.py")
        print("[PATCH] Manual fix required. See instructions below.")
        return False


if __name__ == "__main__":
    print("="*60)
    print("Solana Bytecode Analyzer - Auto Patcher")
    print("="*60)
    
    if not DISASM_PATH.exists():
        print(f"ERROR: {DISASM_PATH} not found. Run from project root.")
        exit(1)
    
    if not CFG_PATH.exists():
        print(f"ERROR: {CFG_PATH} not found. Run from project root.")
        exit(1)
    
    print(f"\nPatching: {DISASM_PATH}")
    ok1 = patch_disassembler()
    
    print(f"\nPatching: {CFG_PATH}")
    ok2 = patch_cfg_recovery()
    
    print("\n" + "="*60)
    if ok1 and ok2:
        print("ALL PATCHES APPLIED SUCCESSFULLY")
        print("Run: python -m analysis.bytecode_analyzer.test_bytecode")
    else:
        print("SOME PATCHES FAILED - Manual fix required")
    print("="*60)
# create_test_ebpf.py
# Run: python create_test_ebpf.py

import struct
import os

def create_minimal_solana_program(output_path="test_program.so"):
    """
    Create a minimal but valid Solana eBPF ELF binary for testing.
    Contains actual eBPF instructions that our disassembler can parse.
    """
    
    # eBPF instructions (8 bytes each)
    # Format: | opcode(1) | dst/src(1) | offset(2) | imm(4) |
    
    instructions = []
    
    # 1. mov64 r1, 42  (load immediate)
    # opcode=0xb7 (mov64 imm), dst=1, src=0, offset=0, imm=42
    instructions.append(struct.pack("<BBhi", 0xb7, 0x01, 0, 42))
    
    # 2. mov64 r2, r10  (frame pointer)
    # opcode=0xbf (mov64 reg), dst=2, src=10, offset=0, imm=0
    instructions.append(struct.pack("<BBhi", 0xbf, 0x2a, 0, 0))
    
    # 3. add64 r2, -8  (allocate stack space)
    # opcode=0x07 (add64 imm), dst=2, src=0, offset=0, imm=-8
    instructions.append(struct.pack("<BBhi", 0x07, 0x02, 0, -8))
    
    # 4. stxdw [r2+0], r1  (store r1 to stack)
    # opcode=0x7b (stxdw), dst=2, src=1, offset=0, imm=0
    instructions.append(struct.pack("<BBhi", 0x7b, 0x12, 0, 0))
    
    # 5. ldxdw r3, [r2+0]  (load from stack)
    # opcode=0x79 (ldxdw), dst=3, src=2, offset=0, imm=0
    instructions.append(struct.pack("<BBhi", 0x79, 0x23, 0, 0))
    
    # 6. jne r3, 42, +2  (conditional jump)
    # opcode=0x55 (jne imm), dst=3, src=0, offset=2, imm=42
    instructions.append(struct.pack("<BBhi", 0x55, 0x03, 2, 42))
    
    # 7. mov64 r0, 0  (return 0 - success)
    # opcode=0xb7, dst=0, src=0, offset=0, imm=0
    instructions.append(struct.pack("<BBhi", 0xb7, 0x00, 0, 0))
    
    # 8. ja +1  (jump over error)
    # opcode=0x05 (ja), dst=0, src=0, offset=1, imm=0
    instructions.append(struct.pack("<BBhi", 0x05, 0x00, 1, 0))
    
    # 
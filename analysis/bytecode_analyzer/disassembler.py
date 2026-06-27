"""
Solana SBF Disassembler - Production Version
Uses pyelftools for ELF parsing, custom decoder for SBF instructions.
"""
import struct
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False
    print("[WARNING] pyelftools not installed. Run: pip install pyelftools")

# Solana syscall mapping (from solana-program-library)
SOLANA_SYSCALLS = {
    0x00: "abort",
    0x01: "sol_panic_",
    0x02: "sol_log_",
    0x03: "sol_log_64_",
    0x04: "sol_log_compute_units_",
    0x05: "sol_log_pubkey",
    0x06: "sol_create_program_address",
    0x07: "sol_try_find_program_address",
    0x08: "sol_sha256",
    0x09: "sol_keccak256",
    0x0a: "sol_secp256k1_recover",
    0x0b: "sol_blake3",
    0x0e: "sol_zk_token_elgamal_op_with_scalar",
    0x0f: "sol_curve_validate_point",
    0x10: "sol_curve_group_op",
    0x11: "sol_curve_multiscalar_mul",
    0x12: "sol_curve_pairing_group_op",
    0x13: "sol_alt_bn128_group_op",
    0x14: "sol_alt_bn128_compression",
    0x1e: "sol_memset_",
    0x1f: "sol_memcpy_",
    0x20: "sol_memcmp_",
    0x21: "sol_memmove_",
    0x22: "sol_invoke_signed_c",
    0x23: "sol_invoke_signed_rust",
    0x24: "sol_alloc_free_",
    0x25: "sol_set_return_data",
    0x26: "sol_get_return_data",
    0x27: "sol_log_data",
    0x28: "sol_get_processed_sibling_instruction",
    0x29: "sol_get_stack_height",
    0x2a: "sol_poseidon",
    0x2b: "sol_remaining_compute_units",
}


@dataclass
class eBPFInstruction:
    """Represents a single eBPF instruction."""
    offset: int
    opcode: int
    mnemonic: str
    operands: str
    
    is_load: bool = False
    is_store: bool = False
    is_call: bool = False
    is_jump: bool = False
    is_syscall: bool = False
    is_return: bool = False
    is_arithmetic: bool = False
    
    target_offset: Optional[int] = None
    dst_reg: int = 0
    src_reg: int = 0
    imm: int = 0
    offset_imm: int = 0


class eBPFDisassembler:
    """Solana SBF disassembler using pyelftools + custom decoder."""
    
    def __init__(self, so_path: str):
        self.so_path = Path(so_path)
        self.instructions: List[eBPFInstruction] = []
        self.text_data: bytes = b""
        self.rodata: bytes = b""
        self.symbols: Dict[str, Tuple[int, int]] = {}
        
    def _is_bpf_elf(self) -> bool:
        """Check if file is a Solana BPF ELF (SBFv1=0xF7 or SBFv2=0x107)."""
        try:
            with open(self.so_path, 'rb') as f:
                data = f.read(512)
                elf_offset = data.find(b'\x7fELF')
                if elf_offset == -1:
                    return False
                
                machine_offset = elf_offset + 18
                if machine_offset + 2 > len(data):
                    return False
                    
                machine = struct.unpack('<H', data[machine_offset:machine_offset+2])[0]
                
                # Accept both SBFv1 and SBFv2
                if machine in (0xF7, 0x107):
                    self._elf_offset = elf_offset
                    print(f"[Disasm] Detected SBF ELF (machine=0x{machine:X})")
                    return True
                else:
                    print(f"[Disasm] Found ELF but machine type is 0x{machine:02X}, not SBF")
                    return False
                    
        except Exception as e:
            print(f"[Disasm] ELF check error: {e}")
            return False


    def _extract_sections(self):
        """Extract .text and .rodata using pyelftools, with header skip."""
        if not ELFTOOLS_AVAILABLE:
            # Fallback: raw read with offset
            with open(self.so_path, 'rb') as f:
                data = f.read()
                elf_offset = getattr(self, '_elf_offset', data.find(b'\x7fELF'))
                if elf_offset >= 0:
                    self.text_data = data[elf_offset:]
            return

        with open(self.so_path, 'rb') as f:
            data = f.read()
            elf_offset = getattr(self, '_elf_offset', 0)
            
            if elf_offset < 0:
                print("[Disasm] Warning: No ELF header found")
                return
                
            # Use BytesIO with offset for pyelftools
            from io import BytesIO
            elf_stream = BytesIO(data[elf_offset:])
            
            try:
                elf = ELFFile(elf_stream)
                
                # Extract .text
                text = elf.get_section_by_name('.text')
                if text:
                    self.text_data = text.data()
                    print(f"[Disasm] .text section: {len(self.text_data)} bytes")
                else:
                    print("[Disasm] Warning: No .text section found")
                    
                # Extract .rodata
                rodata = elf.get_section_by_name('.rodata')
                if rodata:
                    self.rodata = rodata.data()
                    
                # Extract symbols
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if sym.entry.st_value > 0 and sym.entry.st_size > 0:
                                name = sym.name if sym.name else f"func_{sym.entry.st_value:04x}"
                                self.symbols[name] = (sym.entry.st_value, sym.entry.st_size)
                                
            except Exception as e:
                print(f"[Disasm] ELF parsing warning: {e}")
                # Fallback: treat everything after header as text
                self.text_data = data[elf_offset+64:]
    
    def disassemble(self, use_capstone: bool = True) -> List[eBPFInstruction]:
        """
        Disassemble SBF bytecode.
        use_capstone parameter kept for API compatibility but ignored.
        """
        if not self._is_bpf_elf():
            raise ValueError(
                f"File {self.so_path} is not a Solana eBPF program. "
                f"Expected ELF machine type 0xF7 (BPF=247)."
            )
        
        self._extract_sections()
        
        if not self.text_data:
            print("[Disasm] Warning: No text data to disassemble")
            return []
        
        self.instructions = []
        idx = 0
        
        while idx + 8 <= len(self.text_data):
            raw = self.text_data[idx:idx+8]
            instr = self._decode_instruction(raw, idx)
            self.instructions.append(instr)
            
            # lddw is 16 bytes (two instructions)
            if instr.opcode == 0x18:
                idx += 16
            else:
                idx += 8
        
        print(f"[Disasm] Decoded {len(self.instructions)} instructions")
        return self.instructions
    
    def _decode_instruction(self, raw: bytes, offset: int) -> eBPFInstruction:
        """Decode a single SBF instruction."""
        opcode, dst_src, offset_imm, imm = struct.unpack_from("<BBhi", raw, 0)
        dst_reg = dst_src & 0x0F
        src_reg = (dst_src >> 4) & 0x0F
        
        op_class = opcode & 0x07
        
        # ALU/ALU64
        if op_class == 0x07:
            return self._decode_alu(opcode, dst_reg, src_reg, offset, imm, offset_imm)
        
        # Load/Store
        if op_class in (0x01, 0x03):
            return self._decode_ldst(opcode, dst_reg, src_reg, offset, imm, offset_imm)
        
        # Jump/Call
        if op_class == 0x05:
            return self._decode_jump(opcode, dst_reg, src_reg, offset, imm, offset_imm)
        
        # Special: lddw
        if opcode == 0x18:
            if offset + 16 <= len(self.text_data):
                raw2 = self.text_data[offset+8:offset+16]
                _, _, _, imm2 = struct.unpack_from("<BBhi", raw2, 0)
                imm = (imm & 0xFFFFFFFF) | ((imm2 & 0xFFFFFFFF) << 32)
            return eBPFInstruction(
                offset=offset, opcode=opcode, mnemonic="lddw",
                operands=f"r{dst_reg}, 0x{imm:016x}",
                is_load=True, dst_reg=dst_reg, imm=imm
            )
        
        # Unknown
        return eBPFInstruction(
            offset=offset, opcode=opcode, mnemonic="unknown",
            operands=f"0x{opcode:02x}", dst_reg=dst_reg, src_reg=src_reg, imm=imm
        )
    
    def _decode_alu(self, opcode, dst_reg, src_reg, offset, imm, offset_imm):
        """Decode ALU/ALU64 instruction."""
        op_map = {
            0x07: "add", 0x0f: "sub", 0x17: "mul", 0x1f: "div",
            0x27: "or", 0x2f: "and", 0x37: "lsh", 0x3f: "rsh",
            0x47: "neg", 0x4f: "mod", 0x57: "xor", 0x5f: "mov",
            0x67: "arsh", 0x77: "end",
        }
        
        op = opcode & 0xF0
        is_imm = (opcode & 0x08) == 0x08
        is_64 = (opcode & 0x07) == 0x07
        
        mnemonic = op_map.get(op, f"alu_0x{op:02x}")
        if is_64:
            mnemonic += "64"
        
        if is_imm:
            operands = f"r{dst_reg}, {imm}"
        else:
            operands = f"r{dst_reg}, r{src_reg}"
        
        return eBPFInstruction(
            offset=offset, opcode=opcode, mnemonic=mnemonic,
            operands=operands, is_arithmetic=True,
            dst_reg=dst_reg, src_reg=src_reg, imm=imm
        )
    
    def _decode_ldst(self, opcode, dst_reg, src_reg, offset, imm, offset_imm):
        """Decode load/store instruction."""
        size_map = {0x00: "w", 0x01: "h", 0x02: "b", 0x03: "dw"}
        mode = (opcode >> 5) & 0x07
        size = size_map.get(opcode & 0x18, "?")
        
        is_load = mode in (0x00, 0x01, 0x03)
        is_store = mode in (0x02, 0x06, 0x07)
        
        if is_load:
            mnemonic = f"ldx{size}" if mode == 0x03 else f"ld{size}"
            operands = f"r{dst_reg}, [r{src_reg}+{offset_imm}]"
        else:
            mnemonic = f"stx{size}" if mode == 0x03 else f"st{size}"
            operands = f"[r{dst_reg}+{offset_imm}], r{src_reg}" if mode == 0x03 else f"[r{dst_reg}+{offset_imm}], {imm}"
        
        return eBPFInstruction(
            offset=offset, opcode=opcode, mnemonic=mnemonic,
            operands=operands, is_load=is_load, is_store=is_store,
            dst_reg=dst_reg, src_reg=src_reg, imm=imm, offset_imm=offset_imm
        )
    
    def _decode_jump(self, opcode, dst_reg, src_reg, offset, imm, offset_imm):
        """Decode jump/call/exit instruction."""
        # Exit
        if opcode == 0x95:
            return eBPFInstruction(
                offset=offset, opcode=opcode, mnemonic="exit",
                operands="", is_return=True, is_jump=True,
                dst_reg=dst_reg, src_reg=src_reg, imm=imm
            )
        
        # Call / Syscall - FIXED: src_reg=0 = syscall, src_reg=1 = local call (Solana sBPF)
        if opcode == 0x85:
            is_call = True
            target_offset = None
            
            # In Solana sBPF: src_reg=0 = syscall (helper), src_reg=1 = local function call
            if src_reg == 0:
                syscall_num = imm & 0xFFFFFFFF
                syscall_name = SOLANA_SYSCALLS.get(syscall_num, f"syscall_{syscall_num}")
                return eBPFInstruction(
                    offset=offset, opcode=opcode, mnemonic="syscall",
                    operands=syscall_name, is_call=True, is_syscall=True,
                    is_jump=True, target_offset=target_offset,
                    dst_reg=dst_reg, src_reg=src_reg, imm=imm
                )
            else:
                return eBPFInstruction(
                    offset=offset, opcode=opcode, mnemonic="call",
                    operands=f"function_{imm}", is_call=True,
                    is_jump=True, target_offset=target_offset,
                    dst_reg=dst_reg, src_reg=src_reg, imm=imm
                )
        
        # Jumps
        jump_map = {
            0x05: "ja", 0x15: "jeq", 0x25: "jgt", 0x35: "jge",
            0xa5: "jlt", 0xb5: "jle", 0x45: "jset", 0x55: "jne",
            0x65: "jsgt", 0x75: "jsge", 0xc5: "jslt", 0xd5: "jsle",
        }
        
        op = opcode & 0xF0
        mnemonic = jump_map.get(op, f"jmp_0x{op:02x}")
        target = offset + 8 + (offset_imm * 8)
        
        is_imm = (opcode & 0x08) == 0x08
        if is_imm:
            operands = f"r{dst_reg}, {imm}, +{offset_imm*8}"
        else:
            operands = f"r{dst_reg}, r{src_reg}, +{offset_imm*8}"
        
        return eBPFInstruction(
            offset=offset, opcode=opcode, mnemonic=mnemonic,
            operands=operands, is_jump=True, target_offset=target,
            dst_reg=dst_reg, src_reg=src_reg, imm=imm, offset_imm=offset_imm
        )
    
    def get_function_boundaries(self) -> Dict[str, Tuple[int, int]]:
        """Get function boundaries from symbol table."""
        return self.symbols
    
    def get_strings(self) -> List[str]:
        """Extract strings from rodata."""
        strings = []
        if self.rodata:
            current = ""
            for byte in self.rodata:
                if 32 <= byte < 127:
                    current += chr(byte)
                else:
                    if len(current) >= 4:
                        strings.append(current)
                    current = ""
            if len(current) >= 4:
                strings.append(current)
        return strings
    
    def find_strings(self) -> List[str]:
        """Alias for get_strings() for backward compatibility."""
        return self.get_strings()
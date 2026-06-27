"""
Test script for Bytecode Analyzer - PRODUCTION READY
Run with: python -m analysis.bytecode_analyzer.test_bytecode

BUG FIXES:
- Proper CLI argument parsing (no more --check treated as filename)
- Auto-creates test binary if no Solana programs found
- Handles missing llvm-objdump gracefully
- Validates ELF before scanning
"""

import sys
import struct
import subprocess
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from analysis.bytecode_analyzer import BytecodeScanner


def is_solana_program(so_path: Path) -> bool:
    """Check if a .so file is a valid Solana eBPF program (machine type 0xF7 = 247)."""
    try:
        with open(so_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'\x7fELF':
                return False
            f.seek(18)
            machine = struct.unpack('<H', f.read(2))[0]
            return machine == 0xF7
    except Exception:
        return False


def find_solana_programs(root: Path = Path(".")) -> list[Path]:
    """Find actual Solana eBPF .so files, skipping Python extensions and system libs."""
    candidates = list(root.rglob("*.so"))
    solana_files = []

    for p in candidates:
        # Skip Python virtual environment and system files
        path_str = str(p)
        if any(skip in path_str for skip in ['site-packages', 'venv', 'lib/python', '__pycache__', '/usr/lib', '/lib/x']):
            continue
        # Skip native Linux shared libraries by name pattern
        if any(x in p.name for x in ['cpython', 'mypyc', 'libpython', '.so.']):
            continue
        if is_solana_program(p):
            solana_files.append(p)

    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for p in solana_files:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def create_test_program(output_path: Path = Path("test_program.so")) -> Path:
    """
    Create a minimal Solana eBPF test program with embedded vulnerabilities
    for testing the scanner.
    """
    print(f"Creating {output_path}...")

    # eBPF opcodes
    BPF_MOV64 = 0xB7
    BPF_ADD64 = 0x0F
    BPF_CALL = 0x85
    BPF_EXIT = 0x95

    # Build instructions that trigger vulnerability patterns
    text_data = b''
    # mov64 r1, 0
    text_data += struct.pack('<BBhi', BPF_MOV64, 0x01, 0, 0)
    # mov64 r2, 0x100000000
    text_data += struct.pack('<BBhi', BPF_MOV64, 0x02, 0, 0)
    # add64 r1, r2 (unchecked arithmetic - triggers pattern)
    text_data += struct.pack('<BBhi', 0x0F, 0x21, 0, 0)
    # call sol_log_ (syscall 2)
    text_data += struct.pack('<BBhi', BPF_CALL, 0x01, 0, 2)
    # call sol_invoke_signed_c (syscall 35) - CPI without signer check
    text_data += struct.pack('<BBhi', BPF_CALL, 0x01, 0, 35)
    # mov64 r0, 0
    text_data += struct.pack('<BBhi', BPF_MOV64, 0x00, 0, 0)
    # exit
    text_data += struct.pack('<BBhi', BPF_EXIT, 0x00, 0, 0)

    # Pad to 64 bytes
    while len(text_data) % 64 != 0:
        text_data += b'\x00'

    # .rodata: strings
    rodata = b"Hello Solana\x00Program Log\x00Error\x00"
    while len(rodata) % 8 != 0:
        rodata += b'\x00'

    # Section names
    shstrtab = b'\x00.shstrtab\x00.text\x00.rodata\x00.symtab\x00.strtab\x00'
    while len(shstrtab) % 8 != 0:
        shstrtab += b'\x00'

    # Symbol strings
    strtab = b'\x00entrypoint\x00process\x00'
    while len(strtab) % 8 != 0:
        strtab += b'\x00'

    # Symbol table (24 bytes per entry)
    symtab = b''
    symtab += struct.pack('<IBBHQQ', 0, 0, 0, 0, 0, 0)  # Null symbol
    symtab += struct.pack('<IBBHQQ', 1, 0x12, 0, 1, 0, len(text_data))   # entrypoint
    symtab += struct.pack('<IBBHQQ', 11, 0x12, 0, 1, 8, 16)              # process

    # Offsets
    text_offset = 64
    rodata_offset = text_offset + len(text_data)
    shstrtab_offset = rodata_offset + len(rodata)
    symtab_offset = shstrtab_offset + len(shstrtab)
    strtab_offset = symtab_offset + len(symtab)

    num_sections = 6
    sh_offset = strtab_offset + len(strtab)
    while sh_offset % 8 != 0:
        sh_offset += 1

    # ELF header (64 bytes)
    elf_header = bytearray(64)
    elf_header[0:4] = b'\x7fELF'
    elf_header[4] = 2      # 64-bit
    elf_header[5] = 1      # Little endian
    elf_header[6] = 1      # ELF version
    elf_header[16:18] = struct.pack('<H', 1)      # ET_REL (relocatable)
    elf_header[18:20] = struct.pack('<H', 0xF7)  # BPF machine (247)
    elf_header[20:24] = struct.pack('<I', 1)     # Version
    elf_header[40:48] = struct.pack('<Q', sh_offset)  # Section header offset
    elf_header[52:54] = struct.pack('<H', 64)    # e_ehsize
    elf_header[58:60] = struct.pack('<H', 64)    # e_shentsize
    elf_header[60:62] = struct.pack('<H', num_sections)
    elf_header[62:64] = struct.pack('<H', 3)      # .shstrtab index

    def make_shdr(name_offset, type_, flags, addr, offset, size, link, info, addralign, entsize):
        shdr = bytearray(64)
        shdr[0:4] = struct.pack('<I', name_offset)
        shdr[4:8] = struct.pack('<I', type_)
        shdr[8:16] = struct.pack('<Q', flags)
        shdr[16:24] = struct.pack('<Q', addr)
        shdr[24:32] = struct.pack('<Q', offset)
        shdr[32:40] = struct.pack('<Q', size)
        shdr[40:44] = struct.pack('<I', link)
        shdr[44:48] = struct.pack('<I', info)
        shdr[48:56] = struct.pack('<Q', addralign)
        shdr[56:64] = struct.pack('<Q', entsize)
        return bytes(shdr)

    section_headers = b''
    section_headers += make_shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    section_headers += make_shdr(11, 1, 6, 0, text_offset, len(text_data), 0, 0, 8, 0)
    section_headers += make_shdr(17, 1, 2, 0, rodata_offset, len(rodata), 0, 0, 1, 0)
    section_headers += make_shdr(25, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)
    section_headers += make_shdr(35, 2, 0, 0, symtab_offset, len(symtab), 5, 2, 8, 24)
    section_headers += make_shdr(43, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0)

    # Assemble
    elf_data = bytes(elf_header)
    elf_data += text_data
    elf_data += rodata
    elf_data += shstrtab
    elf_data += symtab
    elf_data += strtab
    while len(elf_data) < sh_offset:
        elf_data += b'\x00'
    elf_data += section_headers

    with open(output_path, 'wb') as f:
        f.write(elf_data)

    print(f"  Created ({len(elf_data)} bytes)")
    print(f"  Machine: BPF (0xF7)")
    print(f"  Instructions: {len(text_data) // 8}")
    print(f"  Functions: entrypoint, process")
    return output_path


def quick_elf_check(so_path: str) -> bool:
    """Quick diagnostic for any .so file."""
    path = Path(so_path)
    print(f"\nELF Check: {path}")
    print(f"  Exists: {path.exists()}")

    if not path.exists():
        return False

    size = path.stat().st_size
    print(f"  Size: {size} bytes")

    with open(path, 'rb') as f:
        magic = f.read(4)
        print(f"  Magic: {magic}")

        if magic == b'\x7fELF':
            f.seek(18)
            machine = struct.unpack('<H', f.read(2))[0]
            machine_names = {
                0xF7: "BPF (Solana)",
                62: "x86-64 (Linux native)",
                183: "ARM64",
                40: "ARM",
            }
            name = machine_names.get(machine, f"Unknown ({machine})")
            print(f"  Machine: {name}")

            is_solana = (machine == 0xF7)
            print(f"  Is Solana program: {is_solana}")
            return is_solana
        else:
            print("  Not an ELF file")
            return False


def test_with_local_so(so_path: Path = None):
    """Test with a local Solana .so file."""
    if so_path is None:
        # Search for existing Solana programs
        search_dirs = [
            Path("target/deploy"),
            Path("target/sbf-solana-solana/release"),
            Path("target/sbf-solana-solana/debug"),
            Path("."),
        ]

        solana_files = []
        for d in search_dirs:
            if d.exists():
                solana_files.extend(find_solana_programs(d))

        # Remove duplicates
        seen = set()
        unique = []
        for p in solana_files:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        solana_files = unique

        if not solana_files:
            print("No Solana programs found. Creating test binary...")
            so_path = create_test_program()
        else:
            so_path = solana_files[0]
    else:
        if not so_path.exists():
            print(f"File not found: {so_path}")
            return None
        if not is_solana_program(so_path):
            print(f"Not a Solana program: {so_path}")
            return None

    print(f"\nUsing Solana program: {so_path}")
    print(f"File size: {so_path.stat().st_size} bytes")

    # Try to get file type info
    try:
        result = subprocess.run(['file', str(so_path)], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"Type: {result.stdout.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    scanner = BytecodeScanner(use_capstone=True)

    try:
        result = scanner.scan_local(str(so_path), program_id="test_program")

        print(f"\n{'='*60}")
        print(f"SCAN RESULTS")
        print(f"{'='*60}")
        print(f"  Instructions:     {result.instruction_count}")
        print(f"  Functions:        {result.function_count}")
        print(f"  Basic Blocks:     {result.block_count}")
        print(f"  Patterns:         {len(result.patterns)}")
        print(f"  Critical:         {len(result.critical_findings)}")

        if result.critical_findings:
            print(f"\nCRITICAL FINDINGS:")
            for f in result.critical_findings[:5]:
                print(f"    {f.pattern_type}")
                print(f"      Location: {f.function}:{f.block_id}")
                print(f"      Confidence: {f.confidence:.0%}")
                if f.evidence:
                    print(f"      Evidence: {f.evidence[0]}")

        if result.patterns:
            print(f"\nALL PATTERNS:")
            summary = {}
            for p in result.patterns:
                summary[p.pattern_type] = summary.get(p.pattern_type, 0) + 1
            for pattern, count in sorted(summary.items(), key=lambda x: -x[1])[:10]:
                print(f"    {pattern}: {count}")

        print(f"\nOutput saved to: {scanner.output_dir / 'test_program'}")
        return result

    except Exception as e:
        print(f"\nScan failed: {e}")
        print("\nTroubleshooting:")
        print("  1. Is this a valid Solana eBPF program?")
        print("  2. Is llvm-objdump installed? (which llvm-objdump)")
        print("  3. Try: llvm-objdump -d <file> | head -20")
        raise


def test_with_mainnet_program():
    """Test with a real mainnet program."""
    RAYDIUM_AMM = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"

    scanner = BytecodeScanner(use_llvm=True)

    try:
        result = scanner.scan_program(RAYDIUM_AMM)
        print(f"\nRaydium AMM Analysis Complete")
        print(f"Instructions: {result.instruction_count}")
        print(f"Functions: {result.function_count}")
        return result
    except Exception as e:
        print(f"Mainnet test failed: {e}")
        print("Make sure solana-cli is installed and configured")
        return None


def print_usage():
    print("""
Usage: python -m analysis.bytecode_analyzer.test_bytecode [COMMAND] [ARGS]

Commands:
  (no args)              Auto-find or create test program and scan
  --create-test          Create test_program.so and exit
  --check <file.so>      Check if a file is a valid Solana program
  <file.so>              Scan a specific .so file
  --mainnet              Test with Raydium AMM from mainnet
  --help                 Show this help message
""")


def main():
    """Main entry point with proper CLI handling."""
    args = sys.argv[1:]

    if not args:
        # No args: auto-find or create test
        print("=" * 60)
        print("Solana Bytecode Analyzer - Test Suite")
        print("=" * 60)
        test_with_local_so()
        return

    command = args[0]

    if command in ('--help', '-h'):
        print_usage()
        return

    if command == '--create-test':
        create_test_program()
        return

    if command == '--check':
        if len(args) < 2:
            print("Error: --check requires a file path")
            print("Usage: python test_bytecode.py --check <file.so>")
            return
        quick_elf_check(args[1])
        return

    if command == '--mainnet':
        print("=" * 60)
        print("Solana Bytecode Analyzer - Mainnet Test")
        print("=" * 60)
        test_with_mainnet_program()
        return

    # Otherwise treat as a file path
    so_path = Path(command)
    if not so_path.exists():
        print(f"Error: File not found: {so_path}")
        print(f"Unknown command or file: {command}")
        print_usage()
        return

    print("=" * 60)
    print("Solana Bytecode Analyzer - File Scan")
    print("=" * 60)
    test_with_local_so(so_path)


if __name__ == "__main__":
    main()
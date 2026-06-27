"""
Test script for Batch Scanner
Run with: python -m analysis.bytecode_analyzer.test_batch
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from analysis.bytecode_analyzer.batch_scanner import BatchBytecodeScanner


def test_single_local():
    """Test with a single local .so file."""
    print("=" * 60)
    print("TEST 1: Single Local Program")
    print("=" * 60)
    
    scanner = BatchBytecodeScanner()
    
    # Use existing test_program.so
    result = scanner.scan_program(
        "test_program",
        use_local=True,
        local_path=Path("test_program.so")
    )
    
    if result:
        print(f"\n✓ Scan complete:")
        print(f"  Instructions: {result.instruction_count}")
        print(f"  Functions: {result.function_count}")
        print(f"  Blocks: {result.block_count}")
        print(f"  Patterns: {len(result.patterns)}")
        print(f"  Critical: {len(result.critical_findings)}")
        
        if result.critical_findings:
            print(f"\n⚠ Critical Findings:")
            for f in result.critical_findings:
                print(f"  - {f.pattern_type} @ {f.function}:{f.block_id}")
    else:
        print("✗ Scan failed")
    
    return result


def test_batch_local():
    """Test batch scan with local files only."""
    print("\n" + "=" * 60)
    print("TEST 2: Batch Local Scan")
    print("=" * 60)
    
    scanner = BatchBytecodeScanner()
    
    # Scan test_program.so multiple times as different "programs"
    # In real usage, you'd have multiple .so files
    batch = scanner.scan_batch(["test_program"], use_local=True)
    
    print(f"\nBatch Results:")
    print(f"  Total: {batch.total_programs}")
    print(f"  Successful: {batch.successful}")
    print(f"  Failed: {batch.failed}")
    
    report = scanner.generate_report(batch)
    print(f"\n{report}")
    
    return batch


def test_download_and_scan():
    """Test downloading a real program from mainnet."""
    print("\n" + "=" * 60)
    print("TEST 3: Download + Scan (Mainnet)")
    print("=" * 60)
    
    scanner = BatchBytecodeScanner()
    
    # Try to download and scan a small program
    # Using Token program as it's small and well-known
    program_id = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
    
    print(f"Fetching {program_id} from mainnet...")
    result = scanner.scan_program(program_id, use_local=False)
    
    if result:
        print(f"\n✓ Scan complete:")
        print(f"  Instructions: {result.instruction_count}")
        print(f"  Functions: {result.function_count}")
        print(f"  Patterns: {len(result.patterns)}")
    else:
        print("✗ Download or scan failed (network may be unavailable)")
    
    return result


def test_full_batch():
    """Test full batch scan of known programs."""
    print("\n" + "=" * 60)
    print("TEST 4: Full Batch Scan (Known Programs)")
    print("=" * 60)
    
    scanner = BatchBytecodeScanner()
    
    # Scan a subset of known programs
    programs = ["raydium_amm", "orca_whirlpool", "metaplex_token"]
    
    print(f"Scanning {len(programs)} programs...")
    batch = scanner.scan_batch(programs, use_local=False)
    
    print(f"\n{batch.generate_report()}")
    
    return batch


if __name__ == "__main__":
    print("=" * 60)
    print("Solana Bytecode Analyzer - Batch Test Suite")
    print("=" * 60)
    
    import argparse
    parser = argparse.ArgumentParser(description="Batch scanner tests")
    parser.add_argument("--test", choices=["single", "batch", "download", "full", "all"],
                       default="all", help="Which test to run")
    args = parser.parse_args()
    
    if args.test in ("single", "all"):
        test_single_local()
    
    if args.test in ("batch", "all"):
        test_batch_local()
    
    if args.test in ("download", "all"):
        test_download_and_scan()
    
    if args.test == "full":
        test_full_batch()
    
    print("\n" + "=" * 60)
    print("Tests complete!")
    print("=" * 60)
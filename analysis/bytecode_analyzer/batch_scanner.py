"""
Batch Scanner for Solana Bytecode Analyzer
Scans multiple programs in parallel with enhanced semantic patterns.
"""
import json
import time
import struct
import base64
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from .bytecode_scanner import BytecodeScanner, BytecodeScanResult


# Free public RPC endpoints (no API key needed)
RPC_ENDPOINTS = {
    "mainnet": "https://api.mainnet-beta.solana.com",
    "devnet": "https://api.devnet.solana.com",
    "helius": "https://mainnet.helius-rpc.com/?api-key=1",  # Demo key, may be rate-limited
}


# Enhanced vulnerability patterns for Solana
ENHANCED_PATTERNS = {
    # Critical: Missing security checks
    "missing_signer_check_before_cpi": {
        "description": "CPI call without preceding signer verification",
        "severity": "CRITICAL",
        "confidence_threshold": 0.6,
    },
    "missing_owner_check_before_cpi": {
        "description": "CPI call without preceding owner verification",
        "severity": "CRITICAL",
        "confidence_threshold": 0.5,
    },
    "missing_rent_exemption_check": {
        "description": "Account creation without rent exemption check",
        "severity": "HIGH",
        "confidence_threshold": 0.6,
    },
    
    # Arithmetic vulnerabilities
    "unchecked_arithmetic": {
        "description": "Arithmetic operation without overflow check",
        "severity": "HIGH",
        "confidence_threshold": 0.5,
    },
    "potential_integer_overflow": {
        "description": "Potential integer overflow in arithmetic",
        "severity": "HIGH",
        "confidence_threshold": 0.4,
    },
    
    # Account management
    "pda_without_seed_validation": {
        "description": "PDA usage without seed validation",
        "severity": "HIGH",
        "confidence_threshold": 0.6,
    },
    "account_closure_vulnerability": {
        "description": "Account may be closed without proper cleanup",
        "severity": "MEDIUM",
        "confidence_threshold": 0.5,
    },
    "missing_close_authority_check": {
        "description": "Token account closure without authority check",
        "severity": "HIGH",
        "confidence_threshold": 0.6,
    },
    
    # Authority checks
    "missing_admin_authority_check": {
        "description": "Admin function without authority verification",
        "severity": "CRITICAL",
        "confidence_threshold": 0.7,
    },
    "hardcoded_address": {
        "description": "Hardcoded address detected in program",
        "severity": "MEDIUM",
        "confidence_threshold": 0.5,
    },
    
    # CPI security
    "cpi_to_unverified_program": {
        "description": "CPI to program without address verification",
        "severity": "CRITICAL",
        "confidence_threshold": 0.6,
    },
    "unchecked_program_id": {
        "description": "Program ID not verified before CPI",
        "severity": "HIGH",
        "confidence_threshold": 0.6,
    },
    
    # Reentrancy
    "potential_reentrancy": {
        "description": "State change after CPI call (reentrancy risk)",
        "severity": "HIGH",
        "confidence_threshold": 0.5,
    },
    
    # Data validation
    "missing_account_data_length_check": {
        "description": "Account data accessed without length check",
        "severity": "MEDIUM",
        "confidence_threshold": 0.5,
    },
    "missing_discriminator_check": {
        "description": "Account discriminator not verified",
        "severity": "HIGH",
        "confidence_threshold": 0.6,
    },
}


@dataclass
class BatchScanResult:
    """Results from a batch scan."""
    total_programs: int
    successful: int
    failed: int
    results: Dict[str, BytecodeScanResult] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    aggregate_stats: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "total_programs": self.total_programs,
            "successful": self.successful,
            "failed": self.failed,
            "results": {k: v.to_dict() for k, v in self.results.items()},
            "errors": self.errors,
            "aggregate_stats": self.aggregate_stats,
        }
    
    def to_json(self, output_path: Optional[str] = None) -> str:
        data = self.to_dict()
        json_str = json.dumps(data, indent=2, default=str)
        if output_path:
            Path(output_path).write_text(json_str)
        return json_str


class SolanaProgramDownloader:
    """Download Solana program binaries via RPC (no solana-cli needed)."""
    
    def __init__(self, rpc_url: Optional[str] = None, output_dir: str = "downloaded_programs"):
        self.rpc_url = rpc_url or RPC_ENDPOINTS["mainnet"]
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def fetch_program(self, program_id: str) -> Optional[Path]:
        """
        Fetch a program binary via RPC.
        SBF programs store metadata in the program account (36 bytes),
        and the actual ELF binary in a separate programData PDA account.
        """
        import base64
        
        # Step 1: Get program account to find programData address
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [
                program_id,
                {"encoding": "base64"}
            ]
        }
        
        program_data_addr = None
        
        try:
            response = requests.post(
                self.rpc_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            if "error" in data:
                print(f"[Download] RPC error for {program_id}: {data['error']}")
                return None
            
            result = data.get("result", {}).get("value")
            if not result:
                print(f"[Download] Program {program_id} not found")
                return None
            
            if not result.get("executable"):
                print(f"[Download] {program_id} is not a program")
                return None
            
            # Skip native programs
            if result.get("owner") == "NativeLoader1111111111111111111111111111111":
                print(f"[Download] {program_id} is a native program")
                return None
            
            # Parse account data to extract programData address
            account_data = base64.b64decode(result["data"][0])
            
            # Upgradeable loader format: 4 bytes header + 32 bytes programData pubkey
            if len(account_data) >= 36:
                # Bytes 4-35 = programData address (32 bytes)
                program_data_bytes = account_data[4:36]
                # Convert to base58-like string (Solana address format)
                # Use a simple base58 encoder
                program_data_addr = self._bytes_to_base58(program_data_bytes)
                print(f"[Download] Program data account: {program_data_addr}")
            else:
                print(f"[Download] Unexpected account data length: {len(account_data)}")
                return None
                
        except Exception as e:
            print(f"[Download] Error fetching program info: {e}")
            return None
        
        if not program_data_addr:
            print(f"[Download] Could not extract programData address")
            return None
        
        # Step 2: Fetch the actual program data account
        payload2 = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getAccountInfo",
            "params": [
                program_data_addr,
                {"encoding": "base64"}
            ]
        }
        
        try:
            response2 = requests.post(
                self.rpc_url,
                json=payload2,
                headers={"Content-Type": "application/json"},
                timeout=60
            )
            response2.raise_for_status()
            data2 = response2.json()
            
            if "error" in data2:
                print(f"[Download] RPC error for program data: {data2['error']}")
                return None
            
            result2 = data2.get("result", {}).get("value")
            if not result2:
                print(f"[Download] Program data account not found")
                return None
            
            # Decode program data
            program_data = base64.b64decode(result2["data"][0])
            print(f"[Download] Program data size: {len(program_data)} bytes")
            
            # Find ELF magic in the data
            # Program data format: [upgrade authority option][authority pubkey][slot][unused][ELF binary]
            # The ELF binary starts at variable offset, so search for magic
            elf_offset = program_data.find(b'\x7fELF')
            
            if elf_offset == -1:
                print(f"[Download] No ELF magic found in program data")
                # Debug: show first 64 bytes
                print(f"[Download] First 64 bytes: {program_data[:64].hex()}")
                return None
            
            elf_binary = program_data[elf_offset:]
            print(f"[Download] ELF found at offset {elf_offset}, size {len(elf_binary)} bytes")
            
            # Verify it's BPF
            if len(elf_binary) < 20:
                print(f"[Download] ELF too short")
                return None
            
            machine = struct.unpack('<H', elf_binary[18:20])[0]
            # Accept both BPF (0xF7) and standard eBPF (0x0107 = 263) machine types
            # Solana SBF uses a modified BPF that may report differently
            if machine not in (0x00F7, 0x0107, 0x00F3):
                print(f"[Download] Warning: Unexpected machine type 0x{machine:04x}, continuing anyway")
                # Don't return None, try to parse anyway
            
            # Save to file
            output_path = self.output_dir / f"{program_id}.so"
            output_path.write_bytes(elf_binary)
            
            print(f"[Download] ✓ Saved {program_id}: {len(elf_binary)} bytes -> {output_path}")
            return output_path
            
        except Exception as e:
            print(f"[Download] Error fetching program data: {e}")
            return None
    
    def _bytes_to_base58(self, data: bytes) -> str:
        """Convert bytes to Base58 (Solana address format)."""
        ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        
        # Convert bytes to big integer
        num = int.from_bytes(data, 'big')
        
        # Encode to base58
        result = ""
        while num > 0:
            num, rem = divmod(num, 58)
            result = ALPHABET[rem] + result
        
        # Add leading '1's for leading zero bytes
        for b in data:
            if b == 0:
                result = '1' + result
            else:
                break
        
        return result or '1'
    
    def fetch_multiple(self, program_ids: List[str], max_workers: int = 3) -> Dict[str, Optional[Path]]:
        """Fetch multiple programs in parallel."""
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.fetch_program, pid): pid for pid in program_ids}
            for future in as_completed(futures):
                pid = futures[future]
                try:
                    results[pid] = future.result()
                except Exception as e:
                    print(f"[Download] Exception for {pid}: {e}")
                    results[pid] = None
        return results


class BatchBytecodeScanner:
    """
    Batch scanner with enhanced semantic patterns.
    Scans multiple Solana programs and aggregates results.
    """
    
    # Known mainnet programs for testing
    TEST_PROGRAMS = {
    "raydium_amm": "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",      # SBF ✓
    "orca_whirlpool": "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",      # SBF ✓
    "metaplex_token": "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",     # SBF ✓
    "serum_dex_v3": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",      # SBF ✓
    "marinade": "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD",           # SBF ✓
    "solend": "So1endDq2YkqhipRh3WViPgUgWjGbeKtObT1kBrEAx",              # SBF ✓
    "jupiter_v6": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",        # SBF ✓
    "drift": "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH",              # SBF ✓
    "kamino": "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYn2TxD5",              # SBF ✓
    "marginfi": "MFv2hWf31Z9kbCa1snEjYanR5rgjhKbCHC5YrePFUVa",           # SBF ✓
    "tensor": "TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN",             # SBF ✓
    "sharky": "SHARKobtfF1bHhxD2eqftjHBdVSCbKo9JtgK71FhELP",             # SBF ✓
}
    
    def __init__(self, 
                 rpc_url: Optional[str] = None,
                 output_dir: str = "batch_results",
                 max_workers: int = 3):
        self.downloader = SolanaProgramDownloader(rpc_url)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.max_workers = max_workers
        self.enhanced_patterns = ENHANCED_PATTERNS
        
    def scan_program(self, program_id: str, 
                     use_local: bool = False,
                     local_path: Optional[Path] = None) -> Optional[BytecodeScanResult]:
        """Scan a single program."""
        so_path = local_path
        
        if not use_local:
            # Try to download
            so_path = self.downloader.fetch_program(program_id)
            if so_path is None:
                return None
        
        if so_path is None or not so_path.exists():
            print(f"[BatchScan] No .so file for {program_id}")
            return None
        
        try:
            scanner = BytecodeScanner(use_capstone=False)
            result = scanner.scan_local(str(so_path), program_id=program_id)
            return result
        except Exception as e:
            print(f"[BatchScan] Scan failed for {program_id}: {e}")
            return None
    
    def scan_batch(self, program_ids: List[str],
                   use_local: bool = False) -> BatchScanResult:
        """
        Scan multiple programs in batch.
        
        Args:
            program_ids: List of program IDs or names from TEST_PROGRAMS
            use_local: If True, look for local .so files instead of downloading
        """
        # Resolve names to IDs
        resolved_ids = []
        for pid in program_ids:
            if pid in self.TEST_PROGRAMS:
                resolved_ids.append(self.TEST_PROGRAMS[pid])
            else:
                resolved_ids.append(pid)
        
        total = len(resolved_ids)
        successful = 0
        failed = 0
        results = {}
        errors = {}
        
        print(f"\n{'='*60}")
        print(f"BATCH SCAN: {total} programs")
        print(f"{'='*60}")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for pid in resolved_ids:
                if use_local:
                    local_path = self.downloader.output_dir / f"{pid}.so"
                    future = executor.submit(self.scan_program, pid, True, local_path)
                else:
                    future = executor.submit(self.scan_program, pid)
                futures[future] = pid
            
            for future in as_completed(futures):
                pid = futures[future]
                try:
                    result = future.result()
                    if result:
                        results[pid] = result
                        successful += 1
                        print(f"  ✓ {pid}: {result.instruction_count} instructions, "
                              f"{len(result.patterns)} patterns")
                    else:
                        errors[pid] = "Scan returned None"
                        failed += 1
                        print(f"  ✗ {pid}: Failed")
                except Exception as e:
                    errors[pid] = str(e)
                    failed += 1
                    print(f"  ✗ {pid}: {e}")
        
        # Aggregate statistics
        aggregate = self._compute_aggregate(results)
        
        batch_result = BatchScanResult(
            total_programs=total,
            successful=successful,
            failed=failed,
            results=results,
            errors=errors,
            aggregate_stats=aggregate
        )
        
        # Save results
        timestamp = int(time.time())
        output_path = self.output_dir / f"batch_scan_{timestamp}.json"
        batch_result.to_json(str(output_path))
        print(f"\n💾 Batch results saved to: {output_path}")
        
        return batch_result
    
    def _compute_aggregate(self, results: Dict[str, BytecodeScanResult]) -> Dict:
        """Compute aggregate statistics across all scans."""
        stats = {
            "total_instructions": 0,
            "total_functions": 0,
            "total_blocks": 0,
            "total_patterns": 0,
            "total_critical": 0,
            "severity_breakdown": defaultdict(int),
            "pattern_breakdown": defaultdict(int),
            "programs_with_critical": 0,
        }
        
        for pid, result in results.items():
            stats["total_instructions"] += result.instruction_count
            stats["total_functions"] += result.function_count
            stats["total_blocks"] += result.block_count
            stats["total_patterns"] += len(result.patterns)
            stats["total_critical"] += len(result.critical_findings)
            
            if result.critical_findings:
                stats["programs_with_critical"] += 1
            
            for p in result.patterns:
                stats["pattern_breakdown"][p.pattern_type] += 1
                # Map to severity from enhanced patterns
                if p.pattern_type in self.enhanced_patterns:
                    sev = self.enhanced_patterns[p.pattern_type]["severity"]
                    stats["severity_breakdown"][sev] += 1
        
        stats["pattern_breakdown"] = dict(stats["pattern_breakdown"])
        stats["severity_breakdown"] = dict(stats["severity_breakdown"])
        return stats
    
    def scan_test_suite(self) -> BatchScanResult:
        """Scan all known test programs."""
        return self.scan_batch(list(self.TEST_PROGRAMS.keys()))
    
    def generate_report(self, batch_result: BatchScanResult) -> str:
        """Generate a human-readable report."""
        lines = [
            "=" * 60,
            "BATCH SCAN REPORT",
            "=" * 60,
            f"Total Programs: {batch_result.total_programs}",
            f"Successful: {batch_result.successful}",
            f"Failed: {batch_result.failed}",
            "",
            "AGGREGATE STATISTICS:",
            f"  Total Instructions: {batch_result.aggregate_stats.get('total_instructions', 0)}",
            f"  Total Functions: {batch_result.aggregate_stats.get('total_functions', 0)}",
            f"  Total Blocks: {batch_result.aggregate_stats.get('total_blocks', 0)}",
            f"  Total Patterns: {batch_result.aggregate_stats.get('total_patterns', 0)}",
            f"  Total Critical: {batch_result.aggregate_stats.get('total_critical', 0)}",
            f"  Programs with Critical: {batch_result.aggregate_stats.get('programs_with_critical', 0)}",
            "",
            "SEVERITY BREAKDOWN:",
        ]
        
        for sev, count in batch_result.aggregate_stats.get("severity_breakdown", {}).items():
            lines.append(f"  {sev}: {count}")
        
        lines.extend([
            "",
            "TOP PATTERNS:",
        ])
        
        patterns = batch_result.aggregate_stats.get("pattern_breakdown", {})
        for pattern, count in sorted(patterns.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  {pattern}: {count}")
        
        lines.extend([
            "",
            "PROGRAMS WITH CRITICAL FINDINGS:",
        ])
        
        for pid, result in batch_result.results.items():
            if result.critical_findings:
                lines.append(f"  {pid}:")
                for f in result.critical_findings[:3]:
                    lines.append(f"    - {f.pattern_type} (confidence: {f.confidence:.0%})")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
"""
Bytecode Scanner - Main Orchestrator

Integrates all components:
1. Fetches .so from mainnet/devnet
2. Disassembles eBPF instructions (Capstone-based)
3. Recovers control flow graph
4. Extracts semantic security patterns
5. Encodes features for GNN/HGT
6. Produces unified vulnerability report

Usage:
    scanner = BytecodeScanner()
    result = scanner.scan_program("9xQeWvG816bUx9EP...")
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from .so_fetcher import SolanaProgramFetcher
from .disassembler import eBPFDisassembler
from .cfg_recovery import CFGRecoverer
from .semantic_extractor import SemanticExtractor, VulnerabilityPattern
from .feature_encoder import FeatureEncoder, GraphFeatures


@dataclass
class BytecodeScanResult:
    """Complete result from a bytecode scan."""
    program_id: str
    so_path: Path
    timestamp: float

    # Analysis results
    instruction_count: int = 0
    function_count: int = 0
    block_count: int = 0

    # Security findings
    patterns: List[VulnerabilityPattern] = field(default_factory=list)
    critical_findings: List[VulnerabilityPattern] = field(default_factory=list)

    # Graph features
    graph_features: Optional[GraphFeatures] = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "program_id": self.program_id,
            "so_path": str(self.so_path),
            "timestamp": self.timestamp,
            "instruction_count": self.instruction_count,
            "function_count": self.function_count,
            "block_count": self.block_count,
            "patterns": [p.to_dict() for p in self.patterns],
            "critical_findings": [p.to_dict() for p in self.critical_findings],
            "metadata": self.metadata,
        }

    def to_json(self, output_path: Optional[str] = None) -> str:
        """Serialize to JSON."""
        data = self.to_dict()
        json_str = json.dumps(data, indent=2, default=str)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(json_str)

        return json_str


class BytecodeScanner:
    """
    Main orchestrator for Solana bytecode analysis.

    Pipeline:
    1. Fetch .so from blockchain
    2. Disassemble eBPF (Capstone-based)
    3. Recover CFG
    4. Extract semantic patterns
    5. Encode graph features
    6. Generate report
    """

    def __init__(self, 
                 rpc_url: Optional[str] = None,
                 output_dir: str = "bytecode_results",
                 use_capstone: bool = True):
        self.use_capstone = use_capstone  # Kept for API compatibility
        self.fetcher = SolanaProgramFetcher(rpc_url=rpc_url)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_capstone = use_capstone

        # Component instances (set during scan)
        self.disassembler: Optional[eBPFDisassembler] = None
        self.cfg_recoverer: Optional[CFGRecoverer] = None
        self.semantic_extractor: Optional[SemanticExtractor] = None
        self.feature_encoder: Optional[FeatureEncoder] = None
    
    def _bridge_to_langgraph(self, program_id: str, patterns: list, outdir: str):
        try:
            from agents.scanner.scanner_v3 import scan_contract_v3
            from agents.patcher.patch_agent import patch_contract
            from agents.validator.validator_agent import validate_contract
            from analysis.bytecode_analyzer.agents.pseudo_source_generator import (
                bridge_bytecode_to_pipeline
            )
            
            print("\n[BRIDGE] Converting bytecode findings to pseudo-source...")
            pattern_dicts = [p.to_dict() for p in patterns]
            
            print("[BRIDGE] Generating pseudo-source via bridge...")
            bridge_result = bridge_bytecode_to_pipeline(pattern_dicts, program_id, outdir)
            pseudo_source_path = bridge_result["pseudo_source"]
            with open(pseudo_source_path, "r") as f:
                pseudo_source = f.read()
            print(f"[BRIDGE] Pseudo-source generated: {len(pseudo_source)} chars")
            
            print("[BRIDGE] Running patch_agent...")
            patched = patch_contract(pseudo_source)
            
            print("[BRIDGE] Running validator_agent...")
            validation = validate_contract(patched)
            
            if validation.get("success"):
                print("[BRIDGE] ✅ Full pipeline complete!")
            else:
                print("[BRIDGE] ⚠️ Patch failed validation.")
            
            return {"findings": findings, "validation": validation}
            
        except Exception as e:
            print(f"[BRIDGE] Error: {e}")
            return None

    def scan_program(self,
                     program_id: str,
                     so_path: Optional[Path] = None,
                     skip_fetch: bool = False) -> BytecodeScanResult:
        """
        Complete scan of a Solana program.

        Args:
            program_id: Solana program address (base58)
            so_path: Optional local .so file path (skip fetch if provided)
            skip_fetch: Use local file without fetching

        Returns:
            BytecodeScanResult with all findings
        """
        start_time = time.time()
        print(f"\n{'='*60}")
        print(f"BYTECODE SCAN: {program_id}")
        print(f"{'='*60}\n")

        # Step 1: Fetch or use local .so
        if so_path and skip_fetch:
            binary_path = Path(so_path)
            print(f"[Scanner] Using local file: {binary_path}")
        else:
            try:
                binary_path = self.fetcher.fetch(program_id, use_cli=True)
            except Exception as e:
                print(f"[Scanner] Fetch failed: {e}")
                if so_path:
                    binary_path = Path(so_path)
                    print(f"[Scanner] Falling back to local file: {binary_path}")
                else:
                    raise

        # Step 2: Disassemble
        print(f"\n[Phase 1/5] Disassembling eBPF bytecode...")
        try:
            self.disassembler = eBPFDisassembler(str(binary_path))
            instructions = self.disassembler.disassemble()
            print(f"  -> {len(instructions)} instructions decoded")
        except ValueError as e:
            print(f"\nERROR: {e}")
            print("\nTroubleshooting:")
            print("  1. Make sure the file is a Solana program built with 'cargo build-sbf'")
            print("  2. Check: file <your.so>  # Should show 'ELF 64-bit LSB relocatable, eBPF'")
            print("  3. Try: llvm-objdump -d <your.so>  # Should show eBPF instructions")
            print("  4. Run: python -m analysis.bytecode_analyzer.test_bytecode --create-test")
            raise

        # Step 3: Recover CFG
        print(f"\n[Phase 2/5] Recovering control flow graph...")
        self.cfg_recoverer = CFGRecoverer(self.disassembler)
        functions = self.cfg_recoverer.recover()
        total_blocks = sum(len(f.blocks) for f in functions.values())
        print(f"  -> {len(functions)} functions, {total_blocks} basic blocks")

        # Step 4: Extract semantic patterns
        print(f"\n[Phase 3/5] Extracting security patterns...")
        self.semantic_extractor = SemanticExtractor(self.disassembler, self.cfg_recoverer)
        patterns = self.semantic_extractor.extract_all()
        critical = self.semantic_extractor.get_critical_findings()
        print(f"  -> {len(patterns)} patterns, {len(critical)} critical")

        # Step 5: Encode features
        print(f"\n[Phase 4/5] Encoding graph features for HGT...")
        self.feature_encoder = FeatureEncoder(self.disassembler, self.cfg_recoverer, self.semantic_extractor)
        features = self.feature_encoder.encode()
        stats = self.feature_encoder.get_node_statistics()
        print(f"  -> Graph nodes: {stats}")

        # Step 6: Build result
        print(f"\n[Phase 5/5] Generating report...")
        result = BytecodeScanResult(
            program_id=program_id,
            so_path=binary_path,
            timestamp=time.time(),
            instruction_count=len(instructions),
            function_count=len(functions),
            block_count=total_blocks,
            patterns=patterns,
            critical_findings=critical,
            graph_features=features,
            metadata={
                "scan_duration": time.time() - start_time,
                "use_capstone": self.use_capstone,
                "node_statistics": stats,
            }
        )

        # Save outputs
        self._save_outputs(result, program_id)

        # Bridge to LangGraph pipeline
        base_name = program_id.replace("/", "_")
        out_dir = self.output_dir / base_name
        self._bridge_to_langgraph(program_id, result.patterns, str(out_dir))

        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE in {result.metadata['scan_duration']:.2f}s")
        print(f"{'='*60}")

        return result

    def _save_outputs(self, result: BytecodeScanResult, program_id: str):
        """Save all analysis outputs."""
        base_name = program_id.replace("/", "_")
        out_dir = self.output_dir / base_name
        out_dir.mkdir(parents=True, exist_ok=True)

        # JSON report
        result.to_json(out_dir / "report.json")
        print(f"  -> Report: {out_dir / 'report.json'}")

        # Graph features
        if self.feature_encoder:
            self.feature_encoder.export_to_json(out_dir / "graph_features.json")
            self.feature_encoder.export_to_dot(out_dir / "cfg.dot")
            print(f"  -> Graph features: {out_dir / 'graph_features.json'}")
            print(f"  -> CFG DOT: {out_dir / 'cfg.dot'}")

        # Vulnerability summary
        summary = self.semantic_extractor.get_vulnerability_summary() if self.semantic_extractor else {}
        with open(out_dir / "vuln_summary.json", 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"  -> Vuln summary: {out_dir / 'vuln_summary.json'}")

    def scan_local(self, so_path: str, program_id: str = "unknown") -> BytecodeScanResult:
        """
        Scan a local .so file without fetching from chain.
        """
        return self.scan_program(program_id, so_path=Path(so_path), skip_fetch=True)

    def get_call_graph(self) -> Dict[str, List[str]]:
        """Get function call graph from last scan."""
        if not self.cfg_recoverer:
            raise ValueError("No scan performed yet")

        G = self.cfg_recoverer.get_call_graph()
        return {node: list(G.successors(node)) for node in G.nodes()}

    def get_dominator_tree(self, func_name: str) -> Optional[Dict]:
        """Get dominator tree for a function."""
        if not self.cfg_recoverer:
            raise ValueError("No scan performed yet")

        dom_tree = self.cfg_recoverer.get_dominator_tree(func_name)
        if dom_tree is None:
            return None

        return {node: list(dom_tree.successors(node)) for node in dom_tree.nodes()}

    def find_loops(self, func_name: str) -> List[List[str]]:
        """Find loops in a function."""
        if not self.cfg_recoverer:
            raise ValueError("No scan performed yet")

        return self.cfg_recoverer.find_loops(func_name)
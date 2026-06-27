"""
Unified Scanner
===============
Main orchestrator combining AST + CFG + Symbolic + KB + LLM.
No hardcoded rules - all patterns from KB.
"""
import os
import sys
import warnings
from pathlib import Path
from typing import List, Dict, Any

warnings.filterwarnings("ignore")
os.environ["TOKENIZERS_PARALLELISM"] = "false"

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from .fact_extractor import FactExtractor
from .kb_matcher import KBPatternMatcher
from .symbolic_engine import SymbolicEngine
from .llm_confirmer import LLMConfirmer
from .deduplicator import Deduplicator

try:
    from analysis.ast_parser.rust_ast_parser import parse_rust_ast
    from analysis.ast_parser.cfg_builder import analyze_cfg
except ImportError:
    parse_rust_ast = None
    analyze_cfg = None


class UnifiedScanner:
    """KB-driven + LLM-enhanced vulnerability scanner."""

    def __init__(self, use_llm: bool = True):
        self.extractor = FactExtractor()
        self.kb_matcher = KBPatternMatcher()
        self.symbolic = SymbolicEngine()
        self.llm_confirmer = LLMConfirmer() if use_llm else None
        self.deduplicator = Deduplicator()
        self.findings = []

    def scan(self, source_code: str, contract_name: str = "unknown") -> Dict[str, Any]:
        """Run full scan pipeline."""
        print(f"\n[UnifiedScanner] Scanning {contract_name}...")
        self.findings = []

        # Layer 1: Parse AST and CFG
        print("[UnifiedScanner] Layer 1: Parsing")
        ast_result = None
        cfg_result = None

        if parse_rust_ast:
            try:
                ast_result = parse_rust_ast(source_code)
                print(f"  AST: {len(ast_result.functions)} functions")
            except Exception as e:
                print(f"  AST parser failed: {e}")

        if analyze_cfg:
            try:
                cfg_result = analyze_cfg(source_code)
                print(f"  CFG: {len(cfg_result.get('function_facts', {}))} functions")
            except Exception as e:
                print(f"  CFG parser failed: {e}")

        # Layer 2: Extract facts
        print("[UnifiedScanner] Layer 2: Fact Extraction")
        facts = self.extractor.extract_all(source_code, ast_result, cfg_result)
        print(f"  Extracted {len(facts)} facts")

        # Layer 3: KB Pattern Matching
        print("[UnifiedScanner] Layer 3: KB Pattern Matching")
        kb_findings = self.kb_matcher.match_facts(facts)
        print(f"  KB matches: {len(kb_findings)}")

        # Layer 4: Symbolic Execution
        print("[UnifiedScanner] Layer 4: Symbolic Execution")
        symbolic_findings = self.symbolic.analyze(facts)
        symbolic_dicts = self.symbolic.to_dict_list()
        print(f"  Symbolic findings: {len(symbolic_dicts)}")

        # Layer 5: LLM Confirmation (optional)
        all_findings = kb_findings + symbolic_dicts

        if self.llm_confirmer:
            print("[UnifiedScanner] Layer 5: LLM Confirmation")
            all_findings = self.llm_confirmer.confirm_batch(all_findings, source_code)
            confirmed_count = sum(1 for f in all_findings if f.get("llm_confirmed", False))
            print(f"  LLM confirmed: {confirmed_count}")

        # Layer 6: Deduplication
        print("[UnifiedScanner] Layer 6: Deduplication")
        self.findings = self.deduplicator.deduplicate(all_findings)
        print(f"  Unique findings: {len(self.findings)}")

        stats = self._compute_stats()

        return {
            "contract": contract_name,
            "findings": self.findings,
            "stats": stats,
            "layers": {
                "facts": len(facts),
                "kb_matches": len(kb_findings),
                "symbolic": len(symbolic_dicts),
                "unique": len(self.findings),
            }
        }

    def _compute_stats(self) -> Dict[str, Any]:
        stats = {
            "total": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "categories": {},
            "sources": {},
        }

        for f in self.findings:
            sev = f.get("severity", "LOW")
            stats[sev.lower()] += 1

            cat = f.get("category", "other")
            stats["categories"][cat] = stats["categories"].get(cat, 0) + 1

            src = f.get("source", "unknown")
            stats["sources"][src] = stats["sources"].get(src, 0) + 1

        return stats

    def get_fixes(self) -> List[Dict[str, str]]:
        """Get unique fixes for all findings."""
        fixes = []
        seen = set()

        for f in self.findings:
            vuln_type = f.get("vuln_type", "")
            fix = f.get("fix", "") or f.get("llm_fix", "")

            if fix and vuln_type and vuln_type not in seen:
                seen.add(vuln_type)
                fixes.append({
                    "vuln_type": vuln_type,
                    "fix": fix,
                    "severity": f.get("severity", "MEDIUM"),
                    "function": f.get("function", "unknown"),
                })

        return fixes


def scan_contract(source_code: str, contract_name: str = "unknown", use_llm: bool = True) -> Dict[str, Any]:
    """One-shot contract scan."""
    scanner = UnifiedScanner(use_llm=use_llm)
    return scanner.scan(source_code, contract_name)

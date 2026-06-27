"""
Deduplicator
============
Merges findings from multiple layers (AST, CFG, Symbolic, LLM).
Uses function + vuln_type similarity for deduplication.
"""
from typing import List, Dict, Any
from collections import defaultdict


class Deduplicator:
    """Deduplicate and merge findings across detection layers."""

    def __init__(self):
        self.severity_scores = {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 50,
            "LOW": 25,
        }

    def deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """
        Deduplicate findings.
        Same vulnerability in same function = one finding.
        Keeps highest severity, merges sources, boosts confidence for multi-layer.
        """
        groups = defaultdict(list)

        for f in findings:
            key = self._make_key(f)
            groups[key].append(f)

        merged = []
        for key, group in groups.items():
            best = self._merge_group(group)
            merged.append(best)

        # Sort by severity then confidence
        merged.sort(key=lambda x: (
            self.severity_scores.get(x.get("severity", "LOW"), 0),
            x.get("confidence", 0)
        ), reverse=True)

        return merged

    def _make_key(self, finding: Dict) -> tuple:
        """Create deduplication key."""
        func = finding.get("function", "unknown")
        vuln = self._normalize_vuln_name(finding.get("vuln_type", ""))
        line = finding.get("line", 0) // 5  # Group nearby lines
        return (func, vuln, line)

    def _normalize_vuln_name(self, name: str) -> str:
        """Normalize vulnerability name for deduplication."""
        name = name.lower().strip()

        mappings = {
            "missing signer": "missing_signer_check",
            "signer check": "missing_signer_check",
            "no signer": "missing_signer_check",
            "missing owner": "missing_owner_check",
            "owner check": "missing_owner_check",
            "no owner": "missing_owner_check",
            "integer overflow": "integer_overflow",
            "integer underflow": "integer_overflow",
            "unchecked math": "integer_overflow",
            "arithmetic": "integer_overflow",
            "precision loss": "precision_loss",
            "cpi": "arbitrary_cpi",
            "cross-program": "arbitrary_cpi",
            "reinit": "reinitialization",
            "reinitialization": "reinitialization",
            "close": "unsafe_closure",
            "account closure": "unsafe_closure",
            "unchecked account": "unchecked_account_usage",
        }

        for key, val in mappings.items():
            if key in name:
                return val

        return name.replace(" ", "_")

    def _merge_group(self, group: List[Dict]) -> Dict:
        """Merge findings in the same group."""
        # Pick the one with highest severity
        best = max(group, key=lambda x: self.severity_scores.get(x.get("severity", "LOW"), 0))

        # Merge sources
        sources = set()
        layers = set()
        evidences = set()
        max_confidence = 0

        for g in group:
            sources.add(g.get("source", "unknown"))
            max_confidence = max(max_confidence, g.get("confidence", 0))

            if "matched_keywords" in g:
                layers.add("kb")
            if "path_constraint" in g:
                layers.add("symbolic")
            if "llm_confirmed" in g:
                layers.add("llm")

            evidence = g.get("evidence", "")
            if evidence:
                evidences.add(evidence)

        # Boost confidence if multiple layers agree
        confidence_boost = 0
        if len(layers) > 1:
            confidence_boost = 0.15
            best["multi_layer_confirmed"] = True

        best["source"] = "+".join(sorted(sources))
        best["detection_layers"] = list(layers)
        best["evidence"] = " | ".join(sorted(evidences)) if evidences else best.get("evidence", "")
        best["confidence"] = min(max_confidence + confidence_boost, 1.0)

        return best

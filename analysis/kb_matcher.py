"""
KB Pattern Matcher
==================
Matches extracted facts against KB vulnerability patterns.
No hardcoded rules - all patterns from knowledge base.
"""
import os
import sys
import json
import warnings
from pathlib import Path
from typing import List, Dict, Any, Optional

os.environ["ANONYMIZED_TELEMETRY"] = "False"
warnings.filterwarnings("ignore")

try:
    import chromadb.telemetry.product.posthog as _posthog
    _posthog._direct_capture = lambda *a, **k: None
except Exception:
    pass

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).parent.parent.parent


class KBPatternMatcher:
    """Matches code facts against KB vulnerability patterns."""

    def __init__(self, kb_path: str = "knowledge_base/chromadb"):
        self.kb_path = PROJECT_ROOT / kb_path
        self.client = None
        self.vuln_nodes = []
        self._load_kb()

    def _load_kb(self):
        """Load vulnerability nodes from ChromaDB."""
        try:
            self.client = chromadb.PersistentClient(
                path=str(self.kb_path),
                settings=Settings(anonymized_telemetry=False)
            )
            col = self.client.get_collection("vuln_nodes")
            data = col.get(include=["metadatas"])

            for meta in data["metadatas"]:
                if meta:
                    self.vuln_nodes.append({
                        "name": meta.get("name", ""),
                        "category": meta.get("category", "other"),
                        "severity": meta.get("severity", "medium"),
                        "description": meta.get("description", ""),
                        "fix": meta.get("fix", ""),
                        "preconditions": meta.get("preconditions", []),
                        "ast_patterns": meta.get("ast_patterns", []),
                        "cfg_patterns": meta.get("cfg_patterns", []),
                    })
            print(f"[KB-Matcher] Loaded {len(self.vuln_nodes)} vulnerability patterns")
        except Exception as e:
            print(f"[KB-Matcher] Warning: Could not load KB: {e}")
            self._load_fallback_patterns()

    def _load_fallback_patterns(self):
        """Fallback: load from vuln_nodes.json if ChromaDB fails."""
        try:
            vuln_path = PROJECT_ROOT / "knowledge_base" / "vuln_nodes.json"
            with open(vuln_path) as f:
                data = json.load(f)
            nodes = data.get("nodes", []) if isinstance(data, dict) else data
            for node in nodes:
                self.vuln_nodes.append({
                    "name": node.get("name", ""),
                    "category": node.get("category", "other"),
                    "severity": node.get("severity", "medium"),
                    "description": node.get("description", ""),
                    "fix": node.get("fix", ""),
                    "preconditions": node.get("preconditions", []),
                    "ast_patterns": node.get("ast_patterns", []),
                    "cfg_patterns": node.get("cfg_patterns", []),
                })
            print(f"[KB-Matcher] Loaded {len(self.vuln_nodes)} patterns from JSON fallback")
        except Exception as e:
            print(f"[KB-Matcher] Fallback also failed: {e}")

    def match_facts(self, facts: List[Dict]) -> List[Dict[str, Any]]:
        """Match facts against KB patterns and return findings."""
        findings = []

        for fact in facts:
            matches = self._match_single_fact(fact)
            findings.extend(matches)

        return self._deduplicate(findings)

    def _match_single_fact(self, fact: Dict) -> List[Dict]:
        """Match a single fact against all KB patterns."""
        matches = []
        fact_layer = fact.get("layer", "")
        fact_type = fact.get("fact_type", "")
        context = fact.get("context", {})
        function = fact.get("function", "unknown")
        line = fact.get("line", 0)

        for node in self.vuln_nodes:
            score = 0
            matched_keywords = []

            name_lower = node.get("name", "").lower()
            desc_lower = node.get("description", "").lower()
            category = node.get("category", "other")

            # Layer-specific matching
            if fact_layer == "ast":
                score += self._score_ast_match(context, node, name_lower, desc_lower)
            elif fact_layer == "cfg":
                score += self._score_cfg_match(context, node, name_lower, desc_lower)
            elif fact_layer == "symbolic":
                score += self._score_symbolic_match(context, node, name_lower, desc_lower)

            # Category bonus
            if category == "auth" and any(k in name_lower for k in ["signer", "owner", "authority"]):
                if not context.get("has_signer", True) or not context.get("signer_check", True):
                    score += 5
            if category == "arithmetic" and any(k in name_lower for k in ["overflow", "underflow", "arithmetic"]):
                if not context.get("has_checked_math", True) or context.get("unchecked_math", False):
                    score += 5
            if category == "account" and any(k in name_lower for k in ["transfer", "close", "init", "reinit"]):
                score += 3
            if category == "cpi" and "cpi" in name_lower:
                score += 3

            if score >= 15:
                matches.append({
                    "vuln_type": node["name"],
                    "category": category,
                    "severity": node.get("severity", "medium").upper(),
                    "function": function,
                    "line": line,
                    "description": node.get("description", f"Detected {node['name']}"),
                    "fix": node.get("fix", ""),
                    "confidence": min(score / 40.0, 1.0),
                    "evidence": f"Matched via {fact_layer}: {json.dumps(context)[:100]}",
                    "source": f"kb_{fact_layer}_match",
                    "matched_keywords": matched_keywords,
                })

        return matches

    def _score_ast_match(self, context: Dict, node: Dict, name_lower: str, desc_lower: str) -> int:
        score = 0

        if not context.get("has_signer", True):
            if any(k in name_lower for k in ["signer", "authority", "authorization"]):
                score += 20
            if any(k in desc_lower for k in ["missing signer", "no signer", "without signer"]):
                score += 15

        if not context.get("has_owner_check", True):
            if any(k in name_lower for k in ["owner", "ownership"]):
                score += 20
            if any(k in desc_lower for k in ["missing owner", "no owner", "without owner"]):
                score += 15

        if not context.get("has_checked_math", True):
            if any(k in name_lower for k in ["overflow", "underflow", "arithmetic"]):
                score += 20
            if any(k in desc_lower for k in ["unchecked arithmetic", "integer overflow", "math"]):
                score += 15

        return score

    def _score_cfg_match(self, context: Dict, node: Dict, name_lower: str, desc_lower: str) -> int:
        score = 0

        if context.get("signer_check") is False:
            if any(k in name_lower for k in ["signer", "authority"]):
                score += 20

        if context.get("owner_check") is False:
            if any(k in name_lower for k in ["owner", "ownership"]):
                score += 20

        if context.get("unchecked_math") is True:
            if any(k in name_lower for k in ["overflow", "underflow", "arithmetic"]):
                score += 20

        if context.get("transfer") is True and context.get("signer_check") is False:
            if any(k in name_lower for k in ["transfer", "drain"]):
                score += 20

        if context.get("close") is True and context.get("signer_check") is False:
            if any(k in name_lower for k in ["close", "closure"]):
                score += 20

        if context.get("cpi") is True and context.get("signer_check") is False:
            if any(k in name_lower for k in ["cpi", "invoke", "cross-program"]):
                score += 25

        return score

    def _score_symbolic_match(self, context: Dict, node: Dict, name_lower: str, desc_lower: str) -> int:
        score = 0

        unchecked = context.get("unchecked_accounts", [])
        actions = context.get("actions_found", [])

        if unchecked and actions:
            if any(k in name_lower for k in ["signer", "authority", "missing check"]):
                score += 20
            if any(k in name_lower for k in ["owner", "ownership"]):
                score += 15
            if "transfer" in actions and any(k in name_lower for k in ["transfer", "drain"]):
                score += 20
            if "cpi" in actions and any(k in name_lower for k in ["cpi", "invoke"]):
                score += 20

        return score

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate by function + vuln_type."""
        seen = {}
        for f in findings:
            key = (f.get("function"), f.get("vuln_type"))
            if key not in seen or f.get("confidence", 0) > seen[key].get("confidence", 0):
                seen[key] = f
        return list(seen.values())

    def get_fix_template(self, vuln_type: str) -> Optional[str]:
        for node in self.vuln_nodes:
            if node["name"].lower() == vuln_type.lower():
                return node.get("fix", "")
        return None

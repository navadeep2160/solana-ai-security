"""
KB Pattern Matcher
==================
Loads vulnerability patterns from ChromaDB KB and matches against AST/CFG facts.
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

    def match_ast_fact(self, fact: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match an AST fact against KB patterns."""
        matches = []
        fact_text = json.dumps(fact).lower()
        risk_indicators = fact.get("risk_indicators", [])

        for node in self.vuln_nodes:
            score = 0
            matched_keywords = []

            # Match by risk indicators
            for risk in risk_indicators:
                risk_lower = risk.lower()
                desc_lower = node.get("description", "").lower()
                name_lower = node.get("name", "").lower()

                if risk_lower in desc_lower or risk_lower in name_lower:
                    score += 15
                    matched_keywords.append(risk)

                # Keyword matching
                if risk == "no_signer" and any(k in name_lower for k in ["signer", "authority", "authorization"]):
                    score += 10
                    matched_keywords.append("signer")
                if risk == "no_owner" and any(k in name_lower for k in ["owner", "ownership"]):
                    score += 10
                    matched_keywords.append("owner")
                if risk == "unchecked_math" and any(k in name_lower for k in ["overflow", "underflow", "arithmetic"]):
                    score += 10
                    matched_keywords.append("arithmetic")
                if risk == "unchecked_cpi" and any(k in name_lower for k in ["cpi", "invoke", "cross-program"]):
                    score += 10
                    matched_keywords.append("cpi")
                if risk == "unchecked_transfer" and any(k in name_lower for k in ["transfer", "drain"]):
                    score += 10
                    matched_keywords.append("transfer")
                if risk == "unchecked_close" and any(k in name_lower for k in ["close", "closure"]):
                    score += 10
                    matched_keywords.append("close")
                if risk == "unchecked_init" and any(k in name_lower for k in ["reinit", "reinitialize", "initialization"]):
                    score += 10
                    matched_keywords.append("reinit")

            # Category-based matching
            category = node.get("category", "other")
            if category == "auth" and any(r in risk_indicators for r in ["no_signer", "no_owner"]):
                score += 5
            if category == "arithmetic" and "unchecked_math" in risk_indicators:
                score += 5
            if category == "account" and any(r in risk_indicators for r in ["unchecked_transfer", "unchecked_close", "unchecked_init"]):
                score += 5
            if category == "cpi" and "unchecked_cpi" in risk_indicators:
                score += 5

            if score >= 10:
                matches.append({
                    "vuln_type": node["name"],
                    "category": category,
                    "severity": node["severity"],
                    "description": node["description"] or f"Detected {node['name']}",
                    "fix": node["fix"],
                    "confidence": min(score / 30.0, 1.0),
                    "matched_keywords": list(set(matched_keywords)),
                    "source": "kb_ast_match",
                    "fact": fact,
                })

        matches.sort(key=lambda x: x["confidence"], reverse=True)
        return matches[:3]

    def match_cfg_block(self, func_name: str, block: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match a CFG block against KB patterns."""
        matches = []
        tags = block.get("tags", {})

        tag_vulns = []
        if tags.get("signer_check") is False:
            tag_vulns.append(("Missing Signer Check", "auth", "high", "signer"))
        if tags.get("owner_check") is False:
            tag_vulns.append(("Missing Ownership Check", "auth", "high", "owner"))
        if tags.get("unchecked_math") is True:
            tag_vulns.append(("Integer Overflow/Underflow", "arithmetic", "high", "arithmetic"))
        if tags.get("transfer") is True and tags.get("signer_check") is False:
            tag_vulns.append(("Unsafe Transfer", "account", "high", "transfer"))
        if tags.get("close") is True and tags.get("signer_check") is False:
            tag_vulns.append(("Unsafe Account Closure", "account", "high", "close"))
        if tags.get("init") is True and tags.get("signer_check") is False:
            tag_vulns.append(("Reinitialization Risk", "account", "medium", "reinit"))
        if tags.get("cpi") is True and tags.get("signer_check") is False:
            tag_vulns.append(("Arbitrary CPI", "cpi", "critical", "cpi"))

        for default_name, category, severity, keyword in tag_vulns:
            best_match = None
            best_score = 0

            for node in self.vuln_nodes:
                score = 0
                desc = (node.get("description", "") + " " + node.get("name", "")).lower()

                if keyword in desc:
                    score += 10
                if category == node.get("category", "other"):
                    score += 5
                if default_name.lower() in node.get("name", "").lower():
                    score += 10

                if score > best_score:
                    best_score = score
                    best_match = node

            if best_match:
                matches.append({
                    "vuln_type": best_match["name"],
                    "category": best_match.get("category", category),
                    "severity": best_match.get("severity", severity),
                    "description": best_match.get("description", f"{default_name} detected"),
                    "fix": best_match.get("fix", ""),
                    "confidence": min(best_score / 25.0, 1.0),
                    "evidence": f"CFG tag: {keyword}",
                    "source": "kb_cfg_match",
                    "function": func_name,
                    "line": block.get("line_start", 0),
                })
            else:
                matches.append({
                    "vuln_type": default_name,
                    "category": category,
                    "severity": severity,
                    "description": f"{default_name} detected in block",
                    "fix": "Add proper validation checks",
                    "confidence": 0.6,
                    "evidence": f"CFG tag: {keyword}",
                    "source": "cfg_tag",
                    "function": func_name,
                    "line": block.get("line_start", 0),
                })

        return matches

    def get_fix_template(self, vuln_type: str) -> Optional[str]:
        """Get fix template for a vulnerability type from KB."""
        for node in self.vuln_nodes:
            if node["name"].lower() == vuln_type.lower():
                return node.get("fix", "")
        return None

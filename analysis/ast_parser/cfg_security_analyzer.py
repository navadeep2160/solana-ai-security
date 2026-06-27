"""
CFG Security Analyzer — KB-Driven (Description-Based Matching)
===============================================================
CFG tags tell us what's structurally wrong.
KB nodes give us vulnerability names and fixes.
We match tags to the most relevant KB node by description keywords.
"""
import os
import sys
import warnings
from pathlib import Path

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
sys.path.insert(0, str(PROJECT_ROOT))

def get_kb_nodes():
    """Load all KB vulnerability nodes."""
    try:
        client = chromadb.PersistentClient(
            path=str(PROJECT_ROOT / "knowledge_base" / "chromadb"),
            settings=Settings(anonymized_telemetry=False)
        )
        col = client.get_collection("vuln_nodes")
        data = col.get(include=["metadatas"])
        return [m for m in data["metadatas"] if m]
    except Exception as e:
        print(f"[CFG-Analyzer] KB error: {e}")
        return []

def find_kb_match(nodes, tag_name, func_lines):
    """Find best matching KB node for a given tag."""
    func_text = " ".join(func_lines).lower()
    
    # Tag → keyword mapping
    tag_keywords = {
        "signer_check": ["signer", "authority", "authorization", "missing signer"],
        "owner_check": ["owner", "ownership", "missing owner"],
        "unchecked_math": ["overflow", "underflow", "arithmetic", "checked", "math"],
        "transfer": ["transfer", "cpi", "invoke", "cross-program"],
        "close": ["close", "closure", "destroy"],
        "init": ["reinit", "reinitialize", "initialization", "init"],
    }
    
    keywords = tag_keywords.get(tag_name, [tag_name])
    best_match = None
    best_score = 0
    
    for node in nodes:
        desc = (node.get("description", "") + " " + node.get("name", "")).lower()
        score = 0
        
        # Keyword match in description
        for kw in keywords:
            if kw in desc:
                score += 10
        
        # Keyword match in function text
        for kw in keywords:
            if kw in func_text:
                score += 5
        
        if score > best_score:
            best_score = score
            best_match = node
    
    return best_match

def analyze_cfg_security(cfg_result):
    """Analyze CFG tags, match to KB nodes for names/fixes."""
    findings = []
    nodes = get_kb_nodes()
    
    # CFG tag → (bad_value, default_category, default_name, default_sev)
    tag_checks = [
        ("signer_check", False, "auth", "Missing Signer Check", "high"),
        ("owner_check", False, "auth", "Missing Ownership Check", "high"),
        ("unchecked_math", True, "arithmetic", "Integer Overflow/Underflow", "high"),
        ("transfer", True, "account", "Unsafe Transfer", "medium"),
        ("close", True, "account", "Unsafe Account Closure", "medium"),
        ("init", True, "account", "Reinitialization Risk", "medium"),
    ]
    
    functions = cfg_result.get("functions", {})
    
    for func_name, func_data in functions.items():
        blocks = func_data.get("blocks", [])
        func_lines = []
        for b in blocks:
            func_lines.extend(b.get("lines", []))
        
        for block in blocks:
            tags = block.get("tags", {})
            line_start = block.get("line_start", 0)
            
            for tag_name, bad_value, default_cat, default_name, default_sev in tag_checks:
                if tags.get(tag_name) == bad_value:
                    # Find best KB match
                    kb_node = find_kb_match(nodes, tag_name, func_lines)
                    
                    if kb_node:
                        findings.append({
                            "vuln_type": kb_node.get("name", default_name),
                            "severity": kb_node.get("severity", default_sev),
                            "category": kb_node.get("category", default_cat),
                            "function": func_name,
                            "line": line_start,
                            "description": kb_node.get("description", f"Block has {tag_name}={bad_value}"),
                            "fix": kb_node.get("fix", "Review and add proper checks"),
                            "evidence": f"CFG tag {tag_name}={bad_value}",
                            "source": "kb_matched"
                        })
                    else:
                        findings.append({
                            "vuln_type": default_name,
                            "severity": default_sev,
                            "category": default_cat,
                            "function": func_name,
                            "line": line_start,
                            "description": f"Block has {tag_name}={bad_value}",
                            "fix": "Review and add proper checks",
                            "evidence": f"CFG tag {tag_name}={bad_value}",
                            "source": "cfg_tag"
                        })
    
    # Deduplicate by (function, vuln_type)
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("function"), f.get("vuln_type"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    return unique

if __name__ == "__main__":
    from cfg_builder import analyze_cfg
    test_code = open(PROJECT_ROOT / "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs").read()
    cfg = analyze_cfg(test_code)
    findings = analyze_cfg_security(cfg)
    print(f"Found {len(findings)} CFG security findings")
    for f in findings:
        print(f"  [{f['severity']}] {f['vuln_type']} in {f['function']}:{f['line']}")

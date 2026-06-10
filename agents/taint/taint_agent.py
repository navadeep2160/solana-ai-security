"""
Taint Analysis Agent — Week 4
Zero hardcoded sinks or checks.
AST extracts raw facts → KB defines dangerous patterns → AI reasons about flows.
"""
import json
from models.ollama_client import load_model
from utils.logger import write_log


def extract_raw_facts(contract: str) -> dict:
    """
    Extract ONLY raw structural facts — no vulnerability logic.
    What operations exist, what variables flow where.
    """
    from analysis.ast_parser.rust_ast_parser import parse_rust_ast
    ast = parse_rust_ast(contract)

    facts = {"functions": {}}

    for fn in ast.functions:
        facts["functions"][fn.name] = {
            "line":       fn.line,
            "params":     fn.params,
            "has_signer": fn.has_signer,
            "has_owner":  fn.has_owner_check,
            "has_math":   fn.has_checked_math,
            "raw_lines":  [],
        }

    # Extract raw code lines per function
    lines = contract.split("\n")
    current_fn = None
    depth = 0
    for i, line in enumerate(lines, 1):
        import re
        m = re.match(r'\s*pub fn (\w+)\s*\(', line)
        if m and m.group(1) in facts["functions"]:
            current_fn = m.group(1)
            depth = 0
        if current_fn:
            depth += line.count("{") - line.count("}")
            facts["functions"][current_fn]["raw_lines"].append(
                {"line": i, "code": line.rstrip()})
            if depth < 0:
                current_fn = None

    return facts


def analyze_taint(contract: str) -> list:
    """
    Main entry — pure KB+AI driven taint analysis.
    No hardcoded sinks or checks.
    """
    print("[TAINT] Extracting raw AST facts...")
    facts = extract_raw_facts(contract)

    fn_count = len(facts["functions"])
    print(f"[TAINT] {fn_count} functions extracted")

    # Query KB for what constitutes dangerous patterns
    from kb.kb_router import query_sc_rules, query_vuln_nodes
    kb_sinks   = query_sc_rules("dangerous sink state mutation transfer lamports", top_k=3)
    kb_sources = query_sc_rules("user controlled input parameter taint source", top_k=2)
    kb_checks  = query_sc_rules("security check validation signer owner require", top_k=2)

    kb_context = "DANGEROUS PATTERNS FROM KB:\n"
    kb_context += "\n".join(r["content"][:200] for r in kb_sinks)
    kb_context += "\nUSER INPUT PATTERNS:\n"
    kb_context += "\n".join(r["content"][:150] for r in kb_sources)
    kb_context += "\nSECURITY CHECK PATTERNS:\n"
    kb_context += "\n".join(r["content"][:150] for r in kb_checks)

    # Build function summary for AI
    fn_summary = []
    for fname, fdata in facts["functions"].items():
        code_sample = "\n".join(
            l["code"] for l in fdata["raw_lines"]
            if l["code"].strip()
        )[:500]
        fn_summary.append({
            "name":       fname,
            "line":       fdata["line"],
            "has_signer": fdata["has_signer"],
            "has_owner":  fdata["has_owner"],
            "has_math":   fdata["has_math"],
            "code":       code_sample,
        })

    llm = load_model()

    prompt = f"""You are a Solana taint analysis expert.

Analyze these functions for taint vulnerabilities — where user-controlled
input flows to dangerous operations without security validation.

Use the KB context below to understand what constitutes:
- Dangerous sinks (state mutations, transfers, authority changes)
- User-controlled sources (function parameters, remaining_accounts)
- Missing security checks

KB CONTEXT:
{kb_context[:1500]}

FUNCTIONS TO ANALYZE:
{json.dumps(fn_summary, indent=2)[:3000]}

For each function where user input reaches a dangerous sink without
a security check, report a taint finding.

Return ONLY valid JSON:
{{
  "findings": [
    {{
      "type": "descriptive_taint_type",
      "severity": "critical|high|medium|low",
      "function": "function_name",
      "taint_source": "what user controls e.g. amount parameter",
      "taint_sink": "what dangerous operation it reaches",
      "missing_check": "what validation is absent",
      "reason": "why this taint flow is dangerous",
      "line": <line number>,
      "novel": true
    }}
  ]
}}

novel=true if this finding has no direct KB node match.
Only report real taint flows with clear evidence."""

    try:
        raw = llm.invoke(prompt).content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result   = json.loads(raw.strip())
        findings = result.get("findings", [])
        for f in findings:
            f["source"] = "taint_analysis"
        print(f"[TAINT] {len(findings)} taint findings")
        write_log("taint", {"fn_count": fn_count, "findings": findings})
        return findings
    except Exception as e:
        print(f"[TAINT] Failed: {e}")
        return []


if __name__ == "__main__":
    import sys; sys.path.insert(0, '.')
    code = open(
        "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs"
    ).read()
    findings = analyze_taint(code)
    print(f"\nTaint findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['type']} in {f['function']}")
        print(f"    Source : {f.get('taint_source','')}")
        print(f"    Sink   : {f.get('taint_sink','')}")
        print(f"    Novel  : {f.get('novel',False)}")

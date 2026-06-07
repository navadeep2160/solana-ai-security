"""
V3 Scanner — True KB-driven vulnerability detection.
Flow: Code → AST Facts → Dynamic KB Query → Node Matching → AI Reasoning → Findings
Zero hardcoded vulnerability names or rules.
"""
import os, json, warnings
os.environ["ANONYMIZED_TELEMETRY"] = "False"
warnings.filterwarnings("ignore")

from utils.logger import write_log


def extract_ast_facts(ast_result) -> list:
    facts = []
    for fn in ast_result.functions:
        facts.append({
            "entity_type": "function",
            "name":        fn.name,
            "line":        fn.line,
            "operations":  fn.params,
            "has_signer":  fn.has_signer,
            "has_owner":   fn.has_owner_check,
            "has_math":    fn.has_checked_math,
        })
    for struct in ast_result.account_structs:
        for field in struct.fields:
            facts.append({
                "entity_type":    "account_field",
                "struct_name":    struct.name,
                "field_name":     field["name"],
                "account_type":   field["type"],
                "is_signer":      field["is_signer"],
                "is_account_info":field["is_account_info"],
                "has_constraint": field["has_constraint"],
                "line":           field["line"],
            })
    return facts


def build_dynamic_query(fact: dict) -> str:
    parts = []
    if fact["entity_type"] == "function":
        parts.append(fact["name"])
        if not fact["has_signer"]:
            parts.append("no signer authentication")
        if not fact["has_owner"]:
            parts.append("no owner authorization")
        if not fact["has_math"]:
            parts.append("unsafe arithmetic overflow underflow")
    elif fact["entity_type"] == "account_field":
        parts.append(fact["account_type"])
        parts.append(fact["field_name"])
        if fact["is_account_info"] and not fact["is_signer"]:
            parts.append("AccountInfo missing signer")
        if not fact["has_constraint"]:
            parts.append("no constraint validation")
    return " ".join(parts)


def scan_contract_v3(contract: str) -> dict:
    from analysis.ast_parser.rust_ast_parser import parse_rust_ast
    from kb.kb_router import query_vuln_nodes, query_sc_rules
    from models.ollama_client import load_model

    print("[SCANNER-V3] Parsing AST...")
    ast_result = parse_rust_ast(contract)
    facts      = extract_ast_facts(ast_result)
    print(f"[SCANNER-V3] {len(facts)} AST facts extracted")

    print("[SCANNER-V3] Matching facts → KB nodes...")

    # Deduplicate by vuln name only (not per-function)
    seen_vulns = {}
    for fact in facts:
        query = build_dynamic_query(fact)
        nodes = query_vuln_nodes(query, top_k=3)
        for node in nodes:
            if node["relevance"] < 0.35:
                continue
            name = node["name"]
            # Keep highest relevance match per vuln
            if name not in seen_vulns or \
               node["relevance"] > seen_vulns[name]["node"]["relevance"]:
                chunks = query_sc_rules(query, top_k=2)
                seen_vulns[name] = {
                    "fact":   fact,
                    "node":   node,
                    "chunks": chunks,
                }

    matched = list(seen_vulns.values())
    print(f"[SCANNER-V3] {len(matched)} unique vulnerabilities matched")

    if not matched:
        return {"risks": [], "method": "v3"}

    # Build match summary for AI
    match_summary = [
        {
            "vuln_name":  m["node"]["name"],
            "severity":   m["node"]["severity"],
            "relevance":  m["node"]["relevance"],
            "kb_fix":     m["node"]["fix"][:120],
            "evidence":   f"{m['fact'].get('name') or m['fact'].get('field_name','')} "
                          f"at line {m['fact'].get('line',0)} "
                          f"type={m['fact'].get('account_type') or m['fact'].get('entity_type','')}",
        }
        for m in matched
    ]

    kb_context = "\n".join(
        f"[{m['node']['name']}] {m['chunks'][0]['content'][:150]}"
        for m in matched[:6] if m["chunks"]
    )

    print("[SCANNER-V3] AI confirming matches...")
    llm = load_model()

    prompt = f"""You are a Solana smart contract security scanner.

AST analysis matched {len(matched)} vulnerability patterns from the KB.
Review each match against the contract code and confirm findings.

CONTRACT:
{contract[:2500]}

KB MATCHES (confirm each one):
{json.dumps(match_summary, indent=2)[:3000]}

KB CONTEXT:
{kb_context[:800]}

Return ALL confirmed vulnerabilities. Be thorough — if KB matched it with
relevance > 0.35 and the contract has that code pattern, confirm it.

Return ONLY valid JSON:
{{
  "risks": [
    {{
      "type": "exact vuln_name from KB MATCHES",
      "severity": "severity from KB MATCHES",
      "reason": "specific code evidence from contract",
      "line": <line number>,
      "fix": "kb_fix from KB MATCHES",
      "source": "ast_kb_v3"
    }}
  ]
}}"""

    try:
        raw = llm.invoke(prompt).content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        result = json.loads(raw.strip())
    except Exception as e:
        print(f"[SCANNER-V3] AI failed: {e} — using node matches directly")
        result = {"risks": [
            {
                "type":     m["node"]["name"],
                "severity": m["node"]["severity"],
                "reason":   f"KB node match (relevance={m['node']['relevance']}) "
                            f"at {m['fact'].get('name') or m['fact'].get('field_name','')}",
                "line":     m["fact"].get("line", 0),
                "fix":      m["node"]["fix"][:120],
                "source":   "ast_kb_v3_direct"
            }
            for m in matched
        ]}

    result["method"]      = "v3"
    result["facts_count"] = len(facts)
    result["matches"]     = len(matched)

    log_path = write_log("scanner_v3", result)
    print(f"[SCANNER-V3] Log → {log_path}")
    print(f"[SCANNER-V3] {len(result.get('risks',[]))} findings confirmed")
    return result


if __name__ == "__main__":
    import sys
    sys.path.insert(0, '.')

    path = (sys.argv[1] if len(sys.argv) > 1
            else "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs")
    with open(path) as f:
        code = f.read()

    result = scan_contract_v3(code)

    print(f"\n{'='*55}")
    print("V3 SCAN RESULTS")
    print(f"{'='*55}")
    for r in result.get("risks", []):
        icon = ("🔴" if r["severity"]=="critical" else
                "🟠" if r["severity"]=="high" else
                "🟡" if r["severity"]=="medium" else "🟢")
        print(f"{icon} [{r['severity'].upper():8}] {r['type']}")
        print(f"   Reason : {r['reason'][:80]}")
        print(f"   Fix    : {r['fix'][:80]}")
        print(f"   Line   : {r.get('line',0)}")
    print(f"\nMethod: {result['method']} | "
          f"Facts: {result['facts_count']} | "
          f"Matches: {result['matches']}")

"""
State Machine Analysis Agent — Week 4
Zero hardcoded states, transitions, or keywords.
AST extracts raw function operations → KB defines state patterns → AI builds graph.
"""
import json
from models.ollama_client import load_model
from utils.logger import write_log


def extract_state_facts(contract: str) -> dict:
    """Extract raw function code and fields — no vulnerability logic."""
    from analysis.ast_parser.rust_ast_parser import parse_rust_ast
    import re

    ast   = parse_rust_ast(contract)
    lines = contract.split("\n")
    facts = {"functions": {}, "state_fields": []}

    # Extract state fields — just field names and types, no interpretation
    for line in lines:
        m = re.match(r'\s+pub\s+(\w+)\s*:\s*(\w+)', line)
        if m and m.group(2) in ["bool", "u64", "Pubkey", "i64", "u32", "i32"]:
            facts["state_fields"].append(
                {"name": m.group(1), "type": m.group(2)})

    # Extract raw code per function — no tagging
    for fn in ast.functions:
        fn_lines = lines[max(0, fn.line-1):fn.line+25]
        facts["functions"][fn.name] = {
            "line": fn.line,
            "code": "\n".join(fn_lines)[:400],
        }

    return facts


def analyze_state_machine(contract: str) -> list:
    """KB+AI driven state machine analysis. Zero hardcoded states."""
    print("[STATE] Extracting state facts...")
    facts = extract_state_facts(contract)
    print(f"[STATE] Fields: {[f['name'] for f in facts['state_fields']]}")
    print(f"[STATE] Functions: {list(facts['functions'].keys())}")

    from kb.kb_router import query_sc_rules, query_vuln_nodes
    kb1 = query_sc_rules("state transition sequence vulnerability", top_k=3)
    kb2 = query_vuln_nodes("reinitialization closing account state machine", top_k=3)
    kb_context  = "\n".join(r["content"][:200] for r in kb1)
    kb_context += "\n".join(r.get("content","")[:150] for r in kb2)

    llm = load_model()

    fn_code_summary = "\n\n".join(
        f"Function: {name}\n{data['code']}"
        for name, data in facts["functions"].items()
    )

    prompt = f"""You are a Solana smart contract state machine analyzer.

Analyze this contract's functions and state fields.
Build a state machine showing what states the contract can be in
and what transitions are valid or invalid.

CONTRACT STATE FIELDS:
{json.dumps(facts['state_fields'], indent=2)}

FUNCTION CODE:
{fn_code_summary[:3000]}

KB CONTEXT ON STATE VULNERABILITIES:
{kb_context[:800]}

Tasks:
1. Identify the implicit states from field values and function behavior
2. Build valid and invalid transition sequences
3. Report findings for invalid transitions

Do NOT use hardcoded state names — derive them from the actual code.

Return ONLY valid JSON:
{{
  "state_graph": {{
    "states": ["state names derived from code"],
    "valid_transitions": [
      {{"from": "state", "to": "state", "via": "function_name"}}
    ],
    "invalid_transitions": [
      {{"from": "state", "to": "state", "via": "function_name",
        "reason": "why invalid"}}
    ]
  }},
  "findings": [
    {{
      "type": "state_transition_vulnerability",
      "severity": "critical|high|medium|low",
      "sequence": "fn_a then fn_b",
      "functions_involved": ["fn_a", "fn_b"],
      "reason": "why this transition is dangerous",
      "line": <line number>,
      "source": "state_machine"
    }}
  ]
}}"""

    try:
        raw = llm.invoke(prompt).content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result   = json.loads(raw.strip())
        findings = result.get("findings", [])
        graph    = result.get("state_graph", {})
        for f in findings:
            f["source"] = "state_machine"
        print(f"[STATE] States: {graph.get('states',[])}")
        print(f"[STATE] {len(findings)} findings")
        write_log("state_machine", {"graph": graph, "findings": findings})
        return findings
    except Exception as e:
        print(f"[STATE] Failed: {e}")
        return []


if __name__ == "__main__":
    import sys; sys.path.insert(0, '.')
    code = open(
        "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs").read()
    findings = analyze_state_machine(code)
    print(f"\n{len(findings)} findings")
    for f in findings:
        print(f"  [{f['severity']}] {f.get('sequence','')} — {f.get('reason','')[:60]}")

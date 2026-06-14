"""
Interprocedural CFG Agent — Week 4
Zero hardcoded operators or field patterns.
AST extracts raw per-function code → KB defines dangerous patterns → AI reasons.
"""
import json
from models.ollama_client import load_model
from utils.logger import write_log


def extract_interprocedural_facts(contract: str) -> dict:
    """Extract raw function code and shared fields — no vulnerability logic."""
    from analysis.ast_parser.rust_ast_parser import parse_rust_ast
    import re

    ast   = parse_rust_ast(contract)
    lines = contract.split("\n")
    facts = {"functions": {}, "shared_state": []}

    # Shared state fields — names only
    for line in lines:
        m = re.match(r'\s+pub\s+(\w+)\s*:\s*(\w+)', line)
        if m and m.group(2) in ["bool", "u64", "Pubkey", "i64", "u32"]:
            facts["shared_state"].append(m.group(1))

    # Raw code per function — let AI interpret
    for fn in ast.functions:
        fn_lines = lines[max(0, fn.line-1):fn.line+25]
        facts["functions"][fn.name] = {
            "line":       fn.line,
            "has_signer": fn.has_signer,
            "has_owner":  fn.has_owner_check,
            "code":       "\n".join(fn_lines)[:400],
        }

    return facts


def analyze_interprocedural(contract: str) -> list:
    """KB+AI driven interprocedural analysis."""
    print("[INTERPROC] Extracting facts...")
    facts = extract_interprocedural_facts(contract)
    print(f"[INTERPROC] Shared state: {facts['shared_state']}")

    from kb.kb_router import query_sc_rules, query_vuln_nodes
    kb1 = query_sc_rules("cross function state validation authorization", top_k=3)
    kb2 = query_vuln_nodes("missing owner check authorization state", top_k=2)
    kb_context  = "\n".join(r["content"][:200] for r in kb1)
    kb_context += "\n".join(r.get("content","")[:150] for r in kb2)

    fn_summary = "\n\n".join(
        f"Function: {name} (signer={d['has_signer']} owner={d['has_owner']})\n{d['code']}"
        for name, d in facts["functions"].items()
    )

    llm = load_model()

    prompt = f"""You are a Solana interprocedural security analyzer.

Find cross-function bugs — state set in one function used unsafely in another.

SHARED STATE FIELDS: {facts['shared_state']}

FUNCTION CODE:
{fn_summary[:3000]}

KB CONTEXT:
{kb_context[:800]}

Find patterns like:
- Function A writes state, Function B reads it without re-validating ownership
- Function A initializes, Function B can bypass that
- State assumed valid in B but never checked after A modified it

Return ONLY valid JSON:
{{
  "call_graph": [
    {{"writer": "fn_a", "state": "field", "reader": "fn_b",
      "safe": true|false}}
  ],
  "findings": [
    {{
      "type": "interprocedural_bug_name",
      "severity": "critical|high|medium|low",
      "writer_function": "fn that sets state",
      "reader_function": "fn that reads unsafely",
      "shared_state":    "field involved",
      "missing_check":   "what validation is absent",
      "reason":          "why dangerous",
      "line":            <line>,
      "source":          "interprocedural_cfg"
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
        for f in findings:
            f["source"] = "interprocedural_cfg"
        print(f"[INTERPROC] {len(findings)} findings")
        write_log("interprocedural", result)
        return findings
    except Exception as e:
        print(f"[INTERPROC] Failed: {e}")
        return []


if __name__ == "__main__":
    import sys; sys.path.insert(0, '.')
    code = open(
        "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs").read()
    findings = analyze_interprocedural(code)
    print(f"\n{len(findings)} findings")
    for f in findings:
        print(f"  [{f['severity']}] {f['writer_function']} → "
              f"{f['reader_function']}: {f['reason'][:60]}")

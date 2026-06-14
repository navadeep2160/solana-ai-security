"""
KB-driven AST vulnerability analyzer.
AST parser extracts structure (functions, structs, fields).
This module takes that structure and asks AI+KB what's vulnerable.
Zero hardcoded vulnerability logic here.
"""
import json
import os
import warnings
os.environ["ANONYMIZED_TELEMETRY"] = "False"
warnings.filterwarnings("ignore")

from dotenv import load_dotenv
load_dotenv()


def analyze_ast_with_kb(ast_result, full_code: str) -> list:
    """
    Takes ASTResult (already parsed structure) and runs
    KB-driven AI analysis to find vulnerabilities.
    Returns list of findings.
    """
    from kb.kb_router import query_sc_rules, query_audit_findings
    from models.ollama_client import load_model

    # Build structured summary of what AST found
    functions_summary = []
    for fn in ast_result.functions:
        functions_summary.append({
            "name":            fn.name,
            "line":            fn.line,
            "has_signer":      fn.has_signer,
            "has_owner_check": fn.has_owner_check,
            "has_safe_math":   fn.has_checked_math,
            "params":          fn.params,
        })

    structs_summary = []
    for s in ast_result.account_structs:
        structs_summary.append({
            "name":   s.name,
            "line":   s.line,
            "fields": [
                {
                    "name":            f["name"],
                    "type":            f["type"],
                    "is_signer":       f["is_signer"],
                    "is_account_info": f["is_account_info"],
                    "has_constraint":  f["has_constraint"],
                    "attributes":      f["attributes"],
                    "line":            f["line"],
                }
                for f in s.fields
            ]
        })

    # Query KB
    queries = [
        "missing signer AccountInfo authentication Anchor struct",
        "missing owner check authorization has_one constraint function",
        "unsafe arithmetic overflow underflow checked_sub checked_add",
        "account closure rent lamports close constraint",
        "reinitialization frontrunning initialize function",
        "CPI arbitrary program invoke authority",
        "duplicate mutable accounts transfer",
    ]

    kb_chunks = []
    seen = set()
    for q in queries:
        for fn in [query_sc_rules, query_audit_findings]:
            try:
                results = fn(q, top_k=2)
                for r in results:
                    chunk = r.get("content", "")[:350]
                    if chunk and chunk not in seen:
                        kb_chunks.append({
                            "source":  r.get("source", r.get("rule_id", "KB")),
                            "content": chunk
                        })
                        seen.add(chunk)
            except Exception:
                pass

    kb_context = "\n\n".join(
        f"[{c['source']}]\n{c['content']}" for c in kb_chunks
    )

    llm = load_model(force_local=True)

    prompt = f"""You are a Solana smart contract AST security analyzer.

You have the parsed AST structure of an Anchor smart contract.
Use the knowledge base to identify ALL security vulnerabilities
present in this structure. Be specific — cite exact field names,
function names, and line numbers from the AST data.

AST STRUCTURE:
Functions: {json.dumps(functions_summary, indent=2)}

Account Structs: {json.dumps(structs_summary, indent=2)}

KNOWLEDGE BASE:
{kb_context[:3000]}

Return ONLY valid JSON:
{{
  "findings": [
    {{
      "type": "vulnerability_identifier",
      "severity": "critical|high|medium|low",
      "location": "struct Name, field fieldname, line N  OR  fn funcname, line N",
      "description": "what is wrong based on KB knowledge",
      "evidence": "specific field/function name and type that shows the problem",
      "fix": "concrete fix based on KB",
      "line": <integer line number>,
      "kb_source": "which KB source informed this"
    }}
  ]
}}

Do not flag fields named: target_program, system_program, token_program, rent, clock.
Only report findings with clear evidence in the AST data.
Every finding must have an accurate line number."""

    try:
        result = llm.invoke(prompt)
        raw = result.content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw.strip())
        findings = data.get("findings", [])
        print(f"[AST-KB] {len(findings)} findings from KB-driven AST analysis")
        return findings
    except Exception as e:
        print(f"[AST-KB] Analysis failed: {e}")
        return []


def analyze_cfg_with_kb(cfg_result: dict, full_code: str) -> list:
    """
    Takes CFG analysis result (functions + blocks with tags)
    and runs KB-driven AI analysis to find vulnerabilities.
    Returns list of findings.
    """
    from kb.kb_router import query_sc_rules, query_audit_findings
    from models.ollama_client import load_model

    # Use structured facts from CFG (no vulnerability logic in CFG builder)
    cfg_summary = []
    function_facts = cfg_result.get("function_facts", {})
    if function_facts:
        for fn_name, fn_data in function_facts.items():
            cfg_summary.append({
                "function":     fn_name,
                "struct_signer": fn_data.get("struct_signer", False),
                "struct_owner":  fn_data.get("struct_owner", False),
                "blocks":        fn_data.get("blocks", []),
            })
    else:
        # Fallback for old format
        for fn_name, fn_cfg in cfg_result.get("graphs", {}).items():
            cfg_summary.append({"function": fn_name, "blocks": []})

    # Query KB for execution path vulnerability patterns
    queries = [
        "state mutation before security check execution path",
        "operation before require check validation order",
        "unchecked arithmetic execution path function",
        "no security checks function withdraw transfer",
        "CPI before owner check cross program invocation",
    ]

    kb_chunks = []
    seen = set()
    for q in queries:
        for fn in [query_sc_rules, query_audit_findings]:
            try:
                results = fn(q, top_k=2)
                for r in results:
                    chunk = r.get("content", "")[:350]
                    if chunk and chunk not in seen:
                        kb_chunks.append({
                            "source":  r.get("source", r.get("rule_id", "KB")),
                            "content": chunk
                        })
                        seen.add(chunk)
            except Exception:
                pass

    kb_context = "\n\n".join(
        f"[{c['source']}]\n{c['content']}" for c in kb_chunks
    )

    llm = load_model(force_local=True)

    prompt = f"""You are a Solana smart contract CFG (Control Flow Graph) security analyzer.

You have the CFG block structure of an Anchor smart contract.
Each block shows what security checks and operations are present.
Use the knowledge base to identify execution path vulnerabilities.

CFG STRUCTURE (functions and their basic blocks):
{json.dumps(cfg_summary, indent=2)[:3000]}

KNOWLEDGE BASE:
{kb_context[:2500]}

Analyze for:
- unchecked_math=true with no safe math alternative
- has_transfer=true with has_signer=false AND has_owner=false
- has_cpi=true with has_owner=false
- has_close=true with has_signer=false
- Functions in sensitive set (withdraw, transfer, close_account)
  with no signer or owner checks in ANY block

Return ONLY valid JSON:
{{
  "findings": [
    {{
      "type": "vulnerability_identifier",
      "severity": "critical|high|medium|low",
      "function": "function name",
      "block_id": "block identifier",
      "line": <line_start of the block>,
      "description": "what execution path issue exists based on KB",
      "evidence": "specific block tags that indicate the problem",
      "fix": "how to fix based on KB",
      "kb_source": "which KB source informed this"
    }}
  ]
}}

Only report findings with clear evidence in the CFG data.
Every finding must have an accurate line number."""

    try:
        result = llm.invoke(prompt)
        raw = result.content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw.strip())
        findings = data.get("findings", [])
        print(f"[CFG-KB] {len(findings)} findings from KB-driven CFG analysis")
        return findings
    except Exception as e:
        print(f"[CFG-KB] Analysis failed: {e}")
        return []

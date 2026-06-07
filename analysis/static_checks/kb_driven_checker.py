"""
KB-driven static checker — Zero hardcoded rules.
Queries KB for vulnerability patterns, uses AI to derive
what to look for in the contract, returns findings.
"""
import re
import os
import json
import warnings
os.environ["ANONYMIZED_TELEMETRY"] = "False"
warnings.filterwarnings("ignore")

from dotenv import load_dotenv
load_dotenv()

SKIP_FIELDS = {
    "target_program", "program", "token_program",
    "system_program", "rent", "clock",
    "associated_token_program", "metadata_program",
}


def run_all_checks(code: str) -> list:
    """
    Main entry — queries KB, asks AI what patterns to look for,
    applies them to the contract. No hardcoded rules.
    """
    from kb.kb_router import query_sc_rules, query_audit_findings
    from models.ollama_client import load_model

    print("[CHECKER] Querying KB for vulnerability patterns...")

    # Pull broad context from KB
    queries = [
        "missing signer authentication AccountInfo Anchor",
        "missing owner authorization has_one constraint",
        "integer overflow underflow arithmetic",
        "account closure rent PDA",
        "CPI arbitrary program invoke",
        "duplicate mutable accounts reinitialization",
    ]

    kb_chunks = []
    seen = set()
    for q in queries:
        for fn in [query_sc_rules, query_audit_findings]:
            try:
                results = fn(q, top_k=2)
                for r in results:
                    chunk = r.get("content", "")[:400]
                    if chunk and chunk not in seen:
                        kb_chunks.append({
                            "source": r.get("source", r.get("rule_id", "KB")),
                            "content": chunk
                        })
                        seen.add(chunk)
            except Exception:
                pass

    kb_context = "\n\n".join(
        f"[{c['source']}]\n{c['content']}" for c in kb_chunks
    )
    print(f"[CHECKER] {len(kb_chunks)} KB chunks loaded")

    llm = load_model(force_local=True)

    prompt = f"""You are a Solana smart contract static analyzer.

Given this knowledge base about Solana vulnerabilities, analyze the contract code
and return ALL security findings. Use the KB to determine what constitutes a vulnerability.

CONTRACT CODE:
{code[:3000]}

KNOWLEDGE BASE:
{kb_context[:3000]}

Return ONLY valid JSON — no markdown, no explanation:
{{
  "findings": [
    {{
      "type": "snake_case_vuln_name_from_kb",
      "severity": "critical|high|medium|low",
      "description": "what is wrong and why it is dangerous",
      "line": <integer line number where found>,
      "evidence": "exact code snippet that is vulnerable",
      "fix": "how to fix it",
      "kb_source": "which KB source informed this finding"
    }}
  ]
}}

CRITICAL RULES:
- type field MUST be a snake_case identifier like: missing_signer_check,
  integer_overflow, missing_owner_check, unchecked_account_closure,
  arbitrary_cpi, duplicate_mutable_accounts, reinitialization_attack,
  missing_admin_check, precision_loss — never use generic names
- Only report findings that have clear evidence in the code
- Line numbers must be accurate integers
- Every finding must cite a kb_source from the KB above
- AccountInfo fields named: {list(SKIP_FIELDS)} are intentional — do not flag them
- If no vulnerabilities found, return {{"findings": []}}"""

    try:
        result = llm.invoke(prompt)
        raw = result.content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw.strip())
        findings = data.get("findings", [])
        print(f"[CHECKER] {len(findings)} findings from KB-driven AI analysis")
        return findings
    except Exception as e:
        print(f"[CHECKER] Analysis failed: {e}")
        return []

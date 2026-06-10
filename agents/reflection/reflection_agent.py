"""
Reflection Agent — Week 4
Reads original + patched code + all findings → scores patch quality.
Identifies missed vulnerabilities and over-patching.
"""
import json
from models.ollama_client import load_model
from utils.logger import write_log


def reflect_on_patch(original_code: str, patched_code: str,
                     findings: list, exploit_results: dict) -> tuple[float, str]:
    """
    AI reflects on patch quality.
    Returns (score 0-10, notes string)
    """
    print("[REFLECTION] Analyzing patch quality...")

    from kb.kb_router import query_sc_rules, query_vuln_nodes

    # Get KB context for what a good patch looks like
    kb = query_sc_rules("secure anchor pattern fix best practice", top_k=3)
    kb_context = "\n".join(r["content"][:200] for r in kb)

    confirmed = [f for f in exploit_results.get("findings", [])
                 if f.get("confirmed")]
    fp        = exploit_results.get("false_positive", 0)
    total     = exploit_results.get("total", 0)

    # Build diff summary
    orig_lines    = set(original_code.split("\n"))
    patched_lines = set(patched_code.split("\n"))
    added   = [l for l in patched_lines - orig_lines if l.strip()][:20]
    removed = [l for l in orig_lines - patched_lines if l.strip()][:20]

    llm = load_model()

    prompt = f"""You are a Solana security code reviewer doing patch quality assessment.

Review this security patch and score its quality.

ORIGINAL VULNERABLE CODE (first 1500 chars):
{original_code[:1500]}

PATCHED CODE (first 1500 chars):
{patched_code[:1500]}

KEY CHANGES (added lines):
{chr(10).join(added[:10])}

FINDINGS SUMMARY:
- Total findings: {len(findings)}
- Confirmed exploits: {len(confirmed)}
- False positives removed: {fp}
- Exploit success rate: {len(confirmed)}/{total}

KB SECURE PATTERNS:
{kb_context[:600]}

Evaluate:
1. Did the patch address the confirmed vulnerabilities?
2. Are the fixes correct Anchor patterns?
3. Were any vulnerabilities missed?
4. Was anything over-patched (broke valid behavior)?
5. Does the patched code follow KB best practices?

Return ONLY valid JSON:
{{
  "score": <float 0.0-10.0>,
  "addressed": ["vuln1 was fixed by..."],
  "missed": ["vuln2 was not addressed because..."],
  "over_patched": ["this change breaks X"],
  "best_practice_compliance": <0-10>,
  "summary": "one paragraph assessment"
}}"""

    try:
        raw = llm.invoke(prompt).content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw.strip())
        score  = float(result.get("score", 5.0))
        notes  = result.get("summary", "")

        print(f"[REFLECTION] Score: {score}/10")
        print(f"[REFLECTION] Addressed: {len(result.get('addressed',[]))}")
        print(f"[REFLECTION] Missed: {len(result.get('missed',[]))}")
        if result.get("missed"):
            for m in result["missed"][:3]:
                print(f"  ⚠️  {m[:80]}")

        write_log("reflection", result)
        return score, notes
    except Exception as e:
        print(f"[REFLECTION] Failed: {e}")
        return 5.0, f"Reflection failed: {e}"


if __name__ == "__main__":
    import sys; sys.path.insert(0, '.')
    from pathlib import Path

    original = Path(
        "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib_original.rs"
    ).read_text()
    patched  = Path("outputs/patched/patched_contract.rs").read_text() \
               if Path("outputs/patched/patched_contract.rs").exists() \
               else original

    score, notes = reflect_on_patch(original, patched, [], {})
    print(f"\nReflection score: {score}/10")
    print(f"Notes: {notes[:200]}")

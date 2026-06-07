"""
Risk Scoring Agent — AI-driven CVSS-style scoring.
Batches findings to avoid rate limits. Uses Ollama fallback.
"""
import json
from utils.logger import write_log


def run_scoring(findings: list, exploit_results: dict = None) -> dict:
    from models.ollama_client import load_model
    from kb.kb_router import query_sc_rules, query_vuln_nodes

    llm = load_model()

    # Build exploit lookup
    exploit_map = {}
    if exploit_results:
        for ef in exploit_results.get("findings", []):
            key = ef.get("vulnerability", "")
            exploit_map[key] = ef

    # Remove false positives
    active, removed = [], []
    for finding in findings:
        vuln = finding.get("type", finding.get("vulnerability", "unknown"))
        ef = exploit_map.get(vuln, {})
        if ef.get("result") == "FALSE_POSITIVE":
            removed.append(vuln)
        else:
            active.append(finding)

    print(f"[SCORER] Scoring {len(active)} findings "
          f"({len(removed)} false positives removed)")

    # Deduplicate by type for scoring
    seen, unique_findings = set(), []
    for f in active:
        vuln = f.get("type", f.get("vulnerability", "unknown"))
        if vuln not in seen:
            seen.add(vuln)
            unique_findings.append(f)

    # Batch score all findings in ONE LLM call
    findings_for_prompt = []
    for f in unique_findings:
        vuln = f.get("type", f.get("vulnerability", "unknown"))
        ef   = exploit_map.get(vuln, {})

        # Get KB context
        kb = query_vuln_nodes(vuln, top_k=1)
        kb_severity = kb[0]["severity"] if kb else "medium"
        kb_fix      = kb[0]["fix"][:100] if kb else ""

        findings_for_prompt.append({
            "type":              vuln,
            "severity":          f.get("severity", "medium"),
            "description":       f.get("reason", f.get("description", ""))[:100],
            "source":            f.get("source", "static"),
            "runtime_confirmed": ef.get("confirmed", False),
            "poc_tx":            bool(ef.get("poc_tx", "")),
            "kb_severity":       kb_severity,
            "kb_fix":            kb_fix,
        })

    prompt = f"""You are a Solana security scoring expert.

Score ALL these findings using CVSS-style reasoning.
Return a JSON array with one score per finding.

FINDINGS:
{json.dumps(findings_for_prompt, indent=2)[:3000]}

Rules:
- CONFIRMED runtime exploit → score >= 8.0, level CRITICAL or HIGH
- Static only, no runtime confirmation → max score 7.0
- Use kb_severity to inform scoring
- Balance drained in PoC → impact = 10

Return ONLY valid JSON array:
[
  {{
    "type": "exact type from finding",
    "score": <float 0.0-10.0>,
    "level": "CRITICAL|HIGH|MEDIUM|LOW",
    "exploitability": <0-10>,
    "impact": <0-10>,
    "confidence": <0-10>,
    "reasoning": "one sentence"
  }}
]"""

    scored_map = {}
    try:
        raw = llm.invoke(prompt).content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        scores = json.loads(raw.strip())
        if isinstance(scores, list):
            for s in scores:
                scored_map[s.get("type","").lower()] = s
        elif isinstance(scores, dict) and "scores" in scores:
            for s in scores["scores"]:
                scored_map[s.get("type","").lower()] = s
    except Exception as e:
        print(f"[SCORER] Batch scoring failed: {e} — using KB-based fallback")

    # Build final scored list
    scored = []
    for f in unique_findings:
        vuln = f.get("type", f.get("vulnerability", "unknown"))
        ef   = exploit_map.get(vuln, {})
        confirmed = ef.get("confirmed", False)

        # Try batch result first, then KB fallback
        s = scored_map.get(vuln.lower(), {})
        if not s:
            # KB-based fallback scoring
            kb = query_vuln_nodes(vuln, top_k=1)
            kb_sev = kb[0]["severity"] if kb else "medium"
            base = 9.0 if confirmed else \
                   8.5 if kb_sev == "critical" else \
                   7.0 if kb_sev == "high" else \
                   5.0 if kb_sev == "medium" else 3.0
            s = {
                "score":         base,
                "level":         "CRITICAL" if base >= 9 else
                                 "HIGH" if base >= 7 else
                                 "MEDIUM" if base >= 5 else "LOW",
                "exploitability": 8 if confirmed else 6,
                "impact":         9 if confirmed else 6,
                "confidence":     9 if confirmed else 5,
                "reasoning":      f"KB severity={kb_sev}, runtime={'confirmed' if confirmed else 'static'}"
            }

        scored.append({
            "vulnerability":  vuln,
            "score":          round(float(s.get("score", 5.0)), 2),
            "level":          s.get("level", "MEDIUM"),
            "exploitability": s.get("exploitability", 5),
            "impact":         s.get("impact", 5),
            "confidence":     s.get("confidence", 5),
            "reasoning":      s.get("reasoning", ""),
            "confirmed":      confirmed,
            "poc_tx":         ef.get("poc_tx", ""),
            "source":         f.get("source", "static"),
            "description":    f.get("reason", f.get("description", "")),
        })

    scored.sort(key=lambda x: x["score"], reverse=True)

    output = {
        "total":    len(scored),
        "critical": sum(1 for s in scored if s["level"] == "CRITICAL"),
        "high":     sum(1 for s in scored if s["level"] == "HIGH"),
        "medium":   sum(1 for s in scored if s["level"] == "MEDIUM"),
        "low":      sum(1 for s in scored if s["level"] == "LOW"),
        "false_positives_removed": len(removed),
        "removed":  removed,
        "findings": scored,
    }

    log_path = write_log("scorer", output)
    print(f"\n[SCORER] Log → {log_path}")
    print(f"\n{'='*55}")
    print("RISK SCORING SUMMARY")
    print(f"{'='*55}")
    for f in scored:
        icon = ("🔴" if f["level"] == "CRITICAL" else
                "🟠" if f["level"] == "HIGH" else
                "🟡" if f["level"] == "MEDIUM" else "🟢")
        conf = "✅ runtime" if f["confirmed"] else "📋 static"
        print(f"  {icon} [{f['score']:4.1f}] {f['level']:8s} "
              f"{f['vulnerability'][:35]:35s} {conf}")
    print(f"  False positives removed: {len(removed)}")
    print(f"{'='*55}")
    return output

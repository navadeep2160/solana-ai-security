"""
Risk Scoring Agent — AI-driven CVSS-style scoring.
Gemini reasons about each finding using KB context.
No hardcoded scores.
"""
import json
from utils.logger import write_log


def run_scoring(findings: list, exploit_results: dict = None) -> dict:
    from models.ollama_client import load_model
    from kb.kb_router import query_sc_rules, query_audit_findings

    llm = load_model("scan_model")

    # Build exploit lookup
    exploit_map = {}
    if exploit_results:
        for ef in exploit_results.get("findings", []):
            key = ef.get("vulnerability","")
            exploit_map[key] = ef

    scored   = []
    removed  = []

    for finding in findings:
        vuln = finding.get("type", finding.get("vulnerability","unknown"))

        # Check if exploit confirmed it
        exploit_ev = exploit_map.get(vuln, {})
        confirmed  = exploit_ev.get("confirmed", False)
        poc_tx     = exploit_ev.get("poc_tx", "")

        if exploit_ev.get("result") == "FALSE_POSITIVE":
            removed.append(vuln)
            continue

        # Get KB context for this vulnerability
        kb = query_sc_rules(vuln, top_k=2)
        kb_text = "\n".join(r["content"] for r in kb)[:600]

        state_before = exploit_ev.get("state_before", {})
        state_after  = exploit_ev.get("state_after", {})

        prompt = f"""You are a Solana security scoring expert.

FINDING:
type: {vuln}
severity: {finding.get('severity','unknown')}
description: {finding.get('reason', finding.get('description',''))}
source: {finding.get('source','static')}

RUNTIME EVIDENCE:
exploit_confirmed: {confirmed}
state_before: {state_before}
state_after: {state_after}
poc_transaction: {"yes" if poc_tx else "no"}

KB CONTEXT:
{kb_text}

Score this finding using CVSS-style reasoning.
Return JSON only, no explanation outside the JSON:
{{
  "score": <float 0.0-10.0>,
  "level": "CRITICAL|HIGH|MEDIUM|LOW",
  "exploitability": <0-10>,
  "impact": <0-10>,
  "confidence": <0-10>,
  "reasoning": "one sentence"
}}

Rules:
- CONFIRMED runtime exploit → score >= 8.0
- No runtime confirmation → max score 7.0
- FALSE_POSITIVE → already removed, skip
- State balance drained → impact = 10
- Only static detection → confidence <= 6"""

        try:
            r = llm.invoke(prompt)
            raw = r.content.strip()
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"): raw = raw[4:]
            score_data = json.loads(raw.strip())
        except Exception as e:
            # Fallback scoring
            base = 9.0 if confirmed else 5.0
            score_data = {
                "score": base,
                "level": "CRITICAL" if base >= 9 else "MEDIUM",
                "exploitability": 8 if confirmed else 5,
                "impact": 9 if confirmed else 5,
                "confidence": 9 if confirmed else 4,
                "reasoning": "AI scoring failed, used fallback"
            }

        scored.append({
            "vulnerability": vuln,
            "score":         round(float(score_data.get("score", 5.0)), 2),
            "level":         score_data.get("level", "MEDIUM"),
            "exploitability":score_data.get("exploitability", 5),
            "impact":        score_data.get("impact", 5),
            "confidence":    score_data.get("confidence", 5),
            "reasoning":     score_data.get("reasoning",""),
            "confirmed":     confirmed,
            "poc_tx":        poc_tx,
            "source":        finding.get("source","static"),
            "description":   finding.get("reason", finding.get("description","")),
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
        icon = "🔴" if f["level"]=="CRITICAL" else \
               "🟠" if f["level"]=="HIGH" else \
               "🟡" if f["level"]=="MEDIUM" else "🟢"
        conf = "✅ runtime" if f["confirmed"] else "📋 static"
        print(f"  {icon} [{f['score']}] {f['level']:8s} {f['vulnerability']:35s} {conf}")
    print(f"  False positives removed: {len(removed)}")
    print(f"{'='*55}")

    return output

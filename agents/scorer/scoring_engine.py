"""
agents/scorer/scoring_engine.py
--------------------------------
Risk Scoring Agent — Week 3

Dynamic scoring — works for ANY vulnerability the exploit agent finds.
No hardcoded vuln names. Score is derived purely from runtime evidence:

  final_score = (exploit_score * 0.5) +
                (state_damage_score * 0.3) +
                (confidence * 10 * 0.2)

Bands:
  9-10  CRITICAL
  7-8   HIGH
  4-6   MEDIUM
  0-3   LOW

FALSE_POSITIVE findings are removed from output.
"""

from __future__ import annotations
from dataclasses import dataclass
from utils.logger import write_log


def score_to_level(score: float) -> str:
    if score >= 9.0:   return "CRITICAL"
    elif score >= 7.0: return "HIGH"
    elif score >= 4.0: return "MEDIUM"
    else:              return "LOW"


def _state_damage_score(state_before: dict, state_after: dict,
                         result: str) -> float:
    """
    Measure actual damage from state change evidence.
    Returns 0-10.

    Rules:
    - Balance drained (after < before)          → 9.0
    - Balance wrapped to huge u64 (underflow)   → 10.0
    - Balance unchanged but tx succeeded        → 5.0
    - Tx rejected (FALSE_POSITIVE)              → 0.0
    - No state info available                   → 5.0 (unknown)
    """
    if result == "FALSE_POSITIVE":
        return 0.0

    before_bal = state_before.get("balance")
    after_bal  = state_after.get("balance")

    if before_bal is None or after_bal is None:
        return 5.0

    # Underflow — balance wrapped to near u64::MAX
    if after_bal > 2**60:
        return 10.0

    # Balance was drained
    if after_bal < before_bal:
        drained_pct = (before_bal - after_bal) / max(before_bal, 1)
        return min(9.0, 6.0 + drained_pct * 3.0)

    # Balance unchanged but tx succeeded (auth bypass confirmed)
    if after_bal == before_bal and result == "CONFIRMED":
        return 5.0

    return 4.0


def _compute_final_score(exploit_score: float, state_damage: float,
                          confidence: float, confirmed: bool) -> float:
    """
    Weighted formula — all inputs are runtime evidence, nothing hardcoded.
    CONFIRMED finding cannot score below 8.0.
    """
    score = (exploit_score  * 0.50 +
             state_damage    * 0.30 +
             confidence * 10 * 0.20)
    score = round(min(score, 10.0), 2)

    if confirmed:
        score = max(score, 8.0)

    return score


@dataclass
class ScoredFinding:
    vulnerability: str
    function:      str
    result:        str
    final_score:   float
    level:         str
    confirmed:     bool
    confidence:    float
    exploit_score: float
    state_damage:  float
    description:   str
    poc_tx:        str
    state_before:  dict
    state_after:   dict

    def to_dict(self) -> dict:
        return {
            "vulnerability": self.vulnerability,
            "function":      self.function,
            "result":        self.result,
            "final_score":   self.final_score,
            "level":         self.level,
            "confirmed":     self.confirmed,
            "confidence":    self.confidence,
            "exploit_score": self.exploit_score,
            "state_damage":  round(self.state_damage, 2),
            "description":   self.description,
            "poc_tx":        self.poc_tx,
            "state_before":  self.state_before,
            "state_after":   self.state_after,
        }


def score_exploit_results(exploit_output: dict) -> dict:
    """
    Main entry point.
    Accepts either raw exploit output dict or the wrapped log format
    {"stage":..., "data": {...}}.
    """
    # Handle wrapped log format
    if "data" in exploit_output:
        exploit_output = exploit_output["data"]

    scored  = []
    removed = []

    for f in exploit_output.get("findings", []):
        result    = f.get("result", "UNCONFIRMED")
        vuln      = f.get("vulnerability", "unknown")
        confirmed = f.get("confirmed", False)
        confidence= f.get("confidence", 0.5)
        raw_score = f.get("score", 0.0)
        s_before  = f.get("state_before", {})
        s_after   = f.get("state_after", {})

        if result == "FALSE_POSITIVE":
            removed.append(vuln)
            continue

        damage = _state_damage_score(s_before, s_after, result)
        final  = _compute_final_score(raw_score, damage, confidence, confirmed)

        scored.append(ScoredFinding(
            vulnerability = vuln,
            function      = f.get("function", ""),
            result        = result,
            final_score   = final,
            level         = score_to_level(final),
            confirmed     = confirmed,
            confidence    = confidence,
            exploit_score = raw_score,
            state_damage  = damage,
            description   = f.get("description", "")[:120],
            poc_tx        = f.get("poc_tx", ""),
            state_before  = s_before,
            state_after   = s_after,
        ))

    scored.sort(key=lambda x: x.final_score, reverse=True)

    output = {
        "total":                   len(scored),
        "critical":                sum(1 for s in scored if s.level == "CRITICAL"),
        "high":                    sum(1 for s in scored if s.level == "HIGH"),
        "medium":                  sum(1 for s in scored if s.level == "MEDIUM"),
        "low":                     sum(1 for s in scored if s.level == "LOW"),
        "false_positives_removed": len(removed),
        "removed":                 removed,
        "findings":                [s.to_dict() for s in scored],
    }

    log_path = write_log("scorer", output)
    print(f"\n[SCORER] Log → {log_path}")
    _print_summary(output)
    return output


def _print_summary(output: dict):
    print(f"\n{'='*60}")
    print("RISK SCORING SUMMARY")
    print(f"{'='*60}")
    print(f"  Total scored            : {output['total']}")
    print(f"  CRITICAL                : {output['critical']}")
    print(f"  HIGH                    : {output['high']}")
    print(f"  MEDIUM                  : {output['medium']}")
    print(f"  LOW                     : {output['low']}")
    print(f"  False positives removed : {output['false_positives_removed']}")
    if output["removed"]:
        print(f"  Removed                 : {', '.join(output['removed'])}")
    print(f"\n  Scored findings:")
    for f in output["findings"]:
        icon = ("🔴" if f["level"] == "CRITICAL" else
                "🟠" if f["level"] == "HIGH" else
                "🟡" if f["level"] == "MEDIUM" else "🟢")
        src  = "✅ runtime confirmed" if f["confirmed"] else "📋 static only"
        dmg  = f"damage={f['state_damage']}"
        print(f"  {icon} [{f['final_score']}] {f['level']:8s}  "
              f"{f['vulnerability']:30s}  {dmg}  {src}")
        if f["state_before"] or f["state_after"]:
            print(f"            before={f['state_before']}  "
                  f"after={f['state_after']}")
    print(f"{'='*60}")


if __name__ == "__main__":
    import json, os
    logs = sorted([
        f for f in os.listdir("outputs/logs")
        if f.startswith("exploit_")
    ])
    if not logs:
        print("No exploit log found. Run exploit_agent first.")
    else:
        with open(f"outputs/logs/{logs[-1]}") as fp:
            exploit_out = json.load(fp)
        score_exploit_results(exploit_out)

"""
Deterministic vulnerability detection engine.
This is your REAL detector (NOT LLM).
"""

def detect(features: dict) -> list:
    findings = []

    # ── TPU / Spam Congestion ─────────────────────────
    if features.get("tx_density", 0) > 5:
        findings.append({
            "type": "TPU_CONGESTION",
            "detected": True,
            "severity": "high",
            "evidence": f"tx_density={features['tx_density']}"
        })

    # ── Validator centralization ──────────────────────
    if features.get("top1_stake_pct", 0) > 33:
        findings.append({
            "type": "VALIDATOR_CENTRALIZATION",
            "detected": True,
            "severity": "critical",
            "evidence": f"top1_stake={features['top1_stake_pct']}%"
        })

    # ── Validator skip risk ───────────────────────────
    if features.get("avg_skip_rate", 0) > 0.2:
        findings.append({
            "type": "VALIDATOR_SKIP_RISK",
            "detected": True,
            "severity": "high",
            "evidence": f"skip_rate={features['avg_skip_rate']}"
        })

    # ── Fee manipulation pressure ─────────────────────
    if features.get("fee_spike", 0) > 10000:
        findings.append({
            "type": "FEE_SPIKE_ANOMALY",
            "detected": True,
            "severity": "medium",
            "evidence": f"max_fee={features['fee_spike']}"
        })

    return findings

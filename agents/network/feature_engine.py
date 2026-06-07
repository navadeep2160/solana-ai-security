"""
Feature Engine for Solana Network Security
Extracts real measurable signals from RPC data.
NO LLM, NO RAG here — only ground truth metrics.
"""

def extract_features(metrics: dict) -> dict:
    features = {}

    # ── Basic network load ─────────────────────────────
    perf = metrics.get("performance", {})
    features["avg_tps"] = perf.get("avg_tps", 0)

    # ── Spam / congestion signals ──────────────────────
    features["tx_density"] = metrics.get("tx_density", 0)
    features["max_tx_in_slot"] = metrics.get("block_production", {}).get("max_tx", 0)

    # fallback if spam detector already computed
    features["spam_score"] = metrics.get("spam_score", 0)

    # ── Validator health ───────────────────────────────
    validators = metrics.get("validators", {})
    features["validator_count"] = validators.get("active", 0)
    features["delinquent_count"] = validators.get("delinquent", 0)

    stake = metrics.get("stake", {})
    features["top1_stake_pct"] = stake.get("top1_pct", 0)
    features["top5_stake_pct"] = stake.get("top5_pct", 0)
    features["nakamoto"] = stake.get("nakamoto_coefficient", 0)

    # ── Block production signals ───────────────────────
    bp = metrics.get("block_production", {})
    features["avg_skip_rate"] = bp.get("avg_skip_rate", 0)
    features["critical_skip"] = bp.get("critical_skip_count", 0)

    # ── Priority fee pressure ──────────────────────────
    pf = metrics.get("priority_fees", {})
    features["avg_priority_fee"] = pf.get("avg", 0)
    features["fee_spike"] = pf.get("max", 0)

    return features

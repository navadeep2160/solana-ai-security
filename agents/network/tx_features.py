def extract_tx_features(tx, sig):
    meta = tx.get("meta", {}) or {}

    pre = meta.get("preBalances", [])
    post = meta.get("postBalances", [])

    changes = []
    for i, (a, b) in enumerate(zip(pre, post)):
        if a != b:
            changes.append({
                "index": i,
                "delta": b - a
            })

    return {
        "signature": sig,
        "fee": meta.get("fee", 0),
        "error": meta.get("err"),
        "logs": meta.get("logMessages", [])[:5],
        "balance_changes": changes[:10]
    }

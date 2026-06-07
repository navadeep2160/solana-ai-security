def enrich_features(tx_list):
    slots = {}

    for tx in tx_list:
        slot = tx.get("slot", 0)
        slots[slot] = slots.get(slot, 0) + 1

    max_tx = max(slots.values()) if slots else 0

    return {
        "tx_per_slot_distribution": slots,
        "max_tx_in_slot": max_tx,
        "is_spam_cluster": max_tx > 20
    }

def build_features(metrics):
    return {
        "rpc_url": metrics.get("rpc_url"),
        "slot": metrics.get("current_slot"),
        "performance": metrics.get("performance", {}),
        "validators": metrics.get("validators", {}),
        "stake": metrics.get("stake", {}),
        "target_account": metrics.get("target_account", {})
    }

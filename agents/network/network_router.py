"""
Network Router
ONLY responsible for collecting Solana network metrics
"""

import requests


RPC_URL = "https://api.testnet.solana.com"


def rpc(method, params=None):
    try:
        r = requests.post(RPC_URL, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or []
        }, timeout=10)

        data = r.json()
        return data.get("result")
    except Exception as e:
        print(f"[RPC ERROR] {e}")
        return None


def collect_metrics(rpc_url=None, address=None):
    """
    Unified metric collector for pipeline
    """

    url = rpc_url or RPC_URL

    metrics = {"rpc_url": url}

    # ── Slot info ─────────────────────────
    metrics["slot"] = rpc("getSlot")

    # ── Performance ───────────────────────
    perf = rpc("getRecentPerformanceSamples", [5])
    if perf:
        tps = [
            p.get("numTransactions", 0) /
            max(p.get("samplePeriodSecs", 1), 1)
            for p in perf
        ]
        metrics["performance"] = {
            "avg_tps": sum(tps) / len(tps),
            "max_tps": max(tps),
        }

    # ── Validators ────────────────────────
    vote = rpc("getVoteAccounts")
    if vote:
        current = vote.get("current", [])
        delinquent = vote.get("delinquent", [])

        metrics["validators"] = {
            "active": len(current),
            "delinquent": len(delinquent)
        }

        if current:
            stakes = [v.get("activatedStake", 0) for v in current]
            total = sum(stakes)

            metrics["stake"] = {
                "top1_pct": (max(stakes) / total * 100) if total else 0,
                "top5_pct": sum(sorted(stakes, reverse=True)[:5]) / total * 100 if total else 0
            }

    # ── Block production ──────────────────
    bp = rpc("getRecentBlockProduction")
    if bp:
        try:
            by_identity = bp["value"]["byIdentity"]
            skip = []
            for k, v in by_identity.items():
                assigned, produced = v[0], v[1]
                if assigned > 0:
                    skip.append((assigned - produced) / assigned)

            metrics["block_production"] = {
                "avg_skip_rate": sum(skip) / len(skip) if skip else 0
            }
        except:
            metrics["block_production"] = {}

    # ── Target account ────────────────────
    if address:
        acc = rpc("getAccountInfo", [address, {"encoding": "base64"}])
        if acc and acc.get("value"):
            val = acc["value"]
            metrics["target_account"] = {
                "sol": val.get("lamports", 0) / 1e9
            }

    return metrics

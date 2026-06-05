"""
Network Vulnerability Agent
Detects Solana network-level vulnerabilities using:
- Live devnet/mainnet RPC queries
- RAG from 15 network vulnerability sources
- AI analysis via Groq
"""
import os, json, time, warnings
os.environ["ANONYMIZED_TELEMETRY"] = "False"
warnings.filterwarnings("ignore")

import requests
from utils.logger import write_log

RPC_DEVNET  = "https://api.devnet.solana.com"
RPC_TESTNET = "https://api.testnet.solana.com"
RPC_MAINNET = "https://api.mainnet-beta.solana.com"

# ── RPC helpers ──────────────────────────────────────────────

def rpc(url, method, params=None):
    try:
        resp = requests.post(url, json={
            "jsonrpc": "2.0", "id": 1,
            "method": method,
            "params": params or []
        }, timeout=15)
        return resp.json().get("result")
    except Exception as e:
        return {"error": str(e)}

# ── Collect live network metrics ─────────────────────────────

def collect_metrics(rpc_url: str, target_address: str = None) -> dict:
    print(f"[NETWORK] Collecting metrics from {rpc_url}...")
    metrics = {}

    # Cluster health
    health = requests.get(rpc_url.replace("https://", "https://") + "/health",
                          timeout=10)
    metrics["cluster_health"] = health.text.strip() if health.ok else "unknown"

    # Slot and performance
    slot = rpc(rpc_url, "getSlot")
    metrics["current_slot"] = slot

    perf = rpc(rpc_url, "getRecentPerformanceSamples", [5])
    if perf and isinstance(perf, list):
        avg_tps = sum(p.get("numTransactions",0)/max(p.get("samplePeriodSecs",1),1)
                      for p in perf) / len(perf)
        avg_slots = sum(p.get("numSlots",0) for p in perf) / len(perf)
        metrics["avg_tps"]        = round(avg_tps, 2)
        metrics["avg_slots_per_sample"] = round(avg_slots, 2)
        metrics["perf_samples"]   = perf[:3]

    # Validator / vote accounts
    vote_accounts = rpc(rpc_url, "getVoteAccounts")
    if vote_accounts:
        current  = vote_accounts.get("current", [])
        delin    = vote_accounts.get("delinquent", [])
        metrics["active_validators"]     = len(current)
        metrics["delinquent_validators"] = len(delin)
        # Stake concentration
        if current:
            stakes = [v.get("activatedStake", 0) for v in current]
            total_stake = sum(stakes)
            stakes_sorted = sorted(stakes, reverse=True)
            top1_pct  = stakes_sorted[0] / total_stake * 100 if total_stake else 0
            top5_pct  = sum(stakes_sorted[:5]) / total_stake * 100 if total_stake else 0
            top20_pct = sum(stakes_sorted[:20]) / total_stake * 100 if total_stake else 0
            metrics["stake_concentration"] = {
                "total_stake_sol": total_stake / 1e9,
                "top1_validator_pct":  round(top1_pct, 2),
                "top5_validators_pct": round(top5_pct, 2),
                "top20_validators_pct": round(top20_pct, 2),
                "nakamoto_coefficient": _nakamoto(stakes, total_stake),
            }
        # Delinquent details
        if delin:
            metrics["delinquent_details"] = [
                {"pubkey": v["votePubkey"][:16]+"...",
                 "stake": v.get("activatedStake",0)/1e9}
                for v in delin[:5]
            ]

    # Epoch info
    epoch = rpc(rpc_url, "getEpochInfo")
    if epoch:
        metrics["epoch_info"] = {
            "epoch":           epoch.get("epoch"),
            "slot_index":      epoch.get("slotIndex"),
            "slots_in_epoch":  epoch.get("slotsInEpoch"),
            "transaction_count": epoch.get("transactionCount"),
        }

    # Fee / priority
    fees = rpc(rpc_url, "getRecentPrioritizationFees", [[]])
    if fees and isinstance(fees, list):
        fee_vals = [f.get("prioritizationFee", 0) for f in fees[:20]]
        metrics["priority_fees"] = {
            "min": min(fee_vals),
            "max": max(fee_vals),
            "avg": round(sum(fee_vals)/len(fee_vals), 2) if fee_vals else 0,
        }

    # Target account info
    if target_address:
        acc = rpc(rpc_url, "getAccountInfo",
                  [target_address, {"encoding": "base64"}])
        if acc:
            val = acc.get("value", {}) or {}
            metrics["target_account"] = {
                "address": target_address,
                "lamports": val.get("lamports", 0),
                "sol": val.get("lamports", 0) / 1e9,
                "owner": val.get("owner", ""),
                "executable": val.get("executable", False),
                "data_len": len(val.get("data", [""])[0]) if val.get("data") else 0,
            }

    # Block production / skip rate (last 20 slots)
    leaders = rpc(rpc_url, "getLeaderSchedule")
    if leaders and isinstance(leaders, dict):
        metrics["unique_leaders"] = len(leaders)

    return metrics

def _nakamoto(stakes, total):
    """Minimum validators controlling >33% stake."""
    sorted_s = sorted(stakes, reverse=True)
    acc, count = 0, 0
    for s in sorted_s:
        acc += s
        count += 1
        if acc / total > 0.33:
            return count
    return count

# ── AI analysis ──────────────────────────────────────────────

def analyze_with_ai(metrics: dict, network: str) -> dict:
    from models.ollama_client import load_model
    from kb.kb_router import query_network

    print("[NETWORK] Querying RAG for network vulnerability context...")

    # Query RAG for each major vulnerability category
    rag_context = ""
    queries = [
        "stake concentration nakamoto coefficient centralization",
        "validator delinquent eclipse attack isolation",
        "transaction spam DoS TPU congestion",
        "MEV sandwich frontrunning Jito",
        "gossip protocol abuse flood",
    ]
    seen = set()
    for q in queries:
        results = query_network(q, top_k=2)
        for r in results:
            chunk = r["content"][:300]
            if chunk not in seen:
                rag_context += f"\n[{r['source'] if 'source' in r else r.get('title','')}]\n{chunk}\n"
                seen.add(chunk)

    llm = load_model("scan_model")

    prompt = f"""You are a Solana network security analyst.

Analyze these live {network} network metrics for security vulnerabilities.
Use the KB context below to identify real attack patterns.

LIVE NETWORK METRICS:
{json.dumps(metrics, indent=2)[:3000]}

SECURITY KNOWLEDGE BASE:
{rag_context[:2000]}

Identify ALL security issues. Return ONLY valid JSON:
{{
  "vulnerabilities": [
    {{
      "type": "vulnerability_name",
      "severity": "critical|high|medium|low",
      "detected": true|false,
      "evidence": "specific metric values that indicate this",
      "description": "what this means",
      "mitigation": "how to fix"
    }}
  ],
  "risk_score": <0-10>,
  "network_health": "healthy|degraded|critical",
  "summary": "one paragraph summary"
}}

Check for: stake_concentration, delinquent_validators, 
low_nakamoto_coefficient, high_priority_fees, tps_anomaly,
eclipse_risk, mev_activity, spam_attack, gossip_issues."""

    try:
        result = llm.invoke(prompt)
        raw = result.content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        print(f"[NETWORK] AI parse failed: {e}")
        return {
            "vulnerabilities": [],
            "risk_score": 0,
            "network_health": "unknown",
            "summary": f"AI analysis failed: {e}"
        }

# ── Mitigation suggestions ────────────────────────────────────

def suggest_mitigations(vulnerabilities: list) -> list:
    from kb.kb_router import query_network
    suggestions = []
    for v in vulnerabilities:
        if not v.get("detected"):
            continue
        kb = query_network(v["type"] + " mitigation fix", top_k=2)
        kb_text = "\n".join(r["content"][:200] for r in kb)
        suggestions.append({
            "vulnerability": v["type"],
            "severity": v["severity"],
            "mitigation": v.get("mitigation", ""),
            "kb_reference": kb_text[:300]
        })
    return suggestions

# ── Main entry ────────────────────────────────────────────────

def run_network_agent(
    network: str = "devnet",
    target_address: str = None
) -> dict:
    rpc_url = RPC_TESTNET if network == "testnet" else (RPC_DEVNET if network == "devnet" else RPC_MAINNET)
    print(f"\n[NETWORK] Starting network vulnerability scan on {network}...")

    # Step 1: Collect live metrics
    metrics = collect_metrics(rpc_url, target_address)
    print(f"[NETWORK] Metrics collected: {list(metrics.keys())}")

    # Step 2: AI analysis with RAG
    analysis = analyze_with_ai(metrics, network)

    # Step 3: Mitigations from KB
    mitigations = suggest_mitigations(analysis.get("vulnerabilities", []))

    output = {
        "network":       network,
        "rpc_url":       rpc_url,
        "target_address": target_address,
        "metrics":       metrics,
        "analysis":      analysis,
        "mitigations":   mitigations,
        "total_vulns":   len(analysis.get("vulnerabilities", [])),
        "detected":      sum(1 for v in analysis.get("vulnerabilities",[])
                             if v.get("detected")),
    }

    # Print summary
    print(f"\n{'='*55}")
    print(f"NETWORK VULNERABILITY SCAN — {network.upper()}")
    print(f"{'='*55}")
    print(f"Network health : {analysis.get('network_health','?')}")
    print(f"Risk score     : {analysis.get('risk_score','?')}/10")
    print(f"Vulnerabilities: {output['detected']} detected\n")

    for v in analysis.get("vulnerabilities", []):
        if v.get("detected"):
            icon = "🔴" if v["severity"]=="critical" else \
                   "🟠" if v["severity"]=="high" else \
                   "🟡" if v["severity"]=="medium" else "🟢"
            print(f"  {icon} [{v['severity'].upper()}] {v['type']}")
            print(f"     Evidence: {v.get('evidence','')[:80]}")

    print(f"\nSummary: {analysis.get('summary','')[:300]}")
    print(f"{'='*55}")

    log_path = write_log("network_agent", output)
    print(f"[NETWORK] Log → {log_path}")
    return output


if __name__ == "__main__":
    import sys
    network = sys.argv[1] if len(sys.argv) > 1 else "devnet"
    address = sys.argv[2] if len(sys.argv) > 2 else None
    run_network_agent(network, address)

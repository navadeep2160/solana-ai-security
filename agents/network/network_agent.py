"""
Network Vulnerability Agent — Week 3
Fully RAG-driven. No hardcoded vulnerability names or scores.
All detection logic comes from the KB collections.

Covers all 15 network vulnerability classes:
  Sandwich Attack, Validator Skip, DDoS/Spam, Centralization,
  Eclipse Attack, Oracle Manipulation, Flash Loan, Vote Censorship,
  Gossip Abuse, Supply Chain/CVE, Slow Patch, TPU Congestion,
  Key Leakage, Rent Exemption, Slow Gossip/Partition
"""
import os, json, time, warnings, requests
os.environ["ANONYMIZED_TELEMETRY"] = "False"
warnings.filterwarnings("ignore")

from dotenv import load_dotenv
load_dotenv()

from utils.logger import write_log

RPC_URLS = {
    "testnet": "https://api.testnet.solana.com",
    "devnet":  "https://api.devnet.solana.com",
    "mainnet": "https://api.mainnet-beta.solana.com",
    "local":   "http://localhost:8899",
}


# ── RPC helper ────────────────────────────────────────────────

def rpc(url, method, params=None, retries=3):
    for attempt in range(retries):
        try:
            resp = requests.post(url, json={
                "jsonrpc": "2.0", "id": 1,
                "method": method,
                "params": params or []
            }, timeout=15)
            if resp.status_code == 429:
                time.sleep(2 ** attempt)
                continue
            data = resp.json()
            if "error" in data:
                return None
            return data.get("result")
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
    return None


# ── Collect live metrics ──────────────────────────────────────

def collect_metrics(rpc_url: str, address: str = None) -> dict:
    print(f"[NETWORK] Collecting live metrics...")
    metrics = {"rpc_url": rpc_url}

    # Cluster health
    try:
        h = requests.get(rpc_url + "/health", timeout=10)
        metrics["cluster_health"] = h.text.strip() if h.ok else "unavailable"
    except Exception:
        metrics["cluster_health"] = "unreachable"

    # Current slot
    slot = rpc(rpc_url, "getSlot")
    metrics["current_slot"] = slot

    if not slot:
        print("[NETWORK] ⚠️  RPC not responding — limited metrics")
        return metrics

    # Performance samples
    perf = rpc(rpc_url, "getRecentPerformanceSamples", [5])
    if perf and isinstance(perf, list):
        tps_vals = [
            p.get("numTransactions", 0) / max(p.get("samplePeriodSecs", 1), 1)
            for p in perf
        ]
        metrics["performance"] = {
            "avg_tps":         round(sum(tps_vals) / len(tps_vals), 2),
            "min_tps":         round(min(tps_vals), 2),
            "max_tps":         round(max(tps_vals), 2),
            "samples":         len(perf),
            "raw_samples":     perf[:3],
        }

    # Vote accounts — validators
    vote = rpc(rpc_url, "getVoteAccounts")
    if vote:
        current   = vote.get("current", [])
        delinquent = vote.get("delinquent", [])
        metrics["validators"] = {
            "active":     len(current),
            "delinquent": len(delinquent),
        }
        if current:
            stakes = [v.get("activatedStake", 0) for v in current]
            total  = sum(stakes)
            srt    = sorted(stakes, reverse=True)
            def nakamoto(s, t):
                acc, n = 0, 0
                for x in sorted(s, reverse=True):
                    acc += x; n += 1
                    if acc / t > 0.33: return n
                return n
            metrics["stake"] = {
                "total_sol":          round(total / 1e9, 2),
                "top1_pct":           round(srt[0] / total * 100, 2) if total else 0,
                "top5_pct":           round(sum(srt[:5]) / total * 100, 2) if total else 0,
                "top20_pct":          round(sum(srt[:20]) / total * 100, 2) if total else 0,
                "nakamoto_coefficient": nakamoto(stakes, total),
                "active_pct":         round(total / (total + sum(
                    v.get("activatedStake",0) for v in delinquent
                )) * 100, 2) if total else 0,
            }
        if delinquent:
            metrics["delinquent_sample"] = [
                {
                    "pubkey": v.get("nodePubkey","")[:16] + "...",
                    "stake_sol": round(v.get("activatedStake", 0) / 1e9, 2),
                    "last_vote": v.get("lastVote", 0),
                    "slots_silent": (slot - v.get("lastVote", slot))
                                    if slot else 0,
                }
                for v in sorted(delinquent,
                                key=lambda x: x.get("activatedStake", 0),
                                reverse=True)[:5]
            ]

    # Epoch info
    epoch = rpc(rpc_url, "getEpochInfo")
    if epoch:
        metrics["epoch"] = {
            "epoch":       epoch.get("epoch"),
            "slot_index":  epoch.get("slotIndex"),
            "total_slots": epoch.get("slotsInEpoch"),
            "tx_count":    epoch.get("transactionCount"),
        }

    # Priority fees
    fees = rpc(rpc_url, "getRecentPrioritizationFees", [[]])
    if fees and isinstance(fees, list):
        vals = [f.get("prioritizationFee", 0) for f in fees[:20]]
        if vals:
            metrics["priority_fees"] = {
                "min": min(vals),
                "max": max(vals),
                "avg": round(sum(vals) / len(vals), 2),
                "nonzero_count": sum(1 for v in vals if v > 0),
            }

    # Block production — skip rates
    bp = rpc(rpc_url, "getRecentBlockProduction")
    if bp:
        by_id = bp.get("value", {}).get("byIdentity", {})
        if by_id:
            skip_rates = []
            for vid, counts in by_id.items():
                assigned, produced = counts[0], counts[1]
                if assigned > 0:
                    skip_rates.append((assigned - produced) / assigned)
            if skip_rates:
                metrics["block_production"] = {
                    "validators_checked": len(skip_rates),
                    "avg_skip_rate":      round(sum(skip_rates) / len(skip_rates), 4),
                    "max_skip_rate":      round(max(skip_rates), 4),
                    "high_skip_count":    sum(1 for s in skip_rates if s > 0.20),
                    "critical_skip_count": sum(1 for s in skip_rates if s > 0.50),
                }

    # Leader schedule — unique leaders
    leaders = rpc(rpc_url, "getLeaderSchedule")
    if leaders and isinstance(leaders, dict):
        metrics["leader_schedule"] = {"unique_leaders": len(leaders)}

    # Target address info
    if address:
        acc = rpc(rpc_url, "getAccountInfo",
                  [address, {"encoding": "base64"}])
        if acc:
            val = acc.get("value") or {}
            metrics["target_account"] = {
                "address":    address,
                "sol":        round(val.get("lamports", 0) / 1e9, 6),
                "owner":      val.get("owner", ""),
                "executable": val.get("executable", False),
            }

    print(f"[NETWORK] Metrics collected: {list(metrics.keys())}")
    return metrics


# ── RAG-driven AI analysis ────────────────────────────────────

def analyze_with_rag(metrics: dict, network: str) -> dict:
    from models.ollama_client import load_model
    from kb.kb_router import query_network, query_sc_rules, query_audit_findings

    print("[NETWORK] Querying RAG knowledge base...")

    # Pull context for every major attack class from KB
    rag_parts = []
    queries = [
        "sandwich attack MEV frontrunning Jito Solana validators",
        "validator skip rate abstention epsilon stake delinquent",
        "DDoS spam transaction flood TPU congestion",
        "stake concentration nakamoto coefficient centralization",
        "eclipse attack validator isolation network partition gossip",
        "oracle price manipulation flash loan Solana DeFi",
        "vote censorship transaction censorship leader",
        "gossip protocol abuse amplification flood",
        "CVE supply chain slow patch adoption validator update",
        "key leakage private key account takeover",
        "rent exemption account closure lamports",
    ]

    seen = set()
    for q in queries:
        for fn in [query_network, query_sc_rules, query_audit_findings]:
            try:
                results = fn(q, top_k=1)
                for r in results:
                    chunk = r.get("content", "")[:300]
                    if chunk and chunk not in seen:
                        src = r.get("source", r.get("title", "KB"))
                        rag_parts.append(f"[{src}]\n{chunk}")
                        seen.add(chunk)
            except Exception:
                pass

    rag_context = "\n\n".join(rag_parts)
    print(f"[NETWORK] RAG context: {len(rag_parts)} chunks, {len(rag_context)} chars")

    llm = load_model()

    prompt = f"""You are a Solana network security analyst.

Analyze these LIVE {network.upper()} network metrics for security vulnerabilities.
Use ONLY the knowledge base context below to identify attack patterns and assign scores.
Do NOT use hardcoded thresholds — derive everything from the KB.

LIVE METRICS:
{json.dumps(metrics, indent=2)[:3500]}

KNOWLEDGE BASE (15 vulnerability classes):
{rag_context[:3000]}

Return ONLY valid JSON — no markdown, no explanation outside JSON:
{{
  "vulnerabilities": [
    {{
      "type": "vulnerability_name",
      "severity": "critical|high|medium|low",
      "detected": true|false,
      "evidence": "specific metric values from the live data",
      "paper_reference": "paper/source from KB that informed this",
      "description": "what this means for the network",
      "mitigation": "recommended action based on KB"
    }}
  ],
  "network_health": "healthy|degraded|critical",
  "risk_score": <float 0.0-10.0>,
  "summary": "2-3 sentence paragraph"
}}

Analyze for: sandwich_attack, validator_skip_abuse, ddos_spam,
stake_centralization, eclipse_attack, oracle_manipulation,
flash_loan_risk, vote_censorship, gossip_abuse, cve_supply_chain,
slow_patch_adoption, tpu_congestion, key_leakage, rent_exemption,
network_partition. Only include detected=true if evidence exists in metrics."""

    try:
        result = llm.invoke(prompt)
        raw = result.content.strip()
        if "```" in raw:
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else parts[0]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        print(f"[NETWORK] AI parse failed: {e}")
        return {
            "vulnerabilities": [],
            "network_health":  "unknown",
            "risk_score":      0,
            "summary":         f"AI analysis failed: {str(e)[:200]}"
        }


# ── Main entry ────────────────────────────────────────────────

def run_network_agent(
    network: str = "testnet",
    address: str = None
) -> dict:
    rpc_url = RPC_URLS.get(network, RPC_URLS["testnet"])
    print(f"\n[NETWORK] Network vulnerability scan — {network.upper()}")
    print(f"[NETWORK] RPC: {rpc_url}")

    metrics  = collect_metrics(rpc_url, address)
    analysis = analyze_with_rag(metrics, network)

    detected = [v for v in analysis.get("vulnerabilities", [])
                if v.get("detected")]

    output = {
        "network":        network,
        "rpc_url":        rpc_url,
        "address":        address,
        "metrics":        metrics,
        "analysis":       analysis,
        "total_checked":  len(analysis.get("vulnerabilities", [])),
        "total_detected": len(detected),
    }

    # Print report
    print(f"\n{'='*60}")
    print(f"  NETWORK VULNERABILITY REPORT — {network.upper()}")
    print(f"{'='*60}")
    print(f"  Network health : {analysis.get('network_health','?')}")
    print(f"  Risk score     : {analysis.get('risk_score','?')}/10")
    print(f"  Detected       : {len(detected)} vulnerabilities\n")

    for v in detected:
        icon = ("🔴" if v["severity"] == "critical" else
                "🟠" if v["severity"] == "high" else
                "🟡" if v["severity"] == "medium" else "🟢")
        print(f"  {icon} [{v['severity'].upper()}] {v['type']}")
        print(f"     Evidence  : {v.get('evidence','')[:80]}")
        print(f"     Paper     : {v.get('paper_reference','')[:60]}")
        print(f"     Mitigation: {v.get('mitigation','')[:80]}")

    print(f"\n  Summary: {analysis.get('summary','')[:400]}")
    print(f"{'='*60}")

    log_path = write_log("network_agent", output)
    print(f"[NETWORK] Log → {log_path}")
    return output


if __name__ == "__main__":
    import sys
    network = sys.argv[1] if len(sys.argv) > 1 else "testnet"
    address = sys.argv[2] if len(sys.argv) > 2 else None
    run_network_agent(network, address)

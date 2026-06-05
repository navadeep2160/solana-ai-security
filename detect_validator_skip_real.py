"""
Validator Skip Detector — Real Testnet Version
===============================================
Based on: Kniep et al. "Halting the Solana Blockchain with Epsilon Stake"
          ICDCN 2024, ETH Zurich

RUN THIS ON YOUR OWN LAPTOP — not in a sandbox.

HOW TO RUN:
-----------
# Step 1: Install dependency
    pip install requests

# Step 2: Run against Solana testnet (real)
    python detect_validator_skip_real.py

# Step 3: Run against Navadeep's local validator
    python detect_validator_skip_real.py --rpc http://localhost:8899

# Step 4: Save output for the agent
    python detect_validator_skip_real.py --output finding.json

WHAT THIS DOES:
---------------
Makes 3 real RPC calls to the Solana testnet:
  1. getRecentBlockProduction  → skip rate per validator
  2. getVoteAccounts + getSlot → voting abstention per validator  
  3. getVoteAccounts           → fork stake concentration

All thresholds come directly from Kniep et al. ICDCN 2024.
"""

import requests
import json
import time
import argparse
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────
# THRESHOLDS — from Kniep et al. ICDCN 2024
# ─────────────────────────────────────────────────────────
SKIP_RATE_THRESHOLD   = 0.20   # Section 2.3  — > 20% skip rate → anomalous
CRITICAL_SKIP_RATE    = 0.50   # Section 3.2  — > 50% → epsilon-stake territory
ABSTENTION_SLOTS      = 150    # Section 2.3  — > 150 slots no vote → abstention
SWITCH_FORK_THRESHOLD = 0.38   # Section 3.2  — < 38% stake → fork not votable
DUPLICATE_THRESHOLD   = 0.52   # Section 3.2  — < 52% stake → duplicate unresolvable

# ─────────────────────────────────────────────────────────
# FREE PUBLIC RPC OPTIONS
# Use whichever works for you.
# Testnet is best for your project — it has real validators.
# ─────────────────────────────────────────────────────────
RPC_OPTIONS = {
    "testnet"  : "https://api.testnet.solana.com",
    "devnet"   : "https://api.devnet.solana.com",
    "mainnet"  : "https://api.mainnet-beta.solana.com",
    "local"    : "http://localhost:8899",        # Navadeep's local validator
}


# ─────────────────────────────────────────────────────────
# RPC HELPER — with retry logic for rate limits
# ─────────────────────────────────────────────────────────
def rpc_call(url, method, params=None, retries=3):
    """
    Make a Solana JSON-RPC call with automatic retry on rate limit.
    Returns the result dict, or None on failure.
    """
    payload = {
        "jsonrpc": "2.0",
        "id"     : 1,
        "method" : method,
        "params" : params or []
    }
    headers = {"Content-Type": "application/json"}

    for attempt in range(retries):
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=20)

            # Rate limited — wait and retry
            if resp.status_code == 429:
                wait = 2 ** attempt
                print(f"    Rate limited. Waiting {wait}s...")
                time.sleep(wait)
                continue

            # Auth error — tell user what to do
            if resp.status_code == 403:
                print(f"    [403] RPC blocked this IP.")
                print(f"    → If on laptop: try again, should work.")
                print(f"    → If on server: get a free Helius key at helius.dev")
                return None

            resp.raise_for_status()
            data = resp.json()

            if "error" in data:
                # Method not available on this endpoint
                if data["error"].get("code") == -32601:
                    print(f"    [{method}] not supported on this RPC endpoint")
                else:
                    print(f"    [RPC ERROR] {method}: {data['error'].get('message','unknown')}")
                return None

            return data.get("result")

        except requests.exceptions.ConnectionError:
            print(f"    [CONNECTION ERROR] Cannot reach {url}")
            print(f"    Is the RPC running? Check your internet connection.")
            return None
        except requests.exceptions.Timeout:
            print(f"    [TIMEOUT] {method} timed out (attempt {attempt+1}/{retries})")
            if attempt < retries - 1:
                time.sleep(2)
        except Exception as e:
            print(f"    [ERROR] {method}: {e}")
            return None

    return None


# ─────────────────────────────────────────────────────────
# SIGNAL 1 — Leader slot skip rate
# RPC: getRecentBlockProduction
# Source: Kniep et al. Section 2.3
# ─────────────────────────────────────────────────────────
def check_skip_rate(rpc_url):
    print("\n[Signal 1] Checking leader slot skip rates (getRecentBlockProduction)...")

    result = rpc_call(rpc_url, "getRecentBlockProduction")
    if not result:
        return [{"signal": "skip_rate", "status": "ERROR",
                 "message": "Could not fetch block production data"}]

    by_identity = result.get("value", {}).get("byIdentity", {})
    if not by_identity:
        return [{"signal": "skip_rate", "status": "NO_DATA",
                 "message": "No validator data in response — testnet may have few validators"}]

    slot_range = result.get("context", {}).get("slot", "unknown")
    print(f"    Checking {len(by_identity)} validators at slot {slot_range}...")

    findings = []
    clean_count = 0

    for validator_id, counts in by_identity.items():
        assigned = counts[0]
        produced = counts[1]

        if assigned == 0:
            continue

        skip_rate = (assigned - produced) / assigned

        if skip_rate > SKIP_RATE_THRESHOLD:
            severity = "CRITICAL" if skip_rate > CRITICAL_SKIP_RATE else "HIGH"
            findings.append({
                "signal"          : "skip_rate",
                "validator"       : validator_id,
                "slots_assigned"  : assigned,
                "slots_produced"  : produced,
                "slots_skipped"   : assigned - produced,
                "skip_rate"       : round(skip_rate, 4),
                "skip_rate_pct"   : f"{round(skip_rate * 100, 1)}%",
                "severity"        : severity,
                "paper_reference" : "Kniep et al. ICDCN 2024 Section 2.3",
                "interpretation"  : (
                    f"Validator skipped {assigned - produced} of {assigned} assigned leader slots "
                    f"({round(skip_rate*100,1)}% skip rate). "
                    f"Threshold from paper: >20% = anomalous, >50% = epsilon-stake attack territory."
                )
            })
            icon = "!!!" if severity == "CRITICAL" else "! "
            print(f"    [{icon}] {validator_id[:20]}... "
                  f"skip={round(skip_rate*100,1)}% "
                  f"({produced}/{assigned} produced) → {severity}")
        else:
            clean_count += 1

    if not findings:
        print(f"    [OK] All {len(by_identity)} validators within normal skip rate (<20%)")
        findings.append({
            "signal"  : "skip_rate",
            "status"  : "CLEAN",
            "total_validators_checked": len(by_identity),
            "clean_count": clean_count,
            "message" : f"All {len(by_identity)} validators below skip rate threshold"
        })
    else:
        print(f"    Summary: {len(findings)} flagged, {clean_count} clean")

    return findings


# ─────────────────────────────────────────────────────────
# SIGNAL 2 — Voting abstention
# RPC: getVoteAccounts + getSlot
# Source: Kniep et al. Section 2.3
# The paper shows abstention is HOW epsilon-stake attacks stall consensus
# ─────────────────────────────────────────────────────────
def check_voting_abstention(rpc_url):
    print("\n[Signal 2] Checking voting abstention (getVoteAccounts + getSlot)...")

    current_slot = rpc_call(rpc_url, "getSlot")
    if current_slot is None:
        return [{"signal": "abstention", "status": "ERROR",
                 "message": "Could not fetch current slot"}]

    vote_result = rpc_call(rpc_url, "getVoteAccounts")
    if not vote_result:
        return [{"signal": "abstention", "status": "ERROR",
                 "message": "Could not fetch vote accounts"}]

    current_validators   = vote_result.get("current", [])
    delinquent_validators = vote_result.get("delinquent", [])
    all_validators = current_validators + delinquent_validators

    print(f"    Current slot: {current_slot}")
    print(f"    Active validators:    {len(current_validators)}")
    print(f"    Delinquent validators:{len(delinquent_validators)}")

    if not all_validators:
        return [{"signal": "abstention", "status": "NO_DATA",
                 "message": "No vote accounts found — testnet may have no active validators"}]

    findings = []
    clean_count = 0

    for v in all_validators:
        last_vote        = v.get("lastVote", 0)
        node_pubkey      = v.get("nodePubkey", "unknown")
        vote_pubkey      = v.get("votePubkey", "unknown")
        activated_stake  = v.get("activatedStake", 0)
        commission       = v.get("commission", 0)
        slots_since_vote = current_slot - last_vote
        is_delinquent    = v in delinquent_validators

        if slots_since_vote > ABSTENTION_SLOTS:
            severity = "CRITICAL" if is_delinquent else "HIGH"
            findings.append({
                "signal"              : "voting_abstention",
                "validator"           : node_pubkey,
                "vote_account"        : vote_pubkey,
                "last_vote_slot"      : last_vote,
                "current_slot"        : current_slot,
                "slots_since_last_vote": slots_since_vote,
                "activated_stake_sol" : round(activated_stake / 1e9, 2),
                "commission_pct"      : commission,
                "is_delinquent"       : is_delinquent,
                "severity"            : severity,
                "paper_reference"     : "Kniep et al. ICDCN 2024 Section 2.3",
                "interpretation"      : (
                    f"Validator has not voted for {slots_since_vote} slots "
                    f"(threshold: {ABSTENTION_SLOTS} slots). "
                    f"Per Kniep et al., validators abstain from voting when they "
                    f"cannot verify duplicate blocks — the core mechanism of epsilon-stake attacks."
                )
            })
            icon = "!!!" if severity == "CRITICAL" else "! "
            print(f"    [{icon}] {node_pubkey[:20]}... "
                  f"no vote for {slots_since_vote} slots | "
                  f"delinquent={is_delinquent} → {severity}")
        else:
            clean_count += 1

    if not findings:
        print(f"    [OK] All {len(all_validators)} validators voting normally")
        findings.append({
            "signal"  : "voting_abstention",
            "status"  : "CLEAN",
            "current_slot": current_slot,
            "total_validators_checked": len(all_validators),
            "clean_count": clean_count,
            "message" : "No validators showing abnormal voting abstention"
        })

    return findings


# ─────────────────────────────────────────────────────────
# SIGNAL 3 — Fork stake concentration
# RPC: getVoteAccounts
# Source: Kniep et al. Section 3.2 — the core attack finding
# Switch fork threshold = 38%
# Duplicate threshold   = 52%
# ─────────────────────────────────────────────────────────
def check_fork_stake(rpc_url):
    print("\n[Signal 3] Checking fork stake concentration (getVoteAccounts)...")

    vote_result = rpc_call(rpc_url, "getVoteAccounts")
    if not vote_result:
        return [{"signal": "fork_stake", "status": "ERROR",
                 "message": "Could not fetch vote accounts"}]

    current   = vote_result.get("current", [])
    delinquent = vote_result.get("delinquent", [])

    active_stake    = sum(v.get("activatedStake", 0) for v in current)
    delinquent_stake = sum(v.get("activatedStake", 0) for v in delinquent)
    total_stake     = active_stake + delinquent_stake

    if total_stake == 0:
        return [{"signal": "fork_stake", "status": "NO_DATA",
                 "message": "No stake data — testnet may have no staked validators"}]

    active_pct    = active_stake / total_stake
    delinquent_pct = delinquent_stake / total_stake

    print(f"    Total stake   : {round(total_stake/1e9, 2)} SOL")
    print(f"    Active stake  : {round(active_stake/1e9, 2)} SOL ({round(active_pct*100,1)}%)")
    print(f"    Delinquent    : {round(delinquent_stake/1e9, 2)} SOL ({round(delinquent_pct*100,1)}%)")
    print(f"    Switch fork threshold (paper): {SWITCH_FORK_THRESHOLD*100}%")
    print(f"    Duplicate threshold (paper)  : {DUPLICATE_THRESHOLD*100}%")

    # Core finding from Kniep et al. Section 3.2
    if active_pct < SWITCH_FORK_THRESHOLD:
        severity = "CRITICAL"
        interpretation = (
            f"Only {round(active_pct*100,1)}% of stake on active validators — "
            f"below the 38% switch fork threshold from Kniep et al. "
            f"CRITICAL: Network is in epsilon-stake attack territory. "
            f"No competing fork can reach the switch threshold, causing permanent stall. "
            f"This matches the September 2022 Solana mainnet outage scenario."
        )
        print(f"    [!!!] Active stake {round(active_pct*100,1)}% < 38% switch threshold → CRITICAL")

    elif active_pct < DUPLICATE_THRESHOLD:
        severity = "HIGH"
        interpretation = (
            f"Active stake at {round(active_pct*100,1)}% — "
            f"above switch fork threshold (38%) but below duplicate threshold (52%). "
            f"Duplicate blocks cannot be resolved by vote. Elevated risk of stall."
        )
        print(f"    [! ] Active stake {round(active_pct*100,1)}% < 52% duplicate threshold → HIGH")

    else:
        severity = "CLEAN"
        interpretation = (
            f"Stake concentration healthy: {round(active_pct*100,1)}% active. "
            f"Above both thresholds — switch fork (38%) and duplicate (52%)."
        )
        print(f"    [OK] Active stake {round(active_pct*100,1)}% — above both thresholds")

    finding = {
        "signal"              : "fork_stake_concentration",
        "active_validators"   : len(current),
        "delinquent_validators": len(delinquent),
        "active_stake_sol"    : round(active_stake / 1e9, 2),
        "delinquent_stake_sol": round(delinquent_stake / 1e9, 2),
        "total_stake_sol"     : round(total_stake / 1e9, 2),
        "active_stake_pct"    : round(active_pct, 4),
        "delinquent_stake_pct": round(delinquent_pct, 4),
        "switch_fork_threshold": SWITCH_FORK_THRESHOLD,
        "duplicate_threshold" : DUPLICATE_THRESHOLD,
        "severity"            : severity,
        "paper_reference"     : "Kniep et al. ICDCN 2024 Section 3.2",
        "interpretation"      : interpretation
    }

    return [finding]


# ─────────────────────────────────────────────────────────
# MAIN DETECTOR — the agent tool
# ─────────────────────────────────────────────────────────
def detect_validator_skip(rpc_url="https://api.testnet.solana.com"):
    """
    AGENT TOOL: detect_validator_skip

    Detects validator skip attacks on Solana testnet.
    Implements 3 signals from Kniep et al. ICDCN 2024.

    Args:
        rpc_url: Solana RPC endpoint URL

    Returns:
        dict — structured finding ready for LLM agent consumption
    """
    print(f"\n{'='*60}")
    print(f"  VALIDATOR SKIP DETECTOR")
    print(f"  Paper: Kniep et al. ICDCN 2024")
    print(f"  RPC  : {rpc_url}")
    print(f"  Time : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}")

    # Run all 3 signals
    skip_findings       = check_skip_rate(rpc_url)
    abstention_findings = check_voting_abstention(rpc_url)
    fork_findings       = check_fork_stake(rpc_url)

    all_findings = skip_findings + abstention_findings + fork_findings

    # Compute overall severity
    severities = [f.get("severity") for f in all_findings if f.get("severity") not in (None, "CLEAN")]
    if "CRITICAL" in severities:
        overall_severity = "CRITICAL"
    elif "HIGH" in severities:
        overall_severity = "HIGH"
    elif "MEDIUM" in severities:
        overall_severity = "MEDIUM"
    else:
        overall_severity = "CLEAN"

    flagged = [f for f in all_findings if f.get("severity") in ("CRITICAL", "HIGH")]

    # Mitigation recommendation — fed to LLM agent
    if overall_severity == "CRITICAL":
        mitigation = (
            "IMMEDIATE ACTION REQUIRED. "
            "Network shows epsilon-stake attack pattern (Kniep et al. ICDCN 2024). "
            "Actions: "
            "(1) Alert delinquent validator operators immediately. "
            "(2) Monitor fork divergence every 10 slots. "
            "(3) If fork stall confirmed, coordinate manual validator restart — "
            "consistent with Sept 30 2022 Solana outage recovery. "
            "(4) Review upcoming leader schedule for low-stake validators. "
            "(5) Check if duplicate blocks exist for stalled slots via getBlock."
        )
    elif overall_severity == "HIGH":
        mitigation = (
            "ELEVATED RISK. "
            "One or more validators showing abnormal skip or abstention. "
            "Actions: "
            "(1) Contact affected validator operators. "
            "(2) Monitor skip rate trend over next 5 epochs. "
            "(3) Check validator hardware and network connectivity. "
            "(4) Consider stake reallocation from persistently skipping validators."
        )
    else:
        mitigation = (
            "Network healthy. No action required. "
            "All validators within normal operating parameters per Kniep et al. thresholds."
        )

    output = {
        "detector"                  : "validator_skip",
        "paper"                     : "Kniep et al. ICDCN 2024 — Halting Solana with Epsilon Stake",
        "rpc_endpoint"              : rpc_url,
        "timestamp"                 : datetime.now(timezone.utc).isoformat(),
        "overall_severity"          : overall_severity,
        "flagged_count"             : len(flagged),
        "findings"                  : all_findings,
        "mitigation_recommendation" : mitigation,
        "thresholds_used"           : {
            "skip_rate_threshold"   : SKIP_RATE_THRESHOLD,
            "critical_skip_rate"    : CRITICAL_SKIP_RATE,
            "abstention_slot_limit" : ABSTENTION_SLOTS,
            "switch_fork_threshold" : SWITCH_FORK_THRESHOLD,
            "duplicate_threshold"   : DUPLICATE_THRESHOLD,
        }
    }

    return output


# ─────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Validator Skip Detector — Kniep et al. ICDCN 2024\n"
                    "Run on your laptop against Solana testnet.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--rpc",
        default="https://api.testnet.solana.com",
        help=(
            "Solana RPC endpoint. Options:\n"
            "  Testnet (default): https://api.testnet.solana.com\n"
            "  Devnet           : https://api.devnet.solana.com\n"
            "  Local validator  : http://localhost:8899\n"
            "  Helius devnet    : https://devnet.helius-rpc.com/?api-key=YOUR_KEY"
        )
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Save JSON output to file (e.g. --output finding.json)"
    )
    args = parser.parse_args()

    result = detect_validator_skip(rpc_url=args.rpc)

    # Print summary
    print(f"\n{'='*60}")
    print(f"  FINAL RESULT")
    print(f"{'='*60}")
    print(f"  Severity  : {result['overall_severity']}")
    print(f"  Flagged   : {result['flagged_count']} findings")
    print(f"  Mitigation: {result['mitigation_recommendation'][:80]}...")
    print(f"\n  Full JSON output:")
    print(f"{'='*60}")
    print(json.dumps(result, indent=2))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n  [Saved to {args.output}]")

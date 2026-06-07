from agents.network.network_v2 import run_pipeline
from agents.network.network_router import collect_metrics

def run(address, network="testnet"):
    print("\n[ENTRY] Unified Network Security Pipeline\n")

    # convert address → metrics (THIS IS THE FIX)
    rpc_url = "https://api.testnet.solana.com" if network == "testnet" else "https://api.devnet.solana.com"

    metrics = collect_metrics(rpc_url, address)

    return run_pipeline(metrics)

from agents.network.rpc_client import get_signatures, get_tx
from agents.network.tx_features import extract_tx_features
from agents.network.rag_engine import get_rag_context
from agents.network.analyzer import analyze

RPC = "https://api.devnet.solana.com"

def run(address):

    print("\n[PIPELINE] Starting scan...\n")

    sigs = get_signatures(RPC, address, 5)

    for s in sigs:

        sig = s.get("signature")
        print("\nTX:", sig)

        tx = get_tx(RPC, sig)
        if not tx:
            continue

        features = extract_tx_features(tx, sig)

        rag = get_rag_context([
            "MEV sandwich attack solana jito bundle",
            "spam transaction flood TPU congestion solana",
            "validator skip delinquent stake behavior",
            "oracle manipulation price deviation defi solana"
        ])

        result = analyze(features, rag)

        print("\nRESULT:")
        print(result)

    return True

import json
from agents.network.network_router import collect_metrics
from rag.context_builder import build_rag_context
from agents.network.features import build_features
from agents.network.prompt import build_prompt
from models.llm import load_model
from utils.json_parser import extract_json
from utils.report_writer import save_report
from utils.pretty_print import print_report

def run(address, network="testnet"):

    print("\n[PIPELINE] STARTING ANALYSIS\n")

    metrics = collect_metrics(
        "https://api.testnet.solana.com",
        address
    )

    features = build_features(metrics)

    queries = [
        "TPU congestion Solana spam attack",
        "validator skip delinquent stake Solana",
        "MEV sandwich attack Jito Solana",
        "oracle manipulation DeFi Solana",
        "stake centralization Nakamoto coefficient",
        "CVE Solana supply chain vulnerability"
    ]

    rag_context = build_rag_context(queries)

    llm = load_model()
    prompt = build_prompt(features, rag_context)

    result = llm.invoke(prompt)

    report = extract_json(result.content)

    # SAVE REPORT FILE
    path = save_report(report)

    # PRINT CLEAN OUTPUT
    print_report(report)

    print(f"Report saved at: {path}")

    return report


if __name__ == "__main__":
    import sys
    run(sys.argv[1])

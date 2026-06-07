from kb.kb_router import query_network, query_sc_rules, query_audit_findings

def get_strong_rag():

    queries = [
        "MEV sandwich attack Solana validator Jito",
        "transaction spam flood TPU congestion attack",
        "validator skip delinquent stake outage risk",
        "oracle manipulation price feed exploit",
        "gossip network partition eclipse attack",
        "centralization stake concentration Nakamoto",
        "rent exemption account manipulation"
    ]

    context = []

    for q in queries:
        for fn in [query_network, query_sc_rules, query_audit_findings]:
            try:
                res = fn(q, top_k=2)
                for r in res:
                    text = r.get("content","")[:400]
                    if text:
                        context.append(text)
            except:
                pass

    return "\n\n".join(context)

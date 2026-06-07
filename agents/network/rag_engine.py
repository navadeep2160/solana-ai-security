from kb.kb_router import query_network, query_sc_rules, query_audit_findings

def get_rag_context(queries):
    context = []
    seen = set()

    for q in queries:
        for fn in [query_network, query_sc_rules, query_audit_findings]:
            try:
                results = fn(q, top_k=5)
                for r in results:
                    c = r.get("content", "")
                    if len(c) > 50 and c not in seen:
                        context.append(c[:500])
                        seen.add(c)
            except:
                pass

    return "\n\n".join(context[:10])

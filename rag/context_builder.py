from kb.kb_router import query_network, query_sc_rules, query_audit_findings

def build_rag_context(queries):
    context = []
    seen = set()

    for q in queries:
        for fn in [query_network, query_sc_rules, query_audit_findings]:
            try:
                results = fn(q, top_k=2)
                for r in results:
                    text = r.get("content","")[:400]
                    if text and text not in seen:
                        seen.add(text)
                        context.append(f"[{r.get('source','KB')}]\n{text}")
            except:
                pass

    return "\n\n".join(context)

"""
RAG Explainer
Maps detected vulnerabilities → KB context
"""

from kb.kb_router import query_network

def explain(vuln_type: str) -> str:
    try:
        results = query_network(vuln_type, top_k=1)
        if results:
            return results[0].get("content", "")[:500]
    except:
        pass
    return "No KB context found"

"""
rag/retrieval/retriever.py
Routes all agent queries to knowledge_base/chromadb (322 chunks, 38 sources)
"""
import os, warnings
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

from kb.kb_router import (
    query, query_sc_rules, query_audit_findings,
    query_for_exploit, query_for_patch
)

def retrieve(query_text: str, top_k: int = 5, collection: str = "all") -> list:
    results = query(query_text, collection=collection, n_results=top_k)
    return [{
        "content":    r["content"],
        "metadata":   r["metadata"],
        "relevance":  r["relevance"],
        "collection": r["collection"],
    } for r in results]

def retrieve_for_exploit(vuln_type: str) -> dict:
    results = retrieve(vuln_type, top_k=1, collection="sc_rules")
    return results[0] if results else {}

def retrieve_for_patch(contract_code: str, top_k: int = 3) -> str:
    results = retrieve(contract_code[:500], top_k=top_k, collection="sc_rules")
    return "\n".join(r["content"][:300] for r in results)

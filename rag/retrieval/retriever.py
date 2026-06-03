"""
rag/retrieval/retriever.py
--------------------------
Upgraded retriever — queries unified KB (5 collections)
instead of old single chroma collection.
Falls back to old collection if unified KB not available.
"""
import os
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"

from pathlib import Path

UNIFIED_KB_PATH = Path("kb/chroma_unified")
OLD_KB_PATH     = Path("rag/vector_db/chroma")


def retrieve(query: str, top_k: int = 5, collection: str = "all") -> list:
    """
    Query the unified KB by semantic similarity.
    
    Args:
        query:      Search text
        top_k:      Number of results
        collection: "all" | "sc_rules" | "audit_findings" | 
                    "network_incidents" | "validator_baselines" | 
                    "research_knowledge"
    Returns:
        List of {"content": str, "metadata": dict, "relevance": float}
    """
    if UNIFIED_KB_PATH.exists():
        return _retrieve_unified(query, top_k, collection)
    else:
        return _retrieve_legacy(query, top_k)


def _retrieve_unified(query: str, top_k: int, collection: str) -> list:
    from kb.kb_router import query as kb_query
    results = kb_query(query, collection=collection, n_results=top_k)
    output = []
    for r in results:
        meta = r["metadata"]
        # Normalize metadata — different collections use different keys
        name = (meta.get("name") or meta.get("metric") or
                meta.get("paper") or meta.get("vulnerability") or
                meta.get("id") or "")
        rid  = (meta.get("rule_id") or meta.get("id") or
                meta.get("source") or meta.get("arxiv") or "")
        output.append({
            "content":    r["content"],
            "metadata":   meta,
            "relevance":  r["relevance"],
            "collection": r["collection"],
            "name":       name,
            "id":         rid,
        })
    # Only return results with positive relevance when querying all
    if collection == "all":
        output = [r for r in output if r["relevance"] > 0] or output[:top_k]
    return output[:top_k]


def _retrieve_legacy(query: str, top_k: int) -> list:
    """Fallback to old single-collection chroma."""
    try:
        import chromadb
        from models.embedding_model import create_embedding
        client     = chromadb.PersistentClient(path=str(OLD_KB_PATH))
        collection = client.get_collection("solana_security")
        embedding  = create_embedding(query)
        results    = collection.query(
            query_embeddings=[embedding.tolist()],
            n_results=top_k,
        )
        output = []
        for doc, meta in zip(
            results["documents"][0],
            results["metadatas"][0],
        ):
            output.append({"content": doc, "metadata": meta})
        return output
    except Exception as e:
        print(f"[RETRIEVER] Legacy KB failed: {e}")
        return []


def retrieve_for_exploit(vuln_type: str) -> dict:
    """Get best matching rule for exploit agent."""
    results = retrieve(vuln_type, top_k=1, collection="sc_rules")
    return results[0] if results else {}


def retrieve_for_patch(contract_code: str, top_k: int = 3) -> str:
    """Get fix patterns for patcher — returns formatted string."""
    results = retrieve(contract_code[:500], top_k=top_k, collection="sc_rules")
    fixes = []
    for r in results:
        meta = r.get("metadata", {})
        name = meta.get("name", "")
        fix  = meta.get("fix", "")
        rid  = meta.get("rule_id", "")
        if fix:
            fixes.append(f"[{rid}] {name}: {fix}")
    return "\n".join(fixes) if fixes else ""

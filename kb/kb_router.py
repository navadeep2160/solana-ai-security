"""
kb/kb_router.py
---------------
Routes agent queries to correct ChromaDB collection.
Used by: scanner, exploit agent, patcher, scorer
"""
import os
import chromadb
from pathlib import Path
from sentence_transformers import SentenceTransformer

os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"

CHROMA_DIR = Path("kb/chroma_unified")
_client    = None
_embedder  = None

COLLECTIONS = {
    "sc_rules":            "Smart contract vulnerability rules",
    "audit_findings":      "Real audit findings from OtterSec, Neodyme, ToB",
    "network_incidents":   "Solana network outages and exploits",
    "validator_baselines": "Normal validator metric ranges",
    "research_knowledge":  "Academic research on Solana security",
}


def _get_client():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    return _client


def _get_embedder():
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedder


def query(
    text: str,
    collection: str = "sc_rules",
    n_results: int = 5,
    severity: str = None,
    tags: list = None,
) -> list:
    """
    Query a KB collection by semantic similarity.
    
    Args:
        text:       Query text
        collection: One of COLLECTIONS keys or "all"
        n_results:  Number of results per collection
        severity:   Filter by severity (optional)
        tags:       Filter by tags in metadata (optional)
    
    Returns:
        List of dicts with keys: content, metadata, distance, collection
    """
    client   = _get_client()
    embedder = _get_embedder()
    vector   = embedder.encode(text).tolist()

    collections_to_query = (
        list(COLLECTIONS.keys()) if collection == "all"
        else [collection]
    )

    results = []
    for col_name in collections_to_query:
        try:
            col = client.get_collection(col_name)
            where = {}
            if severity:
                where["severity"] = severity
            
            res = col.query(
                query_embeddings=[vector],
                n_results=min(n_results, col.count()),
                where=where if where else None,
                include=["documents", "metadatas", "distances"],
            )

            for doc, meta, dist in zip(
                res["documents"][0],
                res["metadatas"][0],
                res["distances"][0],
            ):
                results.append({
                    "content":    doc,
                    "metadata":   meta,
                    "distance":   dist,
                    "collection": col_name,
                    "relevance":  round(1 - dist, 3),
                })
        except Exception as e:
            pass

    # Sort by relevance
    results.sort(key=lambda x: x["relevance"], reverse=True)
    return results[:n_results * len(collections_to_query)]


def query_for_exploit(vuln_type: str) -> dict:
    """
    Get exploit strategy for a vulnerability type.
    Returns the most relevant rule with exploit_class.
    """
    results = query(vuln_type, collection="sc_rules", n_results=3)
    if results:
        return results[0]
    return {}


def query_for_patch(vuln_type: str, n: int = 3) -> str:
    """Get fix patterns for patcher prompt."""
    results = query(vuln_type, collection="sc_rules", n_results=n)
    fixes = []
    for r in results:
        meta = r["metadata"]
        if "fix" in meta:
            fixes.append(f"[{meta.get('rule_id','?')}] {meta.get('name','')}: {meta['fix']}")
    return "\n".join(fixes)


def stats() -> dict:
    client = _get_client()
    out = {}
    total = 0
    for col_name in COLLECTIONS:
        try:
            col = client.get_collection(col_name)
            count = col.count()
            out[col_name] = count
            total += count
        except Exception:
            out[col_name] = 0
    out["total"] = total
    return out


if __name__ == "__main__":
    import json
    print("KB Stats:", json.dumps(stats(), indent=2))
    print("\nQuery: 'missing signer check withdraw'")
    results = query("missing signer check withdraw", collection="sc_rules", n_results=3)
    for r in results:
        print(f"  [{r['relevance']}] {r['metadata'].get('rule_id','?')} — {r['metadata'].get('name','?')}")
    print("\nQuery: 'overflow underflow arithmetic'")
    results = query("overflow underflow arithmetic", collection="sc_rules", n_results=3)
    for r in results:
        print(f"  [{r['relevance']}] {r['metadata'].get('rule_id','?')} — {r['metadata'].get('name','?')}")
    print("\nPatch context for 'missing signer':")
    print(query_for_patch("missing signer"))

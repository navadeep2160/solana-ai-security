"""
kb/kb_router.py
---------------
Routes agent queries to correct ChromaDB collection.
Points to knowledge_base/chromadb built from 38 sources.
"""
import os, warnings
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")

import chromadb
from pathlib import Path
from sentence_transformers import SentenceTransformer

# Point to our new KB built from 38 sources
CHROMA_DIR = Path("knowledge_base/chromadb")

_client   = None
_embedder = None

# Map old collection names → new collection names
COLLECTION_MAP = {
    "sc_rules":            "vulnerabilities",
    "audit_findings":      "audit_findings",
    "network_incidents":   "network_kb",
    "validator_baselines": "network_kb",
    "research_knowledge":  "vulnerabilities",
    # new names work directly too
    "vulnerabilities":     "vulnerabilities",
    "network_kb":          "network_kb",
    "architecture":        "architecture",
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
    client   = _get_client()
    embedder = _get_embedder()
    vector   = embedder.encode(text).tolist()

    # Resolve collection name
    if collection == "all":
        collections_to_query = ["vulnerabilities", "audit_findings",
                                 "architecture", "network_kb"]
    else:
        resolved = COLLECTION_MAP.get(collection, "vulnerabilities")
        collections_to_query = [resolved]

    results = []
    for col_name in collections_to_query:
        try:
            col = client.get_collection(col_name)
            res = col.query(
                query_embeddings=[vector],
                n_results=min(n_results, col.count()),
                include=["documents", "metadatas", "distances"],
            )
            for doc, meta, dist in zip(
                res["documents"][0],
                res["metadatas"][0],
                res["distances"][0],
            ):
                # skip garbage
                if "signed in with another tab" in doc or len(doc) < 80:
                    continue
                results.append({
                    "content":    doc,
                    "metadata":   meta,
                    "distance":   dist,
                    "collection": col_name,
                    "relevance":  round(1 - dist, 3),
                })
        except Exception as e:
            pass

    results.sort(key=lambda x: x["relevance"], reverse=True)
    return results[:n_results]

# ── Convenience helpers used by agents ──────────────────────

def query_sc_rules(text: str, top_k: int = 3) -> list:
    return query(text, collection="sc_rules", n_results=top_k)

def query_audit_findings(text: str, top_k: int = 3) -> list:
    return query(text, collection="audit_findings", n_results=top_k)

def query_network(text: str, top_k: int = 3) -> list:
    return query(text, collection="network_kb", n_results=top_k)

def query_for_exploit(vuln_type: str) -> dict:
    results = query_sc_rules(vuln_type, top_k=3)
    return results[0] if results else {}

def query_for_patch(vuln_type: str, n: int = 3) -> str:
    results = query_sc_rules(vuln_type, top_k=n)
    return "\n".join(r["content"][:300] for r in results)

def stats() -> dict:
    client = _get_client()
    out = {}
    total = 0
    for col_name in ["vulnerabilities", "audit_findings", "architecture", "network_kb"]:
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
    print("\nQuery: missing signer check")
    for r in query_sc_rules("missing signer check withdraw", top_k=2):
        print(f"  [{r['relevance']}] {r['content'][:100]}")
    print("\nQuery: overflow underflow")
    for r in query_sc_rules("overflow underflow arithmetic", top_k=2):
        print(f"  [{r['relevance']}] {r['content'][:100]}")

def query_vuln_nodes(text: str, top_k: int = 5, category: str = None) -> list:
    """
    Query structured vulnerability nodes.
    Returns nodes with name, severity, fix, preconditions.
    Used by V3 scanner for node matching.
    """
    client   = _get_client()
    embedder = _get_embedder()
    vector   = embedder.encode(text).tolist()
    try:
        col   = client.get_collection("vuln_nodes")
        where = {"category": category} if category else None
        res   = col.query(
            query_embeddings=[vector],
            n_results=min(top_k, col.count()),
            where=where,
            include=["documents","metadatas","distances"],
        )
        results = []
        for doc, meta, dist in zip(
            res["documents"][0],
            res["metadatas"][0],
            res["distances"][0],
        ):
            results.append({
                "content":   doc,
                "name":      meta["name"],
                "category":  meta["category"],
                "severity":  meta["severity"],
                "fix":       meta["fix"],
                "source":    meta["source"],
                "relevance": round(1 - dist, 3),
            })
        return results
    except Exception as e:
        return []

import json
import sys
from pathlib import Path
from tqdm import tqdm
import chromadb
from sentence_transformers import SentenceTransformer

RAW_DIR = Path(__file__).parent.parent / "raw_sources"
DB_DIR  = Path(__file__).parent.parent / "chromadb"
DB_DIR.mkdir(exist_ok=True)

# Collection → source IDs mapping
COLLECTION_SOURCES = {
    "vulnerabilities": [
        "vrust_paper", "fuzzdelsel_paper", "acm_2022", "acm_2025",
        "solana_program_arxiv", "sealevel_attacks", "swc_registry",
        "neodyme_pitfalls", "sec3_spl", "otter_anchor_security"
    ],
    "audit_findings": [
        "neodyme_reports", "neodyme_anker", "ottersec_reports",
        "trailofbits_solana", "cantina_guide", "cve_solana",
        "immunefi_solana", "slither_detectors"
    ],
    "architecture": [
        "solana_whitepaper", "solana_github", "spl_security",
        "solana_simds", "helius_docs", "eclipse_attack"
    ],
    "network_kb": [
        "solana_status", "validators_app", "helium_hip",
        "helium_sharing", "lorawan_helium", "developer_status",
        "otter_sec_anchor"
    ]
}

def chunk_text(text, chunk_size=500, overlap=50):
    """Split text into overlapping chunks."""
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i:i+chunk_size])
        if len(chunk.strip()) > 100:  # skip tiny chunks
            chunks.append(chunk)
        i += chunk_size - overlap
    return chunks

def ingest_all():
    print("Loading embedding model (one time)...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    print("Model loaded.\n")

    client = chromadb.PersistentClient(path=str(DB_DIR))

    total_chunks = 0

    for collection_name, source_ids in COLLECTION_SOURCES.items():
        print(f"\n=== Ingesting: {collection_name} ===")

        # Delete and recreate for clean ingest
        try:
            client.delete_collection(collection_name)
        except:
            pass
        collection = client.create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"}
        )

        col_chunks = 0

        for source_id in tqdm(source_ids, desc=collection_name):
            raw_file = RAW_DIR / f"{source_id}.json"
            if not raw_file.exists():
                print(f"  MISSING: {source_id}")
                continue

            data = json.loads(raw_file.read_text())
            if data["status"] != "OK" or not data["text"]:
                print(f"  SKIP (no text): {source_id}")
                continue

            chunks = chunk_text(data["text"])
            if not chunks:
                continue

            # Embed all chunks at once (fast)
            embeddings = model.encode(chunks, show_progress_bar=False).tolist()

            ids       = [f"{source_id}_chunk_{i}" for i in range(len(chunks))]
            metadatas = [{
                "source_id":  source_id,
                "title":      data["title"],
                "url":        data["url"],
                "collection": collection_name,
                "chunk_index": i
            } for i in range(len(chunks))]

            # Batch upsert
            batch_size = 50
            for b in range(0, len(chunks), batch_size):
                collection.upsert(
                    ids=ids[b:b+batch_size],
                    embeddings=embeddings[b:b+batch_size],
                    documents=chunks[b:b+batch_size],
                    metadatas=metadatas[b:b+batch_size]
                )

            col_chunks += len(chunks)
            print(f"  {source_id}: {len(chunks)} chunks")

        total_chunks += col_chunks
        print(f"  → {collection_name} total: {col_chunks} chunks")

    print(f"\n{'='*40}")
    print(f"INGESTION COMPLETE")
    print(f"Total chunks in ChromaDB: {total_chunks}")
    print(f"DB saved at: {DB_DIR}")
    print(f"{'='*40}")

    # Final verification
    print("\n=== COLLECTION SIZES ===")
    for name in COLLECTION_SOURCES:
        col = client.get_collection(name)
        print(f"  {name}: {col.count()} chunks")

if __name__ == "__main__":
    ingest_all()

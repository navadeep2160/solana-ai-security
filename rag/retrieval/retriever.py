import chromadb
from models.embedding_model import create_embedding

client = chromadb.PersistentClient(
    path="rag/vector_db/chroma"
)

collection = client.get_collection("solana_security")


def retrieve(query: str, top_k: int = 5):

    embedding = create_embedding(query)

    results = collection.query(
        query_embeddings=[embedding.tolist()],
        n_results=top_k
    )

    output = []

    for doc, meta in zip(
        results["documents"][0],
        results["metadatas"][0]
    ):
        output.append({
            "content": doc,
            "metadata": meta
        })

    return output
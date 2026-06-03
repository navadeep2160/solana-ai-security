import json
import chromadb

from models.embedding_model import (
    create_embedding
)

client = chromadb.PersistentClient(
    path="rag/vector_db/chroma"
)

collection = client.get_or_create_collection(
    "solana_security"
)

with open(
    "knowledge_base/processed/master_knowledge.json",
    "r",
    encoding="utf-8"
) as f:

    data = json.load(f)

for item in data:

    embedding = create_embedding(
        item["content"]
    )

    collection.add(

        ids=[item["id"]],

        documents=[item["content"]],

        embeddings=[embedding.tolist()],

        metadatas=[item["metadata"]]
    )

print("Vector DB built.")
import os
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"

from sentence_transformers import SentenceTransformer
from models.model_registry import get_model

embedding_model = SentenceTransformer(
    get_model("embedding_model")
)

def create_embedding(text: str):
    return embedding_model.encode(text)

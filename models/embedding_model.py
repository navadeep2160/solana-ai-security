from sentence_transformers import SentenceTransformer
from models.model_registry import get_model

embedding_model = SentenceTransformer(
    get_model("embedding_model")
)

def create_embedding(text):

    return embedding_model.encode(text)
MODELS = {
    "scanner_model": "gemini-2.5-flash",
    "patch_model": "gemini-2.5-flash",
    "embedding_model": "all-MiniLM-L6-v2"
}

def get_model(key: str):
    return MODELS.get(key)

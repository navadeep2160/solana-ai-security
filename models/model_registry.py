import yaml

MODELS = {
    "scanner_model": "gemini-2.5-flash-lite",
    "patch_model": "gemini-2.5-flash-lite"
}


def get_model(key: str):
    return MODELS.get(key)
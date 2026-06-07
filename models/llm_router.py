import os
from dotenv import load_dotenv
load_dotenv()

def load_model(force_local=True):
    """
    ALWAYS USE OLLAMA (stable mode for your project)
    """
    from langchain_ollama import ChatOllama

    model = "qwen2.5-coder:14b"
    print(f"[MODEL] Loading → {model} (Ollama LOCAL)")

    return ChatOllama(
        model=model,
        temperature=0
    )

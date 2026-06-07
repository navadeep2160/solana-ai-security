import os
from dotenv import load_dotenv
load_dotenv()

USE_OLLAMA = True  # Set False to use Groq

def load_model(model_name: str = None, model_key: str = "scan_model", force_local: bool = False):
    if USE_OLLAMA or force_local:
        from langchain_ollama import ChatOllama
        print(f"[MODEL] Loading → qwen2.5-coder:14b (Ollama LOCAL)")
        return ChatOllama(
            model="qwen2.5-coder:14b",
            temperature=0,
            base_url="http://localhost:11434",
        )
    else:
        from langchain_groq import ChatGroq
        name = "llama-3.3-70b-versatile"
        api_key = os.getenv("GROQ_API_KEY","").strip()
        print(f"[MODEL] Loading → {name} (Groq)")
        return ChatGroq(model=name, temperature=0, api_key=api_key, max_tokens=4096)

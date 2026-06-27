"""
Ollama Client with Singleton Caching
====================================
Loads model ONCE and reuses across all agent calls.
Eliminates ~2 min overhead from repeated model reloads.
"""
import os
import warnings
from typing import Optional

warnings.filterwarnings("ignore")
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# ── Singleton cache ────────────────────────────────────────
_chat_ollama_instance: Optional[object] = None
_chat_ollama_model_name: Optional[str] = None

_raw_ollama_instance: Optional[object] = None
_raw_ollama_model_name: Optional[str] = None

def get_ollama_client(model_name: str = "qwen2.5-coder:14b", force_local: bool = True):
    """Get cached raw Ollama client. Loads once, reuses forever."""
    global _raw_ollama_instance, _raw_ollama_model_name
    
    if _raw_ollama_instance is not None and _raw_ollama_model_name == model_name:
        return _raw_ollama_instance
    
    try:
        import ollama
        _raw_ollama_instance = ollama.Client()
        _raw_ollama_model_name = model_name
        return _raw_ollama_instance
    except Exception as e:
        print(f"[MODEL] Ollama not available: {e}")
        return None

def load_model(model_name: str = "qwen2.5-coder:14b", force_local: bool = True):
    """Get cached ChatOllama (LangChain) instance. Loads once, reuses forever."""
    global _chat_ollama_instance, _chat_ollama_model_name
    
    if _chat_ollama_instance is not None and _chat_ollama_model_name == model_name:
        return _chat_ollama_instance
    
    from langchain_ollama import ChatOllama
    
    print(f"[MODEL] Loading → {model_name} (Ollama LOCAL) [CACHED]")
    
    _chat_ollama_instance = ChatOllama(
        model=model_name,
        temperature=0.1,
        num_ctx=8192,
        base_url="http://localhost:11434",
    )
    _chat_ollama_model_name = model_name
    return _chat_ollama_instance

def clear_cache():
    """Clear all cached clients."""
    global _chat_ollama_instance, _chat_ollama_model_name
    global _raw_ollama_instance, _raw_ollama_model_name
    _chat_ollama_instance = None
    _chat_ollama_model_name = None
    _raw_ollama_instance = None
    _raw_ollama_model_name = None
    print("[MODEL] Cache cleared")

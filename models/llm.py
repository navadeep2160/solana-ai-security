from langchain_ollama import ChatOllama

def load_model():
    print("[MODEL] Using Ollama qwen2.5-coder:14b")
    return ChatOllama(
        model="qwen2.5-coder:14b",
        temperature=0
    )

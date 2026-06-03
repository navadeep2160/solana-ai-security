import os
from dotenv import load_dotenv
load_dotenv()

def load_model(model_name: str = "llama-3.3-70b-versatile"):
    from langchain_groq import ChatGroq
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        raise ValueError("GROQ_API_KEY not set in environment or .env file")
    print(f"[GROQ] Loading → llama-3.3-70b-versatile")
    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0,
        api_key=api_key,
    )
    print(f"[GROQ] Model loaded successfully")
    return llm

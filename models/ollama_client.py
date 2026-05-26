import os
import time
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

MODELS = {
    "scan_model":      "gemini-2.5-flash",
    "patch_model":     "gemini-2.5-flash",
    "validator_model": "gemini-2.5-flash",
}


def load_model(model_key: str):
    model_name = MODELS.get(model_key, "gemini-2.5-flash")

    api_key = "AIzaSyDi0GHdKOzk60pDzIm-c8uKc7wXTywSxfY"
    if not api_key:
        raise ValueError("GOOGLE_API_KEY not found in .env")

    print(f"[GEMINI] Loading → {model_name}")

    llm = ChatGoogleGenerativeAI(
        model=model_name,
        temperature=0,
        google_api_key=api_key,
        request_timeout=120,
    )

    print("[GEMINI] Model loaded successfully")
    return llm

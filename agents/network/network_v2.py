import json
from models.ollama_client import load_model
from agents.network.rag_fix import get_strong_rag
from agents.network.prompt_fix import build_prompt

def run_pipeline(metrics: dict):

    print("[PIPELINE] Extracting features...")

    rag_context = get_strong_rag()

    print("[PIPELINE] Detecting vulnerabilities...")

    prompt = build_prompt(metrics, rag_context, "testnet")

    print("[PIPELINE] Loading LLM (Ollama)...")

    llm = load_model(force_local=True)

    response = llm.invoke(prompt)

    raw = response.content

    # parse safely
    try:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        result = json.loads(raw[start:end])
    except:
        result = {
            "risk_score": 0,
            "vulnerabilities": [],
            "summary": "parse failed",
            "raw": raw[:500]
        }

    return {
        "features": metrics,
        "rag_used": len(rag_context),
        "analysis": result
    }

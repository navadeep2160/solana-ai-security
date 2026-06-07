import json
from models.ollama_client import load_model
from agents.network.utils_json import extract_json

def analyze(tx_features, rag_context):

    llm = load_model(force_local=True)

    prompt = f"""
You are a professional Solana blockchain security auditor.

IMPORTANT RULE:
Do NOT flag generic spam unless:
- repeated high-frequency transactions in SAME slot
- OR identical instruction patterns

Do NOT hallucinate anomalies.

TX:
{json.dumps(tx_features, indent=2)}

RAG:
{rag_context}

Detect ONLY real evidence-based issues:
- MEV sandwich
- validator skip
- oracle manipulation
- real spam attack (must be proven by slot clustering)

Return strict JSON:
{{
  "risk_score": 0-10,
  "vulnerabilities": [],
  "summary": ""
}}
"""

    res = llm.invoke(prompt).content
    parsed = extract_json(res)

    return parsed if parsed else {
        "risk_score": 0,
        "vulnerabilities": [],
        "summary": "parse_failed"
    }

def build_prompt(metrics, rag_context):
    return f"""
You are a Solana network security engine.

You MUST detect ONLY from REAL evidence in metrics + RAG.

DO NOT hallucinate vulnerabilities.

METRICS:
{metrics}

RAG CONTEXT:
{rag_context}

Return JSON ONLY:

{{
  "risk_score": float,
  "vulnerabilities": [
    {{
      "type": "...",
      "severity": "low|medium|high|critical",
      "detected": true|false,
      "evidence": "...",
      "reason": "based on RAG + metrics"
    }}
  ],
  "summary": "short analysis"
}}
"""

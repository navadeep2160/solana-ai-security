def build_prompt(metrics, rag, network):

    return f"""
You are a Solana blockchain security analyst.

CRITICAL RULE:
You MUST detect vulnerabilities if ANY evidence exists.

NETWORK METRICS:
{metrics}

KNOWLEDGE BASE:
{rag}

Detect:
- spam / TPU congestion
- MEV / sandwich attack
- validator skip / downtime
- oracle manipulation
- stake centralization risk
- gossip / eclipse attack

Return ONLY JSON:
{{
  "risk_score": 0-10,
  "vulnerabilities": [
    {{
      "type": "...",
      "severity": "low|medium|high|critical",
      "detected": true,
      "evidence": "from metrics or KB"
    }}
  ],
  "summary": "short explanation"
}}
"""

import json
from langchain_core.prompts import ChatPromptTemplate
from models.ollama_client import load_model
from rag.retrieval.retriever import retrieve
from utils.logger import write_log

llm = load_model("scan_model")

PROMPT = ChatPromptTemplate.from_template("""
You are a Solana smart contract security scanner.

Return ONLY a JSON object. No markdown. No explanation. No preamble.

FORMAT:
{{
  "risks": [
    {{
      "type": "vulnerability_type",
      "severity": "critical|high|medium|low",
      "reason": "one line explanation"
    }}
  ]
}}

RULES:
- Output raw JSON only
- No ``` fences
- No text before or after JSON
- Only real vulnerabilities
- Keep reasons short

SECURITY CONTEXT:
{context}

CONTRACT:
{contract}
""")


def scan_contract(contract: str) -> dict:
    print("[SCANNER] Retrieving RAG context...")

    retrieved = retrieve(contract, top_k=2)
    context = "\n\n".join(
        r["content"][:400] for r in retrieved
    )

    print("[SCANNER] Running Gemini scan...")

    result = (PROMPT | llm).invoke({
        "contract": contract,
        "context": context
    })

    raw = result.content.strip()

    # Strip fences if model misbehaves
    if raw.startswith("```"):
        raw = raw.strip("`").strip()
        if raw.startswith("json"):
            raw = raw[4:].strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        print("[SCANNER] ⚠️  JSON parse failed — wrapping raw output")
        parsed = {"risks": [], "raw": raw}

    log_path = write_log("scanner", parsed)
    print(f"[SCANNER] Log saved → {log_path}")

    return parsed
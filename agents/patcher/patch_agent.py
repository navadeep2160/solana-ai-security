from langchain_core.prompts import ChatPromptTemplate
from models.ollama_client import load_model
from rag.retrieval.retriever import retrieve
from utils.extract_rust import extract_rust
from utils.rust_guard import looks_like_rust
from utils.logger import write_log

llm = load_model("patch_model")

PROMPT = ChatPromptTemplate.from_template("""
You are a Solana Rust security patching engine.

Return ONLY valid Rust code. No explanations. No markdown. No fences.

STRICT RULES:
- Output raw Rust source only
- Do NOT write ``` or ```rust
- Do NOT explain anything
- Preserve original file structure
- Only fix the vulnerable lines
- All Anchor macros must remain valid
- The contract must compile with `anchor build`

COMPILER ERRORS (fix these):
{errors}

SECURITY CONTEXT (apply these patterns):
{context}

VULNERABLE CONTRACT (patch this):
{contract}
""")


def patch_contract(contract: str, errors: str = "") -> str:
    print("[PATCHER] Retrieving RAG context...")

    retrieved = retrieve(contract, top_k=2)
    context = "\n\n".join(
        r["content"][:400] for r in retrieved
    )

    print("[PATCHER] Calling Gemini for patch...")

    result = (PROMPT | llm).invoke({
        "contract": contract,
        "errors": errors,
        "context": context
    })

    raw = result.content
    patched_code = extract_rust(raw)

    if not looks_like_rust(patched_code):
        print("[PATCHER] ⚠️  Output failed rust_guard — returning original")
        patched_code = contract

    output = {
        "patched_code": patched_code,
        "errors_fed": errors
    }

    log_path = write_log("patcher", output)
    print(f"[PATCHER] Log saved → {log_path}")

    return patched_code
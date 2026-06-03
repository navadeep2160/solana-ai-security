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
- Output raw Rust source only — no fences, no comments, no explanations
- Keep EXACT same imports — do NOT add any new use statements
- Keep EXACT same declare_id! value unchanged
- Keep EXACT same account structs — do NOT add fields, PDAs, or system_program
- Keep EXACT same error codes — do NOT add new ErrorCode variants
- Only change function bodies to fix vulnerabilities:
  * Replace -= with .checked_sub(x).ok_or(ErrorCode::Underflow)?
  * Replace += with .checked_add(x).ok_or(ErrorCode::Overflow)?
  * Replace AccountInfo<'info> with Signer<'info> for authority fields
  * Add has_one = owner constraint to Withdraw and CloseAccount structs
- Do NOT add CPI transfers, PDA seeds, bumps, or system_program fields
- Must compile with: cargo check

COMPILER ERRORS (fix these if present):
{errors}

SECURITY CONTEXT:
{context}

ORIGINAL CONTRACT (apply minimal fixes only):
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

    # Fix ErrorCode — remove any broken version, inject correct one
    import re as _re
    if "ErrorCode::" in patched_code:
        # Remove ALL existing ErrorCode enum definitions
        patched_code = _re.sub(
            r'#\[error(?:_code)?\]\s*\npub enum ErrorCode\s*\{[^}]*\}\s*',
            '',
            patched_code,
            flags=_re.DOTALL
        )
        # Inject correct version
        patched_code = patched_code.rstrip() + """
#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Underflow")]
    Underflow,
}
"""
        print("[PATCHER] Injected clean ErrorCode enum")

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
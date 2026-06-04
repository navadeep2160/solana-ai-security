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

RULES:
- Raw Rust only — no fences, no comments, no explanations
- Keep EXACT same declare_id! value
- Keep EXACT same imports
- Must compile with cargo check

SECURITY FIXES — apply ALL of these:

1. ARITHMETIC — replace unsafe += and -= everywhere:
   x -= y  →  x = x.checked_sub(y).ok_or(ErrorCode::Underflow)?
   x += y  →  x = x.checked_add(y).ok_or(ErrorCode::Overflow)?

2. SIGNER CHECKS — in account structs replace AccountInfo with Signer for authority fields:
   pub user: AccountInfo<'info>    →  pub user: Signer<'info>
   pub caller: AccountInfo<'info>  →  pub caller: Signer<'info>

3. CPI TARGET PROGRAM — keep as AccountInfo but add executable constraint:
   pub target_program: AccountInfo<'info>
   →  #[account(executable)]
      pub target_program: AccountInfo<'info>

4. OWNER CHECKS — add has_one constraint to fund-modifying structs:
   Withdraw struct bank account   →  #[account(mut, has_one = owner)]
                                     rename user field to: pub owner: Signer<'info>
   CloseAccount struct bank       →  #[account(mut, has_one = owner, close = owner)]
                                     rename caller field to: pub owner: Signer<'info>
   Transfer struct from account   →  #[account(mut, has_one = owner)]
   Transfer struct to account     →  #[account(mut, constraint = to.key() != from.key() @ ErrorCode::Unauthorized)]

5. REINITIALIZE — add admin constraint:
   Reinitialize struct bank  →  #[account(mut, constraint = bank.admin == caller.key() @ ErrorCode::Unauthorized)]

6. SET_LOCKED — add admin constraint:
   SetLocked struct bank  →  #[account(mut, constraint = bank.admin == caller.key() @ ErrorCode::Unauthorized)]

COMPILER ERRORS (fix these if present):
{errors}

SECURITY CONTEXT:
{context}

CONTRACT TO PATCH (apply ALL fixes above):
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
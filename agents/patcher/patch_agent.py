"""
KB-driven Patcher — Zero hardcoded field names or fix rules.
Flow: Contract → AST facts → KB fix patterns → AI patch
"""
import re
from models.ollama_client import load_model
from utils.extract_rust import extract_rust
from utils.rust_guard import looks_like_rust
from utils.logger import write_log


def extract_contract_structure(contract: str) -> dict:
    from analysis.ast_parser.rust_ast_parser import parse_rust_ast
    try:
        ast = parse_rust_ast(contract)
        structs = {}
        for s in ast.account_structs:
            structs[s.name] = [
                {"name": f["name"], "type": f["type"],
                 "is_account_info": f["is_account_info"],
                 "is_signer": f["is_signer"],
                 "has_constraint": f["has_constraint"]}
                for f in s.fields
            ]
        functions = {
            fn.name: {
                "line": fn.line,
                "has_signer": fn.has_signer,
                "has_owner": fn.has_owner_check,
                "has_safe_math": fn.has_checked_math,
            }
            for fn in ast.functions
        }
        return {"structs": structs, "functions": functions}
    except Exception as e:
        return {"structs": {}, "functions": {}}


def get_kb_fix_patterns(structure: dict) -> str:
    from kb.kb_router import query_vuln_nodes, query_audit_findings
    patterns, seen = [], set()

    for sname, fields in structure.get("structs", {}).items():
        for f in fields:
            if f["is_account_info"] and not f["is_signer"]:
                nodes = query_vuln_nodes(
                    f"AccountInfo {f['name']} missing signer fix", top_k=1)
                for n in nodes:
                    if n["fix"] and n["fix"] not in seen:
                        patterns.append(f"[{n['name']}] {n['fix']}")
                        seen.add(n["fix"])

    for fname, fdata in structure.get("functions", {}).items():
        if not fdata["has_safe_math"]:
            nodes = query_vuln_nodes("arithmetic overflow fix checked", top_k=1)
            for n in nodes:
                if n["fix"] and n["fix"] not in seen:
                    patterns.append(f"[{n['name']}] {n['fix']}")
                    seen.add(n["fix"])
            break

    audits = query_audit_findings("owner check signer fix anchor", top_k=2)
    for a in audits:
        patterns.append(f"[Audit] {a['content'][:150]}")

    return "\n".join(patterns[:8])


def patch_contract(contract: str, errors: str = "") -> str:
    print("[PATCHER] Extracting contract structure...")
    structure = extract_contract_structure(contract)
    print(f"[PATCHER] {len(structure['structs'])} structs, "
          f"{len(structure['functions'])} functions")

    print("[PATCHER] Getting KB fix patterns...")
    kb_patterns = get_kb_fix_patterns(structure)

    struct_summary = "\n".join(
        f"{sname}: {[(f['name'], f['type']) for f in fields]}"
        for sname, fields in structure["structs"].items()
    )
    fn_summary = "\n".join(
        f"{fname}: signer={d['has_signer']} owner={d['has_owner']} "
        f"safe_math={d['has_safe_math']}"
        for fname, d in structure["functions"].items()
    )

    llm = load_model()
    print("[PATCHER] Calling LLM for patch...")

    prompt = f"""You are a Solana Anchor smart contract security patcher.
Return ONLY valid Rust code. No markdown. No fences. No explanations.

CRITICAL ANCHOR RULES:
- ONLY use these ErrorCode variants: Unauthorized, Underflow, Overflow, InsufficientFunds, DuplicateAccount, InvalidProgram, AlreadyInitialized, NotInitialized, SameAccountTransfer, AccountLocked, InvalidOwner, InvalidAmount
- NEVER invent new ErrorCode variants not in the list above
- NEVER use ProgramError — this is Anchor, use ErrorCode::Variant or error!(ErrorCode::Variant)
- For signer checks use: require!(ctx.accounts.X.is_signer, ErrorCode::Unauthorized)
  OR change field type to Signer<'info> in the struct
- For owner checks use: require!(bank.owner == ctx.accounts.X.key(), ErrorCode::Unauthorized)
- For arithmetic use: .checked_sub(y).ok_or(error!(ErrorCode::Underflow))?
- Keep EXACT declare_id! value
- Keep EXACT module name
- NEVER dereference Pubkey: use ctx.accounts.x.key() NOT *ctx.accounts.x.key()
- For owner checks: require!(bank.owner == ctx.accounts.owner.key(), ErrorCode::Unauthorized)

ACTUAL CONTRACT STRUCTURE:
Structs (use ONLY these field names):
{struct_summary}

Functions:
{fn_summary}

KB FIX PATTERNS:
{kb_patterns}

COMPILER ERRORS TO FIX:
{errors if errors else "None"}

FIXES NEEDED:
1. Replace unsafe arithmetic with checked_sub/checked_add + ErrorCode
2. Add signer/owner validation using ACTUAL field names from structs above
3. Add constraint for CPI program validation
4. Add ErrorCode enum at the end

CONTRACT:
{contract}"""

    try:
        result = llm.invoke(prompt)
        patched_code = extract_rust(result.content)
    except Exception as e:
        print(f"[PATCHER] LLM failed: {e}")
        patched_code = contract

    # Inject ErrorCode if needed
    if "ErrorCode::" in patched_code:
        patched_code = re.sub(
            r'#\[error(?:_code)?\]\s*\npub enum ErrorCode\s*\{[^}]*\}\s*',
            '', patched_code, flags=re.DOTALL)
        patched_code = patched_code.rstrip() + """
#[error_code]
pub enum ErrorCode {
    #[msg("Duplicate account")]
    DuplicateAccount,
    #[msg("Invalid program")]
    InvalidProgram,
    #[msg("Account already initialized")]
    AlreadyInitialized,
    #[msg("Account not initialized")]
    NotInitialized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Same account transfer")]
    SameAccountTransfer,
    #[msg("Account locked")]
    AccountLocked,
    #[msg("Invalid owner")]
    InvalidOwner,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Underflow")]
    Underflow,
}
"""
        print("[PATCHER] Injected ErrorCode enum")

    # Fix common LLM syntax errors (not vulnerability logic)
    import re as _re
    # Fix Pubkey dereference: *ctx.accounts.x.key() → ctx.accounts.x.key()
    patched_code = _re.sub(r'\*ctx\.accounts\.(\w+)\.key\(\)', 
                           r'ctx.accounts..key()', patched_code)
    # Fix double dereference: **x.key → x.key
    patched_code = _re.sub(r'\*\*(\w+)\.key\(\)', r'.key()', patched_code)

    if not looks_like_rust(patched_code):
        print("[PATCHER] ⚠️  rust_guard failed — returning original")
        patched_code = contract

    write_log("patcher", {"patched_code": patched_code, "errors_fed": errors})
    print("[PATCHER] Log saved")
    return patched_code

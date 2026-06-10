"""
Invariant Extraction Agent — Week 4
AI reads contract → extracts what SHOULD always be true →
Exploit agent tests each invariant → broken = novel vulnerability.
Zero hardcoded invariants.
"""
import json
from models.ollama_client import load_model
from utils.logger import write_log


def extract_invariants(contract: str) -> list:
    """
    AI reads contract + KB context → extracts behavioral invariants.
    No hardcoded invariants — AI discovers them from code + KB.
    """
    print("[INVARIANT] Extracting contract invariants...")

    from analysis.ast_parser.rust_ast_parser import parse_rust_ast
    from kb.kb_router import query_sc_rules, query_vuln_nodes

    # Get structural facts
    ast = parse_rust_ast(contract)
    fn_names = [fn.name for fn in ast.functions]
    struct_names = [s.name for s in ast.account_structs]

    # Query KB for what invariants matter in Solana
    kb = query_sc_rules("invariant guarantee contract security property", top_k=3)
    kb_context = "\n".join(r["content"][:200] for r in kb)

    llm = load_model()

    prompt = f"""You are a Solana smart contract formal verification expert.

Read this contract and extract ALL behavioral invariants — properties that
should ALWAYS be true for this contract to be secure.

CONTRACT:
{contract[:3000]}

FUNCTIONS: {fn_names}
ACCOUNT STRUCTS: {struct_names}

KB CONTEXT ON SECURITY PROPERTIES:
{kb_context[:800]}

Extract invariants that, if broken, indicate a vulnerability.
Think about:
- Balance/state consistency: what should never happen to balances?
- Access control: who should NEVER be able to call what?
- State transitions: what sequences of operations should be impossible?
- Data integrity: what field values should always hold certain properties?

Return ONLY valid JSON:
{{
  "invariants": [
    {{
      "id": "INV-001",
      "invariant": "balance never goes below zero",
      "property": "arithmetic_safety",
      "test_instruction": "withdraw",
      "test_amount": 999999999999,
      "test_signer": "attacker",
      "expected_result": "transaction fails",
      "violation_means": "integer underflow vulnerability",
      "severity": "critical|high|medium|low"
    }}
  ]
}}

Be specific about how to TEST each invariant with a transaction."""

    try:
        raw = llm.invoke(prompt).content.strip()
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result     = json.loads(raw.strip())
        invariants = result.get("invariants", [])
        print(f"[INVARIANT] Extracted {len(invariants)} invariants")
        for inv in invariants:
            print(f"  {inv.get('id','?')}: {inv.get('invariant','')[:60]}")
        write_log("invariants", {"invariants": invariants})
        return invariants
    except Exception as e:
        print(f"[INVARIANT] Failed: {e}")
        return []


def test_invariants(invariants: list, program_id: str,
                    rpc_url: str = "http://127.0.0.1:8899") -> list:
    """
    Test each invariant by executing the specified transaction.
    If invariant is violated → novel vulnerability found.
    """
    import asyncio, struct, hashlib
    from solana.rpc.async_api import AsyncClient
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction, AccountMeta
    from solders.message import Message
    from solders.transaction import Transaction
    from solana.rpc.commitment import Confirmed

    results = []

    async def _test(inv):
        client    = AsyncClient(rpc_url, commitment=Confirmed)
        attacker  = Keypair()
        try:
            prog_id = Pubkey.from_string(program_id)

            # Discriminator
            disc = hashlib.sha256(
                f"global:{inv['test_instruction']}".encode()
            ).digest()[:8]

            amount = int(inv.get("test_amount", 0)) % (2**64)
            data   = disc + struct.pack("<Q", amount)

            ix = Instruction(prog_id, data, [
                AccountMeta(attacker.pubkey(), True, True)
            ])
            bh  = (await client.get_latest_blockhash()).value.blockhash
            msg = Message.new_with_blockhash([ix], attacker.pubkey(), bh)
            tx  = Transaction([attacker], msg, bh)
            sig = await client.send_transaction(tx)

            conf = await client.get_transaction(
                sig.value, max_supported_transaction_version=0)
            tx_failed = bool(
                conf.value and conf.value.transaction.meta.err)

            violated = not tx_failed  # invariant violated if tx succeeded
            return {
                "id":        inv["id"],
                "invariant": inv["invariant"],
                "violated":  violated,
                "severity":  inv["severity"] if violated else "none",
                "finding":   inv["violation_means"] if violated else "",
                "tx_failed": tx_failed,
            }
        except Exception as e:
            return {"id": inv["id"], "invariant": inv["invariant"],
                    "violated": False, "error": str(e)[:100]}
        finally:
            await client.close()

    for inv in invariants:
        try:
            result = asyncio.run(_test(inv))
            results.append(result)
            status = "🔴 VIOLATED" if result.get("violated") else "✅ HOLDS"
            print(f"  {status} {inv.get('id','?')}: {inv.get('invariant','')[:50]}")
        except Exception as e:
            results.append({"id": inv.get("id","?"), "error": str(e)})

    return results


if __name__ == "__main__":
    import sys; sys.path.insert(0, '.')
    code = open(
        "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs"
    ).read()
    invs = extract_invariants(code)
    print(f"\nExtracted {len(invs)} invariants")
    for i in invs:
        print(f"  [{i.get('severity','?')}] {i.get('id','?')}: {i.get('invariant','')}")
        print(f"    Test: {i.get('test_instruction','')}({i.get('test_amount','')})"
              f" by {i.get('test_signer','')}")
        print(f"    Violation means: {i.get('violation_means','')}")

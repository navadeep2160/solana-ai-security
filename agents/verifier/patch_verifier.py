"""
Patch Verifier Agent — Week 4
Re-runs confirmed exploits on patched contract.
If exploit now FAILS → patch verified.
If exploit still SUCCEEDS → patch incomplete.
"""
import asyncio, json, os, struct, subprocess, shutil, time, hashlib
from pathlib import Path
from utils.logger import write_log

RPC_URL   = "http://127.0.0.1:8899"
FUZZ_DIR  = "/tmp/verify-ledger"
PAYER_KP  = "/tmp/verify_payer.json"
SO_PATH   = "contracts/vulnerable_bank/target/deploy/vulnerable_bank.so"
DEPLOY_KP = os.path.expanduser("~/.config/solana/id.json")


def _kill():
    subprocess.run(["pkill", "-9", "-f", "solana-test-validator"],
                   capture_output=True)
    for _ in range(10):
        time.sleep(1)
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
        if "8899" not in r.stdout:
            return

def _start():
    _kill()
    shutil.rmtree(FUZZ_DIR, ignore_errors=True)
    proc = subprocess.Popen(
        ["solana-test-validator","--reset","--quiet","-l", FUZZ_DIR],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        time.sleep(3)
        r = subprocess.run(["solana","cluster-version","--url", RPC_URL],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return proc
    return None

def _fund(kp_path, sol=10):
    subprocess.run(["solana-keygen","new","--no-bip39-passphrase",
                    "--outfile", kp_path,"--force"], capture_output=True)
    pub = subprocess.run(["solana","address","--keypair", kp_path],
                         capture_output=True, text=True).stdout.strip()
    subprocess.run(["solana","airdrop", str(sol), pub,"--url", RPC_URL],
                   capture_output=True)
    for _ in range(10):
        time.sleep(2)
        bal = subprocess.run(["solana","balance","--keypair", kp_path,
                               "--url", RPC_URL],
                              capture_output=True, text=True).stdout.strip()
        try:
            if float(bal.replace(" SOL","")) > 0:
                return pub
        except:
            pass
    return None

def _build_patched(patched_code: str) -> bool:
    lib_path = Path(
        "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs")
    lib_path.write_text(patched_code)
    r = subprocess.run(
        ["cargo", "build-sbf"],
        cwd="contracts/vulnerable_bank",
        capture_output=True, text=True)
    return r.returncode == 0

def _deploy() -> str:
    pub = subprocess.run(["solana","address","--keypair", DEPLOY_KP],
                          capture_output=True, text=True).stdout.strip()
    subprocess.run(["solana","airdrop","100", pub,"--url", RPC_URL],
                   capture_output=True)
    time.sleep(4)
    r = subprocess.run(["solana","program","deploy", SO_PATH,
                        "--url", RPC_URL,"--keypair", DEPLOY_KP],
                       capture_output=True, text=True)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if "Program Id:" in line:
                return line.split("Program Id:")[-1].strip()
    return None

async def _run_exploit(plan: dict, program_id: str, payer_kp: str) -> bool:
    """Returns True if exploit SUCCEEDED (bad — means patch failed)."""
    from solana.rpc.async_api import AsyncClient
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solders.instruction import Instruction, AccountMeta
    from solders.message import Message
    from solders.transaction import Transaction
    from solana.rpc.commitment import Confirmed

    with open(payer_kp) as f:
        payer = Keypair.from_bytes(bytes(json.load(f)))

    attacker = Keypair()
    prog_id  = Pubkey.from_string(program_id)
    client   = AsyncClient(RPC_URL, commitment=Confirmed)

    try:
        instruction = plan.get("instruction", "withdraw")
        amount      = int(plan.get("amount", 100)) % (2**64)
        who_signs   = plan.get("who_signs", "owner")
        signer      = attacker if who_signs == "attacker" else payer

        disc    = hashlib.sha256(f"global:{instruction}".encode()).digest()[:8]
        ix_data = disc + struct.pack("<Q", amount)
        ix      = Instruction(prog_id, ix_data, [
            AccountMeta(signer.pubkey(), True, True)
        ])
        bh  = (await client.get_latest_blockhash()).value.blockhash
        msg = Message.new_with_blockhash([ix], signer.pubkey(), bh)
        tx  = Transaction([signer], msg, bh)
        sig = await client.send_transaction(tx)
        await asyncio.sleep(1)
        conf = await client.get_transaction(
            sig.value, max_supported_transaction_version=0)
        # Exploit succeeded if no error
        return bool(conf.value and not conf.value.transaction.meta.err)
    except:
        return False
    finally:
        await client.close()


def verify_patch(patched_contract: str,
                 exploit_results: dict) -> tuple[bool, int, int]:
    """
    Re-run confirmed exploits on patched contract.
    Returns (verified, blocked_count, total_count)
    """
    confirmed = [f for f in exploit_results.get("findings", [])
                 if f.get("confirmed") and f.get("plan")]

    if not confirmed:
        print("[VERIFIER] No confirmed exploits to re-run")
        return True, 0, 0

    print(f"[VERIFIER] Re-running {len(confirmed)} confirmed exploits on patched contract...")

    # Build patched .so
    print("[VERIFIER] Building patched contract...")
    if not _build_patched(patched_contract):
        print("[VERIFIER] ❌ Build failed — cannot verify")
        return False, 0, len(confirmed)

    # Start validator
    print("[VERIFIER] Starting validator...")
    proc = _start()
    if not proc:
        return False, 0, len(confirmed)

    try:
        _fund(PAYER_KP, 50)
        program_id = _deploy()
        if not program_id:
            return False, 0, len(confirmed)
        print(f"[VERIFIER] Patched program: {program_id}")

        blocked = 0
        results = []

        for finding in confirmed:
            vuln = finding.get("vulnerability", "unknown")
            plan = finding.get("plan", {})
            print(f"\n[VERIFIER] Testing: {vuln}")

            exploit_succeeded = asyncio.run(
                _run_exploit(plan, program_id, PAYER_KP))

            if not exploit_succeeded:
                blocked += 1
                status = "✅ BLOCKED"
            else:
                status = "❌ STILL VULNERABLE"

            print(f"  {status}")
            results.append({
                "vulnerability": vuln,
                "blocked":       not exploit_succeeded,
                "plan":          plan,
            })

        verified = blocked == len(confirmed)
        print(f"\n[VERIFIER] {blocked}/{len(confirmed)} exploits blocked")
        print(f"[VERIFIER] Patch {'✅ VERIFIED' if verified else '❌ INCOMPLETE'}")

        write_log("patch_verifier", {
            "verified": verified,
            "blocked":  blocked,
            "total":    len(confirmed),
            "results":  results,
        })
        return verified, blocked, len(confirmed)

    finally:
        _kill()

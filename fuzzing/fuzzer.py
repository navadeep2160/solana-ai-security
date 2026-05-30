import random
import subprocess
import asyncio
import struct
import time
import json
import os
import shutil
from pathlib import Path
from utils.logger import write_log

RPC_URL        = "http://127.0.0.1:8899"
PROGRAM_DIR    = Path("contracts/vulnerable_bank/programs/vulnerable_bank")
SO_PATH        = PROGRAM_DIR / "target/deploy/vulnerable_bank.so"
DEPLOY_KEYPAIR = os.path.expanduser("~/.config/solana/id.json")
FUZZ_KEYPAIR   = "/tmp/fuzz_payer.json"
FUZZ_LEDGER    = "/tmp/fuzz-ledger"
PROG_KEYPAIR   = "contracts/vulnerable_bank/target/deploy/vulnerable_bank-keypair.json"

INIT_DISC     = bytes([175, 175, 109, 31, 13, 152, 155, 237])
DEPOSIT_DISC  = bytes([242,  35, 198, 137,  82, 225, 242, 182])
WITHDRAW_DISC = bytes([183,  18,  70, 156, 148, 109, 161,  34])
BANK_SPACE    = 8 + 32 + 8


def kill_existing_validators():
    subprocess.run(["pkill", "-9", "-f", "solana-test-validator"], capture_output=True)
    for _ in range(15):
        time.sleep(1)
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
        if "8899" not in r.stdout and "9900" not in r.stdout:
            return


def start_validator():
    print("[FUZZER] Starting solana-test-validator...")
    kill_existing_validators()
    shutil.rmtree(FUZZ_LEDGER, ignore_errors=True)
    proc = subprocess.Popen(
        ["solana-test-validator", "--reset", "--quiet", "-l", FUZZ_LEDGER],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for attempt in range(20):
        time.sleep(3)
        r = subprocess.run(["solana", "cluster-version", "--url", RPC_URL],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"[FUZZER] ✅ Validator ready")
            return proc
        if proc.poll() is not None:
            print(f"[FUZZER] ❌ Validator exited with code {proc.returncode}")
            return None
    proc.kill()
    return None


def stop_validator(proc):
    kill_existing_validators()


def setup_fuzz_keypair():
    subprocess.run(
        ["solana-keygen", "new", "--no-bip39-passphrase",
         "--outfile", FUZZ_KEYPAIR, "--force"],
        capture_output=True
    )
    pubkey = subprocess.run(
        ["solana", "address", "--keypair", FUZZ_KEYPAIR],
        capture_output=True, text=True
    ).stdout.strip()
    if not pubkey:
        return None

    subprocess.run(["solana", "airdrop", "100", pubkey, "--url", RPC_URL],
                   capture_output=True, text=True)

    for attempt in range(15):
        time.sleep(2)
        bal = subprocess.run(
            ["solana", "balance", "--keypair", FUZZ_KEYPAIR, "--url", RPC_URL],
            capture_output=True, text=True
        ).stdout.strip()
        print(f"[FUZZER]   balance check {attempt+1}: {bal}")
        try:
            if float(bal.replace(" SOL", "")) > 0:
                print(f"[FUZZER] ✅ Fuzz payer ready: {pubkey[:20]}... ({bal})")
                return pubkey
        except Exception:
            pass
    return None


def deploy():
    deploy_pub = subprocess.run(
        ["solana", "address", "--keypair", DEPLOY_KEYPAIR],
        capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(["solana", "airdrop", "100", deploy_pub, "--url", RPC_URL],
                   capture_output=True, text=True)
    time.sleep(5)

    r = subprocess.run(
        ["solana", "program", "deploy", str(SO_PATH),
         "--url", RPC_URL, "--keypair", DEPLOY_KEYPAIR,
         "--program-id", PROG_KEYPAIR],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if "Program Id:" in line:
                pid = line.split("Program Id:")[-1].strip()
                print(f"[FUZZER] ✅ Deployed → {pid}")
                return pid
    print(f"[FUZZER] ❌ Deploy failed: {r.stderr[:200]}")
    return None


async def setup_bank(payer, program_id, client):
    from solders.keypair import Keypair
    from solders.instruction import Instruction, AccountMeta
    from solders.message import MessageV0
    from solders.transaction import VersionedTransaction
    from solders.system_program import ID as SYS_ID

    bank_kp   = Keypair()
    init_data = INIT_DISC + struct.pack("<Q", 1000)
    init_ix   = Instruction(
        program_id, init_data,
        [
            AccountMeta(bank_kp.pubkey(), True,  True),
            AccountMeta(payer.pubkey(),   True,  True),
            AccountMeta(SYS_ID,           False, False),
        ],
    )
    bh  = (await client.get_latest_blockhash()).value.blockhash
    from solders.message import Message
    msg = Message.new_with_blockhash([init_ix], payer.pubkey(), bh)
    tx  = VersionedTransaction(msg, [payer, bank_kp])

    # Skip simulate — send directly, check confirmation
    try:
        sig = await client.send_transaction(tx)
        await asyncio.sleep(3)
        # Confirm it landed
        conf = await client.get_transaction(sig.value, max_supported_transaction_version=0)
        if conf.value and not conf.value.transaction.meta.err:
            print(f"[FUZZER] ✅ Bank initialized: {bank_kp.pubkey()}")
            return bank_kp, True
        else:
            err = conf.value.transaction.meta.err if conf.value else "not found"
            print(f"[FUZZER] ❌ Bank init failed on-chain: {err}")
            # Print logs
            if conf.value:
                for log in (conf.value.transaction.meta.log_messages or [])[-8:]:
                    print(f"  {log}")
            return bank_kp, False
    except Exception as e:
        print(f"[FUZZER] ❌ Bank init exception: {str(e)[:300]}")
        return bank_kp, False


async def send_ix(disc, amount, bank_pub, payer, program_id, client):
    from solders.instruction import Instruction, AccountMeta
    from solders.message import MessageV0
    from solders.transaction import VersionedTransaction

    data = disc + struct.pack("<Q", amount % (2**64))
    ix   = Instruction(
        program_id, data,
        [
            AccountMeta(bank_pub,       False, True),
            AccountMeta(payer.pubkey(), True,  True),
        ]
    )
    try:
        bh  = (await client.get_latest_blockhash()).value.blockhash
        from solders.message import Message
        msg = Message.new_with_blockhash([ix], payer.pubkey(), bh)
        tx  = VersionedTransaction(msg, [payer])

        sig = await client.send_transaction(tx)
        await asyncio.sleep(0.5)

        conf = await client.get_transaction(sig.value, max_supported_transaction_version=0)
        if conf.value:
            err = conf.value.transaction.meta.err
            if err:
                logs = conf.value.transaction.meta.log_messages or []
                err_log = next((l for l in reversed(logs)
                                if "Error" in l or "error" in l), str(err))
                return {"success": False, "error": err_log[:300]}
        return {"success": True, "error": None}
    except Exception as e:
        msg = str(e)
        # send_transaction raises on preflight failure — that counts as rejection
        return {"success": False, "error": msg[:300]}


async def fuzz_async(cases, program_id_str):
    from solana.rpc.async_api import AsyncClient
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solana.rpc.commitment import Confirmed

    with open(FUZZ_KEYPAIR) as f:
        secret = json.load(f)
    payer      = Keypair.from_bytes(bytes(secret))
    program_id = Pubkey.from_string(program_id_str)
    client     = AsyncClient(RPC_URL, commitment=Confirmed)
    results    = []

    try:
        bal = await client.get_balance(payer.pubkey())
        print(f"[FUZZER] Payer balance: {bal.value / 1e9:.2f} SOL")
        if bal.value == 0:
            print("[FUZZER] ❌ Payer has 0 SOL")
            return results

        # Verify program is visible to SDK before proceeding
        prog_info = await client.get_account_info(program_id)
        if not prog_info.value or not prog_info.value.executable:
            print(f"[FUZZER] ❌ Program not visible to SDK: {program_id_str[:20]}...")
            return results
        print(f"[FUZZER] ✅ Program visible to SDK (executable={prog_info.value.executable})")

        bank_kp, ok = await setup_bank(payer, program_id, client)
        if not ok:
            return results

        bank_pub = bank_kp.pubkey()
        print(f"[FUZZER] Running {len(cases)} cases...\n")

        for case in cases:
            r       = await send_ix(case["disc"], case["amount"],
                                    bank_pub, payer, program_id, client)
            success = r["success"]
            finding = None

            if success and case["expect_fail"]:
                finding = {
                    "type":     "vulnerability_confirmed",
                    "severity": "critical",
                    "description": (f"VULNERABLE: '{case['name']}' accepted "
                                    f"dangerous input (amount={case['amount']})")
                }
            elif not success and not case["expect_fail"]:
                finding = {
                    "type":     "unexpected_rejection",
                    "severity": "low",
                    "description": f"'{case['name']}' rejected: {(r.get('error') or '')[:120]}"
                }

            results.append({
                "case": case["name"], "description": case["description"],
                "amount": case["amount"], "success": success,
                "expect_fail": case["expect_fail"],
                "error": r.get("error"), "finding": finding,
            })

            if finding and finding["severity"] == "critical":
                print(f"  🔴 [CRITICAL] {finding['description']}")
            elif finding:
                print(f"  🟡 [LOW]      {finding['description'][:80]}")
            else:
                print(f"  {'✅' if success else '❌'} {case['name']} (amount={case['amount']})")

    finally:
        await client.close()

    return results


def generate_cases():
    return [
        {"name": "normal_deposit",  "disc": DEPOSIT_DISC,  "amount": 100,
         "expect_fail": False, "description": "Normal deposit 100"},
        {"name": "overflow_max",    "disc": DEPOSIT_DISC,  "amount": 2**64-1,
         "expect_fail": True,  "description": "Deposit u64::MAX — overflow"},
        {"name": "withdraw_100",    "disc": WITHDRAW_DISC, "amount": 100,
         "expect_fail": False, "description": "Withdraw 100"},
        {"name": "underflow",       "disc": WITHDRAW_DISC, "amount": 999_999_999_999,
         "expect_fail": True,  "description": "Withdraw more than balance — underflow"},
        {"name": "zero_deposit",    "disc": DEPOSIT_DISC,  "amount": 0,
         "expect_fail": False, "description": "Deposit zero"},
        {"name": "withdraw_zero",   "disc": WITHDRAW_DISC, "amount": 0,
         "expect_fail": False, "description": "Withdraw zero"},
        {"name": "deposit_500",     "disc": DEPOSIT_DISC,  "amount": 500,
         "expect_fail": False, "description": "Deposit 500"},
        {"name": "withdraw_all",    "disc": WITHDRAW_DISC, "amount": 1000,
         "expect_fail": False, "description": "Withdraw all"},
    ] + [
        {"name": f"random_{i}",
         "disc": random.choice([DEPOSIT_DISC, WITHDRAW_DISC]),
         "amount": random.randint(1, 200),
         "expect_fail": False, "description": "Random small amount"}
        for i in range(5)
    ]


def run_fuzzing(contract_code: str) -> dict:
    output = {
        "total_cases": 0, "passed": 0, "failed": 0,
        "findings": [], "cases": [], "error": None
    }

    proc = start_validator()
    if not proc:
        output["error"] = "Validator failed to start"
        return output

    try:
        pubkey = setup_fuzz_keypair()
        if not pubkey:
            output["error"] = "Keypair funding failed"
            return output

        program_id = deploy()
        if not program_id:
            output["error"] = "Deploy failed"
            return output

        # Wait for program to be confirmed
        for attempt in range(15):
            time.sleep(2)
            r = subprocess.run(
                ["solana", "program", "show", program_id, "--url", RPC_URL],
                capture_output=True, text=True
            )
            if r.returncode == 0 and "Program Id" in r.stdout:
                print(f"[FUZZER] ✅ Program confirmed on-chain (attempt {attempt+1})")
                break
            print(f"[FUZZER]   program check {attempt+1}: waiting...")
        else:
            output["error"] = "Program never confirmed"
            return output

        cases = generate_cases()
        output["total_cases"] = len(cases)
        results = asyncio.run(fuzz_async(cases, program_id))

        for r in results:
            if r["success"]:  output["passed"] += 1
            else:              output["failed"] += 1
            if r["finding"]:  output["findings"].append(r["finding"])
        output["cases"] = results

    except Exception as e:
        output["error"] = str(e)
        print(f"[FUZZER] ❌ Error: {e}")
    finally:
        stop_validator(proc)

    log_path = write_log("fuzzer", output)
    criticals = [f for f in output["findings"] if f.get("severity") == "critical"]
    print(f"\n[FUZZER] Log → {log_path}")
    print(f"\n{'='*50}")
    print(f"Total: {output['total_cases']}  Passed: {output['passed']}  "
          f"Failed: {output['failed']}  Critical: {len(criticals)}")
    if criticals:
        print("\n🔴 CRITICAL FINDINGS:")
        for f in criticals:
            print(f"  {f['description']}")
    print('='*50)
    return output

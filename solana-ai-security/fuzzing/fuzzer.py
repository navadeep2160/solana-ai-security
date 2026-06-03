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


# ─────────────────────────────────────────────
# INFRASTRUCTURE (unchanged from working base)
# ─────────────────────────────────────────────

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
            print("[FUZZER] ✅ Validator ready")
            return proc
        if proc.poll() is not None:
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


# ─────────────────────────────────────────────
# CORE TRANSACTION PRIMITIVES
# ─────────────────────────────────────────────

async def setup_bank(payer, program_id, client):
    from solders.keypair import Keypair
    from solders.instruction import Instruction, AccountMeta
    from solders.message import Message
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
    msg = Message.new_with_blockhash([init_ix], payer.pubkey(), bh)
    tx  = VersionedTransaction(msg, [payer, bank_kp])
    try:
        sig  = await client.send_transaction(tx)
        await asyncio.sleep(3)
        conf = await client.get_transaction(
            sig.value, max_supported_transaction_version=0
        )
        if conf.value and not conf.value.transaction.meta.err:
            print(f"[FUZZER] ✅ Bank initialized: {bank_kp.pubkey()}")
            return bank_kp, True
        err = conf.value.transaction.meta.err if conf.value else "not found"
        print(f"[FUZZER] ❌ Bank init failed: {err}")
        return bank_kp, False
    except Exception as e:
        print(f"[FUZZER] ❌ Bank init exception: {str(e)[:200]}")
        return bank_kp, False


async def send_raw_ix(
    disc, amount, bank_pub, payer, program_id, client,
    signers=None,           # list of Keypair — who actually signs
    account_metas=None,     # override account list for permutation fuzzing
):
    """
    Core instruction sender.
    signers       — defaults to [payer], override for signer permutation
    account_metas — defaults to standard layout, override for account permutation
    """
    from solders.keypair import Keypair
    from solders.instruction import Instruction, AccountMeta
    from solders.message import Message
    from solders.transaction import VersionedTransaction

    data = disc + struct.pack("<Q", amount % (2**64))

    if account_metas is None:
        account_metas = [
            AccountMeta(bank_pub,       False, True),
            AccountMeta(payer.pubkey(), True,  True),
        ]

    if signers is None:
        signers = [payer]

    ix = Instruction(program_id, data, account_metas)

    try:
        bh  = (await client.get_latest_blockhash()).value.blockhash
        msg = Message.new_with_blockhash([ix], signers[0].pubkey(), bh)
        tx  = VersionedTransaction(msg, signers)
        sig = await client.send_transaction(tx)
        await asyncio.sleep(0.5)
        conf = await client.get_transaction(
            sig.value, max_supported_transaction_version=0
        )
        if conf.value:
            err = conf.value.transaction.meta.err
            if err:
                logs = conf.value.transaction.meta.log_messages or []
                err_log = next(
                    (l for l in reversed(logs) if "Error" in l or "error" in l),
                    str(err)
                )
                return {"success": False, "error": err_log[:300]}
        return {"success": True, "error": None}
    except Exception as e:
        return {"success": False, "error": str(e)[:300]}


# ─────────────────────────────────────────────
# 1. BASIC AMOUNT CASES (existing, kept)
# ─────────────────────────────────────────────

def basic_cases():
    return [
        {"name": "normal_deposit",  "disc": DEPOSIT_DISC,  "amount": 100,
         "expect_fail": False, "description": "Normal deposit 100",
         "category": "basic"},
        {"name": "overflow_max",    "disc": DEPOSIT_DISC,  "amount": 2**64-1,
         "expect_fail": True,  "description": "Deposit u64::MAX — overflow",
         "category": "basic"},
        {"name": "withdraw_100",    "disc": WITHDRAW_DISC, "amount": 100,
         "expect_fail": False, "description": "Withdraw 100",
         "category": "basic"},
        {"name": "underflow",       "disc": WITHDRAW_DISC, "amount": 999_999_999_999,
         "expect_fail": True,  "description": "Withdraw more than balance",
         "category": "basic"},
        {"name": "zero_deposit",    "disc": DEPOSIT_DISC,  "amount": 0,
         "expect_fail": False, "description": "Deposit zero",
         "category": "basic"},
        {"name": "withdraw_zero",   "disc": WITHDRAW_DISC, "amount": 0,
         "expect_fail": False, "description": "Withdraw zero",
         "category": "basic"},
        {"name": "deposit_500",     "disc": DEPOSIT_DISC,  "amount": 500,
         "expect_fail": False, "description": "Deposit 500",
         "category": "basic"},
        {"name": "withdraw_all",    "disc": WITHDRAW_DISC, "amount": 1000,
         "expect_fail": False, "description": "Withdraw all",
         "category": "basic"},
    ] + [
        {"name": f"random_{i}",
         "disc": random.choice([DEPOSIT_DISC, WITHDRAW_DISC]),
         "amount": random.randint(1, 200),
         "expect_fail": False, "description": "Random small amount",
         "category": "basic"}
        for i in range(5)
    ]


# ─────────────────────────────────────────────
# 2. STATEFUL SEQUENCES (NEW)
# Each sequence runs multiple instructions in order
# and checks final state is correct
# ─────────────────────────────────────────────

STATEFUL_SEQUENCES = [
    {
        "name": "seq_deposit_withdraw_cycle",
        "description": "Deposit 200, withdraw 100, deposit 50, withdraw 150 — net=0",
        "category": "stateful",
        "steps": [
            {"disc": DEPOSIT_DISC,  "amount": 200, "expect_fail": False},
            {"disc": WITHDRAW_DISC, "amount": 100, "expect_fail": False},
            {"disc": DEPOSIT_DISC,  "amount": 50,  "expect_fail": False},
            {"disc": WITHDRAW_DISC, "amount": 150, "expect_fail": False},
        ],
        "expect_sequence_fail": False,
    },
    {
        "name": "seq_overflow_after_large_deposit",
        "description": "Deposit large amount then try overflow — should fail",
        "category": "stateful",
        "steps": [
            {"disc": DEPOSIT_DISC,  "amount": 2**32,    "expect_fail": False},
            {"disc": DEPOSIT_DISC,  "amount": 2**64 - 1, "expect_fail": True},
        ],
        "expect_sequence_fail": True,
    },
    {
        "name": "seq_drain_then_overdraw",
        "description": "Withdraw all then try to withdraw more — underflow check",
        "category": "stateful",
        "steps": [
            {"disc": WITHDRAW_DISC, "amount": 1000,          "expect_fail": False},
            {"disc": WITHDRAW_DISC, "amount": 1,             "expect_fail": True},
        ],
        "expect_sequence_fail": True,
    },
    {
        "name": "seq_rapid_small_deposits",
        "description": "50 small deposits of 1 — state accumulation test",
        "category": "stateful",
        "steps": [{"disc": DEPOSIT_DISC, "amount": 1, "expect_fail": False}] * 50,
        "expect_sequence_fail": False,
    },
    {
        "name": "seq_alternating_max",
        "description": "Alternate deposit/withdraw near boundary values",
        "category": "stateful",
        "steps": [
            {"disc": DEPOSIT_DISC,  "amount": 2**16, "expect_fail": False},
            {"disc": WITHDRAW_DISC, "amount": 2**16, "expect_fail": False},
            {"disc": DEPOSIT_DISC,  "amount": 2**32, "expect_fail": False},
            {"disc": WITHDRAW_DISC, "amount": 2**32, "expect_fail": False},
        ],
        "expect_sequence_fail": False,
    },
]


async def run_stateful_sequence(seq, bank_pub, payer, program_id, client):
    """Run a multi-step sequence and report per-step results."""
    step_results = []
    any_unexpected = False

    for i, step in enumerate(seq["steps"]):
        r = await send_raw_ix(
            step["disc"], step["amount"],
            bank_pub, payer, program_id, client
        )
        success = r["success"]
        expected = not step["expect_fail"]
        correct  = (success == expected)

        if not correct:
            any_unexpected = True

        step_results.append({
            "step": i + 1,
            "disc": "DEPOSIT" if step["disc"] == DEPOSIT_DISC else "WITHDRAW",
            "amount": step["amount"],
            "success": success,
            "expected_success": expected,
            "correct": correct,
            "error": r.get("error")
        })

        await asyncio.sleep(0.2)

    finding = None
    if any_unexpected:
        # Check if a dangerous sequence succeeded when it should have failed
        dangerous_succeeded = any(
            not s["correct"] and not s["expected_success"] and s["success"]
            for s in step_results
        )
        if dangerous_succeeded:
            finding = {
                "type": "stateful_vulnerability",
                "severity": "critical",
                "description": f"Sequence '{seq['name']}' — dangerous step accepted in stateful context"
            }
        else:
            finding = {
                "type": "stateful_unexpected",
                "severity": "low",
                "description": f"Sequence '{seq['name']}' — step behaved unexpectedly"
            }

    return {
        "case": seq["name"],
        "description": seq["description"],
        "category": "stateful",
        "steps": step_results,
        "any_unexpected": any_unexpected,
        "finding": finding
    }


# ─────────────────────────────────────────────
# 3. ACCOUNT PERMUTATION FUZZING (NEW)
# Pass wrong accounts in each slot — type cosplay,
# account substitution attacks
# ─────────────────────────────────────────────

async def run_account_permutations(bank_pub, payer, program_id, client):
    """
    Try passing wrong accounts in each position.
    Inspired by FuzzDelSol account permutation strategy.
    """
    from solders.keypair import Keypair
    from solders.instruction import AccountMeta
    from solders.pubkey import Pubkey

    results = []
    random_kp  = Keypair()   # unknown account
    random_pub = random_kp.pubkey()

    permutations = [
        {
            "name": "acct_perm_bank_as_user",
            "description": "Pass bank account in user slot — account confusion",
            "metas": [
                AccountMeta(bank_pub, False, True),   # bank (correct)
                AccountMeta(bank_pub, True,  True),   # bank again as user (wrong)
            ],
            "expect_fail": True
        },
        {
            "name": "acct_perm_random_as_bank",
            "description": "Pass random account as bank — should fail ownership",
            "metas": [
                AccountMeta(random_pub, False, True),  # random as bank (wrong)
                AccountMeta(payer.pubkey(), True, True),
            ],
            "expect_fail": True
        },
        {
            "name": "acct_perm_swap_bank_user",
            "description": "Swap bank and user positions completely",
            "metas": [
                AccountMeta(payer.pubkey(), False, True),  # payer as bank (wrong)
                AccountMeta(bank_pub,       True,  True),  # bank as user (wrong)
            ],
            "expect_fail": True
        },
        {
            "name": "acct_perm_duplicate_user",
            "description": "Pass same account twice — duplicate mutable account",
            "metas": [
                AccountMeta(payer.pubkey(), True, True),
                AccountMeta(payer.pubkey(), True, True),
            ],
            "expect_fail": True
        },
        {
            "name": "acct_perm_missing_user",
            "description": "Only pass bank, no user account",
            "metas": [
                AccountMeta(bank_pub, False, True),
            ],
            "expect_fail": True
        },
    ]

    for perm in permutations:
        r = await send_raw_ix(
            DEPOSIT_DISC, 100,
            bank_pub, payer, program_id, client,
            account_metas=perm["metas"]
        )
        success = r["success"]
        finding = None

        if success and perm["expect_fail"]:
            finding = {
                "type": "account_permutation_vulnerability",
                "severity": "critical",
                "description": f"VULNERABLE: '{perm['name']}' — wrong accounts accepted. {perm['description']}"
            }

        results.append({
            "case": perm["name"],
            "description": perm["description"],
            "category": "account_permutation",
            "success": success,
            "expect_fail": perm["expect_fail"],
            "error": r.get("error"),
            "finding": finding
        })

        icon = "🔴" if finding else ("✅" if not success else "❌")
        print(f"  {icon} {perm['name']}")
        await asyncio.sleep(0.2)

    return results


# ─────────────────────────────────────────────
# 4. SIGNER PERMUTATION FUZZING (NEW)
# Flip who signs — missing signer check detection
# ─────────────────────────────────────────────

async def run_signer_permutations(bank_pub, payer, program_id, client):
    """
    Systematically remove or swap signers.
    Detects missing signer check vulnerabilities.
    """
    from solders.keypair import Keypair
    from solders.instruction import AccountMeta

    results = []
    attacker_kp = Keypair()

    # Fund attacker with airdrop
    subprocess.run(
        ["solana", "airdrop", "10",
         str(attacker_kp.pubkey()), "--url", RPC_URL],
        capture_output=True
    )
    await asyncio.sleep(3)

    permutations = [
        {
            "name": "signer_perm_attacker_withdraws",
            "description": "Attacker (not owner) tries to withdraw — missing signer/owner check",
            "disc": WITHDRAW_DISC,
            "amount": 100,
            "signers": [attacker_kp],
            "metas": [
                AccountMeta(bank_pub,              False, True),
                AccountMeta(attacker_kp.pubkey(),  True,  True),
            ],
            "expect_fail": True,
            "vulnerability": "missing_owner_check"
        },
        {
            "name": "signer_perm_attacker_deposits",
            "description": "Attacker deposits to someone else's bank",
            "disc": DEPOSIT_DISC,
            "amount": 50,
            "signers": [attacker_kp],
            "metas": [
                AccountMeta(bank_pub,              False, True),
                AccountMeta(attacker_kp.pubkey(),  True,  True),
            ],
            "expect_fail": False,   # deposit may be allowed by any signer
            "vulnerability": None
        },
        {
            "name": "signer_perm_no_signer_withdraw",
            "description": "Send withdraw with bank not marked writable",
            "disc": WITHDRAW_DISC,
            "amount": 50,
            "signers": [payer],
            "metas": [
                AccountMeta(bank_pub,       False, False),  # not writable
                AccountMeta(payer.pubkey(), True,  True),
            ],
            "expect_fail": True,
            "vulnerability": None
        },
        {
            "name": "signer_perm_attacker_close_account",
            "description": "Attacker tries to close_account — missing authority check",
            "disc": bytes([125, 255, 149, 14, 110, 34, 72, 24]),  # close_account disc
            "amount": 0,
            "signers": [attacker_kp],
            "metas": [
                AccountMeta(bank_pub,              False, True),
                AccountMeta(attacker_kp.pubkey(),  True,  True),
            ],
            "expect_fail": True,
            "vulnerability": "missing_owner_check_close"
        },
    ]

    for perm in permutations:
        r = await send_raw_ix(
            perm["disc"], perm["amount"],
            bank_pub, payer, program_id, client,
            signers=perm["signers"],
            account_metas=perm["metas"]
        )
        success = r["success"]
        finding = None

        if success and perm["expect_fail"] and perm["vulnerability"]:
            finding = {
                "type": "signer_permutation_vulnerability",
                "severity": "critical",
                "description": (
                    f"VULNERABLE: '{perm['name']}' — "
                    f"{perm['description']} — "
                    f"vulnerability: {perm['vulnerability']}"
                )
            }

        results.append({
            "case": perm["name"],
            "description": perm["description"],
            "category": "signer_permutation",
            "success": success,
            "expect_fail": perm["expect_fail"],
            "error": r.get("error"),
            "finding": finding
        })

        icon = "🔴" if finding else ("✅" if not success else "❌")
        print(f"  {icon} {perm['name']}")
        await asyncio.sleep(0.2)

    return results


# ─────────────────────────────────────────────
# 5. PDA FUZZING (NEW)
# Test wrong PDAs, non-canonical bumps,
# seeds from different programs
# ─────────────────────────────────────────────

async def run_pda_fuzzing(bank_pub, payer, program_id, client):
    """
    Derive wrong PDAs and try to use them as the bank account.
    Detects PDA sharing, bump seed, and seed collision issues.
    """
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solders.instruction import AccountMeta

    results = []

    # Derive some fake PDAs
    fake_pdas = []
    seed_sets = [
        [b"bank"],
        [b"vault"],
        [b"bank", payer.pubkey().__bytes__()],
        [b"profile"],
        [b"bank", b"wrong"],
    ]

    for seeds in seed_sets:
        try:
            pda, bump = Pubkey.find_program_address(seeds, program_id)
            fake_pdas.append({
                "pubkey": pda,
                "seeds": [s.decode(errors="replace") for s in seeds],
                "bump": bump
            })
        except Exception:
            pass

    for i, pda_info in enumerate(fake_pdas):
        pda_pub = pda_info["pubkey"]
        name    = f"pda_fuzz_{i}_seeds={'_'.join(pda_info['seeds'])}"

        r = await send_raw_ix(
            DEPOSIT_DISC, 50,
            pda_pub, payer, program_id, client,
            account_metas=[
                AccountMeta(pda_pub,        False, True),
                AccountMeta(payer.pubkey(), True,  True),
            ]
        )
        success = r["success"]
        finding = None

        if success:
            finding = {
                "type": "pda_vulnerability",
                "severity": "high",
                "description": (
                    f"PDA accepted with seeds {pda_info['seeds']} — "
                    f"possible PDA sharing or seed collision"
                )
            }

        results.append({
            "case": name,
            "description": f"PDA with seeds {pda_info['seeds']}",
            "category": "pda_fuzzing",
            "pda": str(pda_pub),
            "seeds": pda_info["seeds"],
            "success": success,
            "expect_fail": True,
            "error": r.get("error"),
            "finding": finding
        })

        icon = "🔴" if finding else "✅"
        print(f"  {icon} {name[:60]}")
        await asyncio.sleep(0.2)

    return results


# ─────────────────────────────────────────────
# MAIN FUZZ ORCHESTRATOR
# ─────────────────────────────────────────────

async def fuzz_async(program_id_str):
    from solana.rpc.async_api import AsyncClient
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solana.rpc.commitment import Confirmed

    with open(FUZZ_KEYPAIR) as f:
        secret = json.load(f)
    payer      = Keypair.from_bytes(bytes(secret))
    program_id = Pubkey.from_string(program_id_str)
    client     = AsyncClient(RPC_URL, commitment=Confirmed)

    all_results  = []
    all_findings = []

    try:
        bal = await client.get_balance(payer.pubkey())
        print(f"[FUZZER] Payer balance: {bal.value / 1e9:.2f} SOL")

        prog_info = await client.get_account_info(program_id)
        if not prog_info.value or not prog_info.value.executable:
            print("[FUZZER] ❌ Program not visible")
            return all_results, all_findings

        print(f"[FUZZER] ✅ Program visible to SDK (executable=True)")

        bank_kp, ok = await setup_bank(payer, program_id, client)
        if not ok:
            return all_results, all_findings

        bank_pub = bank_kp.pubkey()

        # ── 1. BASIC AMOUNT CASES ──
        print(f"\n[FUZZER] ── Phase 1: Basic Amount Cases ──")
        cases = basic_cases()
        for case in cases:
            r       = await send_raw_ix(
                case["disc"], case["amount"],
                bank_pub, payer, program_id, client
            )
            success = r["success"]
            finding = None

            if success and case["expect_fail"]:
                finding = {
                    "type": "vulnerability_confirmed", "severity": "critical",
                    "description": f"VULNERABLE: '{case['name']}' accepted dangerous input (amount={case['amount']})"
                }
            elif not success and not case["expect_fail"]:
                finding = {
                    "type": "unexpected_rejection", "severity": "low",
                    "description": f"'{case['name']}' rejected: {(r.get('error') or '')[:120]}"
                }

            result = {
                "case": case["name"], "description": case["description"],
                "category": case["category"], "amount": case["amount"],
                "success": success, "expect_fail": case["expect_fail"],
                "error": r.get("error"), "finding": finding
            }
            all_results.append(result)
            if finding:
                all_findings.append(finding)

            icon = "🔴" if (finding and finding["severity"]=="critical") else \
                   "🟡" if finding else ("✅" if success else "❌")
            print(f"  {icon} {case['name']} (amount={case['amount']})")
            await asyncio.sleep(0.1)

        # ── 2. STATEFUL SEQUENCES ──
        print(f"\n[FUZZER] ── Phase 2: Stateful Sequences ──")
        for seq in STATEFUL_SEQUENCES:
            # Fresh bank for each sequence to isolate state
            seq_bank_kp, seq_ok = await setup_bank(payer, program_id, client)
            if not seq_ok:
                continue
            result = await run_stateful_sequence(
                seq, seq_bank_kp.pubkey(), payer, program_id, client
            )
            all_results.append(result)
            if result["finding"]:
                all_findings.append(result["finding"])
            icon = "🔴" if (result["finding"] and result["finding"]["severity"]=="critical") else \
                   "🟡" if result["finding"] else "✅"
            passed = sum(1 for s in result["steps"] if s["correct"])
            total  = len(result["steps"])
            print(f"  {icon} {seq['name']} ({passed}/{total} steps correct)")

        # ── 3. ACCOUNT PERMUTATIONS ──
        print(f"\n[FUZZER] ── Phase 3: Account Permutations ──")
        acct_results = await run_account_permutations(
            bank_pub, payer, program_id, client
        )
        all_results.extend(acct_results)
        for r in acct_results:
            if r["finding"]:
                all_findings.append(r["finding"])

        # ── 4. SIGNER PERMUTATIONS ──
        print(f"\n[FUZZER] ── Phase 4: Signer Permutations ──")
        signer_results = await run_signer_permutations(
            bank_pub, payer, program_id, client
        )
        all_results.extend(signer_results)
        for r in signer_results:
            if r["finding"]:
                all_findings.append(r["finding"])

        # ── 5. PDA FUZZING ──
        print(f"\n[FUZZER] ── Phase 5: PDA Fuzzing ──")
        pda_results = await run_pda_fuzzing(
            bank_pub, payer, program_id, client
        )
        all_results.extend(pda_results)
        for r in pda_results:
            if r["finding"]:
                all_findings.append(r["finding"])

    finally:
        await client.close()

    return all_results, all_findings


def run_fuzzing(contract_code: str) -> dict:
    output = {
        "total_cases": 0, "passed": 0, "failed": 0,
        "findings": [], "cases": [],
        "categories": {}, "error": None
    }

    proc = start_validator()
    if not proc:
        output["error"] = "Validator failed"
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

        for attempt in range(15):
            time.sleep(2)
            r = subprocess.run(
                ["solana", "program", "show", program_id, "--url", RPC_URL],
                capture_output=True, text=True
            )
            if r.returncode == 0 and "Program Id" in r.stdout:
                print(f"[FUZZER] ✅ Program confirmed (attempt {attempt+1})")
                break
            print(f"[FUZZER]   program check {attempt+1}: waiting...")
        else:
            output["error"] = "Program never confirmed"
            return output

        all_results, all_findings = asyncio.run(fuzz_async(program_id))

        # Aggregate by category
        categories = {}
        for r in all_results:
            cat = r.get("category", "basic")
            if cat not in categories:
                categories[cat] = {"total": 0, "passed": 0, "failed": 0, "findings": 0}
            categories[cat]["total"] += 1
            # For stateful, count steps
            if cat == "stateful":
                steps = r.get("steps", [])
                categories[cat]["passed"] += sum(1 for s in steps if s.get("correct"))
                categories[cat]["failed"] += sum(1 for s in steps if not s.get("correct"))
            else:
                if r.get("success"):
                    categories[cat]["passed"] += 1
                else:
                    categories[cat]["failed"] += 1
            if r.get("finding"):
                categories[cat]["findings"] += 1

        output["cases"]      = all_results
        output["findings"]   = all_findings
        output["categories"] = categories
        output["total_cases"] = len(all_results)
        output["passed"] = sum(
            1 for r in all_results
            if r.get("success") and r.get("category") != "stateful"
        )
        output["failed"] = sum(
            1 for r in all_results
            if not r.get("success") and r.get("category") != "stateful"
        )

    except Exception as e:
        output["error"] = str(e)
        print(f"[FUZZER] ❌ Error: {e}")
    finally:
        stop_validator(proc)

    log_path   = write_log("fuzzer", output)
    criticals  = [f for f in all_findings if f.get("severity") == "critical"]

    print(f"\n[FUZZER] Log → {log_path}")
    print(f"\n{'='*60}")
    print(f"FUZZER RESULTS SUMMARY")
    print(f"{'='*60}")
    for cat, stats in output["categories"].items():
        print(f"  {cat:30s} total={stats['total']:3d}  findings={stats['findings']}")
    print(f"{'─'*60}")
    print(f"  Total results: {output['total_cases']}")
    print(f"  Critical findings: {len(criticals)}")
    if criticals:
        print("\n🔴 CRITICAL FINDINGS:")
        for f in criticals:
            print(f"  → {f['description']}")
    print('='*60)
    return output

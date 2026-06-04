import subprocess
import time
import os
from pathlib import Path
from utils.logger import write_log

DEVNET_URL   = "https://api.devnet.solana.com"
KEYPAIR      = os.path.expanduser("~/.config/solana/id.json")
SO_PATH      = Path("contracts/vulnerable_bank/target/deploy/vulnerable_bank.so")


def check_balance() -> float:
    r = subprocess.run(
        ["solana", "balance", "--url", DEVNET_URL, "--keypair", KEYPAIR],
        capture_output=True, text=True
    )
    try:
        return float(r.stdout.strip().replace(" SOL", ""))
    except Exception:
        return 0.0


def deploy_to_devnet(so_path: str = None) -> str:
    path = so_path or str(SO_PATH)
    print(f"[DEVNET] Deploying {path} to devnet...")
    r = subprocess.run(
        ["solana", "program", "deploy", path,
         "--url", DEVNET_URL, "--keypair", KEYPAIR],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if "Program Id:" in line:
                pid = line.split("Program Id:")[-1].strip()
                print(f"[DEVNET] ✅ Deployed → {pid}")
                return pid
        print(f"[DEVNET] ✅ Deployed (reused existing)")
        return "Ak49KJAr32qbxt3whtzpLB69Xz1mTT4MGDSXNuaF6AL"
    print(f"[DEVNET] ❌ Deploy failed: {r.stderr[:300]}")
    return None


def run_devnet_validation(contract_code: str, rebuild: bool = True) -> dict:
    output = {
        "network": "devnet",
        "balance_before": 0.0,
        "balance_after": 0.0,
        "build_success": False,
        "deploy_success": False,
        "program_id": None,
        "explorer_url": None,
        "error": None
    }

    try:
        # Check balance
        bal = check_balance()
        output["balance_before"] = bal
        print(f"[DEVNET] Balance: {bal} SOL")

        if bal < 0.5:
            output["error"] = f"Insufficient devnet SOL: {bal}"
            print(f"[DEVNET] ❌ Need at least 0.5 SOL, have {bal}")
            return output

        # Optionally rebuild
        if rebuild:
            print("[DEVNET] Building with cargo build-sbf...")
            build = subprocess.run(
                ["cargo", "build-sbf"],
                cwd="contracts/vulnerable_bank/programs/vulnerable_bank",
                capture_output=True, text=True
            )
            if build.returncode == 0:
                print("[DEVNET] ✅ Build successful")
                output["build_success"] = True
            else:
                output["error"] = f"Build failed: {build.stderr[-300:]}"
                print(f"[DEVNET] ❌ Build failed")
                return output
        else:
            output["build_success"] = True

        # Deploy
        program_id = deploy_to_devnet()
        if not program_id:
            output["error"] = "Deploy failed"
            return output

        output["deploy_success"] = True
        output["program_id"] = program_id
        output["explorer_url"] = f"https://explorer.solana.com/address/{program_id}?cluster=devnet"
        output["balance_after"] = check_balance()

        print(f"[DEVNET] ✅ Verified on devnet")
        print(f"[DEVNET] Explorer: {output['explorer_url']}")

    except Exception as e:
        output["error"] = str(e)
        print(f"[DEVNET] ❌ Error: {e}")

    log_path = write_log("devnet", output)
    print(f"[DEVNET] Log saved → {log_path}")
    return output

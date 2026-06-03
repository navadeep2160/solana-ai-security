import subprocess
from pathlib import Path
from utils.logger import write_log

PROJECT_DIR = Path("contracts/vulnerable_bank/programs/vulnerable_bank")
CONTRACT_PATH = PROJECT_DIR / "src/lib.rs"


def validate_contract(contract_code: str) -> dict:
    print("[VALIDATOR] Writing contract to disk...")
    CONTRACT_PATH.write_text(contract_code)

    print("[VALIDATOR] Running cargo check...")
    result = subprocess.run(
        ["cargo", "check"],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True
    )

    success = result.returncode == 0

    output = {
        "success": success,
        "stdout": result.stdout[-3000:],
        "stderr": result.stderr[-3000:]
    }

    log_path = write_log("validator", output)
    print(f"[VALIDATOR] Log saved → {log_path}")

    if success:
        print("[VALIDATOR] ✅ cargo check passed")
    else:
        print("[VALIDATOR] ❌ cargo check failed")

    return output

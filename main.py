import time
import json
from google.api_core.exceptions import ResourceExhausted

from agents.scanner.scanner_agent import scan_contract
from agents.patcher.patch_agent import patch_contract
from agents.validator.validator_agent import validate_contract
from utils.file_writer import save_patched_contract, save_final_report

MAX_ITER = 3
CONTRACT_PATH = (
    "contracts/vulnerable_bank/"
    "programs/vulnerable_bank/src/lib.rs"
)


def call_with_retry(fn, *args, **kwargs):
    while True:
        try:
            return fn(*args, **kwargs)
        except ResourceExhausted:
            print("\n⏳ Rate limited — waiting 65s before retry...\n")
            time.sleep(65)


def main():
    print("\n🚀 SOLANA AI SECURITY PIPELINE STARTED\n")

    with open(CONTRACT_PATH, "r") as f:
        contract = f.read()

    errors = ""
    validation = {}
    scan_result = {}

    for iteration in range(MAX_ITER):
        print(f"\n========== ITERATION {iteration + 1} / {MAX_ITER} ==========\n")

        # SCAN
        scan_result = call_with_retry(scan_contract, contract)
        risks = scan_result.get("risks", [])
        print(f"[MAIN] Risks found: {len(risks)}")
        for r in risks:
            print(f"  → [{r.get('severity','?').upper()}] {r.get('type','?')}: {r.get('reason','?')}")

        # PATCH
        contract = call_with_retry(patch_contract, contract, errors)

        # VALIDATE
        validation = validate_contract(contract)

        if validation["success"]:
            print("\n✅ CONTRACT COMPILED SUCCESSFULLY\n")
            break

        print("\n❌ BUILD FAILED — feeding errors back to patcher\n")
        errors = validation["stderr"][-1200:]

        if iteration < MAX_ITER - 1:
            print("⏳ Waiting 15s before next iteration...\n")
            time.sleep(15)

    else:
        print(f"\n⚠️  Max iterations ({MAX_ITER}) reached\n")

    # SAVE OUTPUTS
    save_patched_contract(contract)
    save_final_report(scan_result, contract, iteration + 1, validation.get("success", False))

    print("\n========== FINAL RESULT ==========")
    print(json.dumps({
        "success": validation.get("success", False),
        "iterations": iteration + 1,
        "vulnerabilities_found": len(scan_result.get("risks", [])),
        "report": "outputs/reports/final_report.json",
        "patched": "outputs/patched/patched_contract.rs"
    }, indent=2))
    print("\n🏁 PIPELINE COMPLETED\n")


if __name__ == "__main__":
    main()

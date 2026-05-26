import time
import json
import shutil
from pathlib import Path
from google.api_core.exceptions import ResourceExhausted

from agents.scanner.scanner_agent import scan_contract
from agents.patcher.patch_agent import patch_contract
from agents.validator.validator_agent import validate_contract
from analysis.static_checks.checks import run_all_checks
from utils.file_writer import save_patched_contract, save_final_report

MAX_ITER = 3
CONTRACT_PATH = Path(
    "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs"
)
ORIGINAL_PATH = Path(
    "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib_original.rs"
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

    # Always restore original vulnerable contract before scanning
    if ORIGINAL_PATH.exists():
        shutil.copy(ORIGINAL_PATH, CONTRACT_PATH)
        print("[MAIN] Restored original vulnerable contract\n")

    with open(CONTRACT_PATH, "r") as f:
        contract = f.read()

    # Run static checks first — deterministic, no AI needed
    print("[MAIN] Running static checks...")
    static_findings = run_all_checks(contract)
    print(f"[MAIN] Static findings: {len(static_findings)}")
    for f in static_findings:
        print(f"  → [{f['severity'].upper()}] {f['type']}: {f['description']}")

    errors = ""
    validation = {}
    scan_result = {}

    for iteration in range(MAX_ITER):
        print(f"\n========== ITERATION {iteration + 1} / {MAX_ITER} ==========\n")

        # SCAN
        scan_result = call_with_retry(scan_contract, contract)
        risks = scan_result.get("risks", [])
        print(f"[MAIN] AI risks found: {len(risks)}")
        for r in risks:
            print(f"  → [{r.get('severity','?').upper()}] {r.get('type','?')}: {r.get('reason','?')}")

        # Merge static findings into scan result for patcher context
        all_findings = risks + [
            {"type": s["type"], "severity": s["severity"], "reason": s["description"]}
            for s in static_findings
        ]
        scan_result["risks"] = all_findings

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

    # Save outputs
    save_patched_contract(contract)
    save_final_report(scan_result, contract, iteration + 1, validation.get("success", False))

    print("\n========== FINAL RESULT ==========")
    print(json.dumps({
        "success": validation.get("success", False),
        "iterations": iteration + 1,
        "static_findings": len(static_findings),
        "ai_findings": len(risks),
        "total_findings": len(scan_result.get("risks", [])),
        "report": "outputs/reports/final_report.json",
        "patched": "outputs/patched/patched_contract.rs"
    }, indent=2))
    print("\n🏁 PIPELINE COMPLETED\n")


if __name__ == "__main__":
    main()

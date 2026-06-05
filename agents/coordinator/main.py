import time
import json
import shutil
from pathlib import Path
from google.api_core.exceptions import ResourceExhausted

from agents.scanner.scanner_agent import scan_contract
from agents.patcher.patch_agent import patch_contract
from agents.validator.validator_agent import validate_contract
from analysis.static_checks.checks import run_all_checks
from analysis.ast_parser.rust_ast_parser import parse_rust_ast, format_ast_findings
from analysis.ast_parser.cfg_builder import analyze_cfg
from runtime_validator.checker import run_runtime_validation
from agents.exploit.exploit_agent import run_exploit_agent
from agents.scorer.scoring_engine import run_scoring as score_exploit_results
from utils.file_writer import save_patched_contract, save_final_report

MAX_ITER = 3
CONTRACT_PATH = Path(
    "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs"
)
ORIGINAL_PATH = Path(
    "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib_original.rs"
)


def call_with_retry(fn, *args, max_retries=5, **kwargs):
    for attempt in range(max_retries):
        try:
            return fn(*args, **kwargs)
        except ResourceExhausted:
            wait = 65 * (attempt + 1)
            print(f"\n⏳ Rate limited (attempt {attempt+1}/{max_retries}) — waiting {wait}s...\n")
            time.sleep(wait)
    print("\n❌ Max retries reached — skipping this step\n")
    return None


def main():
    print("\n🚀 SOLANA AI SECURITY PIPELINE STARTED\n")

    if ORIGINAL_PATH.exists():
        shutil.copy(ORIGINAL_PATH, CONTRACT_PATH)
        print("[MAIN] Restored original vulnerable contract\n")

    with open(CONTRACT_PATH, "r") as f:
        original_contract = f.read()

    # ── PHASE 1: STATIC ANALYSIS ──────────────────────────────
    print("=" * 50)
    print("PHASE 1: STATIC ANALYSIS")
    print("=" * 50)

    print("\n[MAIN] Running regex static checks...")
    static_findings = run_all_checks(original_contract)
    print(f"[MAIN] Static findings: {len(static_findings)}")
    for f in static_findings:
        print(f"  → [{f['severity'].upper()}] {f['type']}: {f['description']}")

    print("\n[MAIN] Running AST parser...")
    ast_result = parse_rust_ast(original_contract)
    print(format_ast_findings(ast_result))
    ast_findings = [
        {
            "type": f["type"],
            "severity": f["severity"],
            "reason": f"{f['description']} (at {f['location']})",
            "line": f.get("line", 0),
            "source": "ast"
        }
        for f in ast_result.findings
    ]

    print("\n[MAIN] Running CFG analysis...")
    cfg_result = analyze_cfg(original_contract)
    print(cfg_result["summary"])
    cfg_findings = [
        {
            "type": f["type"],
            "severity": f["severity"],
            "reason": f["description"],
            "line": f.get("line", 0),
            "source": "cfg"
        }
        for f in cfg_result["findings"]
    ]
    print(f"[MAIN] CFG findings: {len(cfg_findings)}")
    for finding in cfg_findings:
        sev   = finding.get("severity", "?").upper()
        ftype = finding.get("type", "")
        desc  = finding.get("description", ftype)
        line  = finding.get("line", "")
        desc  = f"{desc} (line {line})" if line else desc
        print(f"  → [{sev}] {desc}")

    # ── PHASE 2: AI SCAN ──────────────────────────────────────
    print("\n" + "=" * 50)
    print("PHASE 2: AI SCAN")
    print("=" * 50)

    scan_result = call_with_retry(scan_contract, original_contract)
    ai_risks = scan_result.get("risks", [])
    print(f"[MAIN] AI findings: {len(ai_risks)}")
    for r in ai_risks:
        print(f"  → [{r.get('severity','?').upper()}] {r.get('type','?')}: {r.get('reason','?')}")

    all_findings = (
        ai_risks
        + [{"type": s["type"], "severity": s["severity"],
            "reason": s["description"], "source": "static"}
           for s in static_findings]
        + ast_findings
        + cfg_findings
    )
    scan_result["risks"]       = all_findings
    scan_result["ast_summary"] = format_ast_findings(ast_result)
    scan_result["cfg_summary"] = cfg_result["summary"]

    print(f"\n[MAIN] Total findings: {len(all_findings)}")
    print(f"  AI: {len(ai_risks)}  Static: {len(static_findings)}  "
          f"AST: {len(ast_findings)}  CFG: {len(cfg_findings)}")

    # ── PHASE 3: PATCH + VALIDATE LOOP ───────────────────────
    print("\n" + "=" * 50)
    print("PHASE 3: PATCH + VALIDATE")
    print("=" * 50)

    contract   = original_contract
    errors     = ""
    validation = {}

    for iteration in range(MAX_ITER):
        print(f"\n--- Patch Iteration {iteration + 1} / {MAX_ITER} ---\n")

        patched = call_with_retry(patch_contract, contract, errors)
        if patched is None:
            print("[MAIN] ⚠️  Patcher returned None — skipping validation")
            continue
        contract   = patched
        validation = validate_contract(contract)
        if validation is None:
            print("[MAIN] ⚠️  Validator returned None")
            continue

        if validation["success"]:
            print("\n✅ CONTRACT COMPILED SUCCESSFULLY\n")
            break

        print("\n❌ BUILD FAILED — feeding errors back to patcher\n")
        errors = validation["stderr"][-1200:]

        if iteration < MAX_ITER - 1:
            print("⏳ Waiting 15s...\n")
            time.sleep(15)
    else:
        print(f"\n⚠️  Max iterations ({MAX_ITER}) reached\n")

    # ── PHASE 4: RUNTIME VALIDATION ──────────────────────────
    runtime_result = {}
    if validation.get("success"):
        print("\n" + "=" * 50)
        print("PHASE 4: RUNTIME VALIDATION")
        print("=" * 50)
        runtime_result = run_runtime_validation(contract)
        if runtime_result.get("deploy_success"):
            print("[MAIN] ✅ Contract verified on local Solana validator")
        else:
            print(f"[MAIN] ⚠️  Runtime validation: {runtime_result.get('error')}")

    # ── PHASE 5: EXPLOIT VALIDATION ──────────────────────────
    exploit_result = {}
    print("\n" + "=" * 50)
    print("PHASE 5: EXPLOIT VALIDATION")
    print("=" * 50)
    try:
        exploit_result = run_exploit_agent(findings=all_findings)
    except Exception as e:
        print(f"[MAIN] ⚠️  Exploit agent error: {e}")
        exploit_result = {"total": 0, "confirmed": 0,
                          "findings": [], "error_msg": str(e)}

    # ── PHASE 6: RISK SCORING ─────────────────────────────────
    score_result = {}
    print("\n" + "=" * 50)
    print("PHASE 6: RISK SCORING")
    print("=" * 50)
    try:
        score_result = score_exploit_results(all_findings, exploit_result)
    except Exception as e:
        print(f"[MAIN] ⚠️  Scorer error: {e}")
        score_result = {"total": 0, "findings": [], "error_msg": str(e)}

    # ── SAVE OUTPUTS ──────────────────────────────────────────
    save_patched_contract(contract)
    save_final_report(
        scan_result, contract,
        iteration + 1,
        validation.get("success", False)
    )

    # ── FINAL RESULT ──────────────────────────────────────────
    print("\n" + "=" * 50)
    print("FINAL RESULT")
    print("=" * 50)
    print(json.dumps({
        "success":          validation.get("success", False),
        "runtime_deployed": runtime_result.get("deploy_success", False),
        "iterations":       iteration + 1,
        "findings": {
            "static":  len(static_findings),
            "ast":     len(ast_findings),
            "cfg":     len(cfg_findings),
            "ai":      len(ai_risks),
            "total":   len(all_findings)
        },
        "exploit": {
            "total":        exploit_result.get("total", 0),
            "confirmed":    exploit_result.get("confirmed", 0),
            "false_positive": exploit_result.get("false_positive", 0),
        },
        "scoring": {
            "total":    score_result.get("total", 0),
            "critical": score_result.get("critical", 0),
            "high":     score_result.get("high", 0),
            "medium":   score_result.get("medium", 0),
            "low":      score_result.get("low", 0),
            "false_positives_removed": score_result.get(
                "false_positives_removed", 0),
        },
        "report":  "outputs/reports/final_report.json",
        "patched": "outputs/patched/patched_contract.rs"
    }, indent=2))
    print("\n🏁 PIPELINE COMPLETED\n")


if __name__ == "__main__":
    main()
import json
from pathlib import Path
from datetime import datetime


def save_patched_contract(code: str):
    path = Path("outputs/patched/patched_contract.rs")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)
    print(f"[FILE] Patched contract saved → {path}")
    return str(path)


def save_final_report(scan_result: dict, patched_code: str, iterations: int, success: bool):
    report = {
        "timestamp": datetime.now().isoformat(),
        "success": success,
        "iterations": iterations,
        "vulnerabilities_found": scan_result.get("risks", []),
        "total_vulnerabilities": len(scan_result.get("risks", [])),
        "patched_contract_path": "outputs/patched/patched_contract.rs",
        "status": "SECURED" if success else "FAILED"
    }
    path = Path("outputs/reports/final_report.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(f"[FILE] Final report saved → {path}")
    return str(path)

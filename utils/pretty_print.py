
def print_report(report: dict):
    print("\n" + "="*70)
    print("        SOLANA NETWORK SECURITY REPORT")
    print("="*70)

    print(f"Risk Score      : {report.get('risk_score', 'N/A')}/10")
    print(f"Summary         : {report.get('summary', '')}")

    print("\n--- VULNERABILITIES ---")

    for v in report.get("vulnerabilities", []):
        icon = "🔴" if v.get("severity") == "critical" else \
               "🟠" if v.get("severity") == "high" else \
               "🟡" if v.get("severity") == "medium" else "🟢"

        status = "DETECTED" if v.get("detected") else "SAFE"

        print(f"\n{icon} {v.get('type')} [{status}]")
        print(f"   Severity : {v.get('severity')}")
        print(f"   Evidence : {v.get('evidence','')}")
        print(f"   Reason   : {v.get('reason','')}")

    print("\n" + "="*70 + "\n")

"""
LangGraph Orchestrator — Week 4
Replaces sequential coordinator with a proper StateGraph.
All agents are nodes. All decisions are edges.
"""
import json
import os
import shutil
import time
from pathlib import Path
from typing import TypedDict, Annotated
import operator

from langgraph.graph import StateGraph, END, START
from utils.logger import write_log

CONTRACT_PATH = Path("contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs")
ORIGINAL_PATH = Path("contracts/vulnerable_bank/programs/vulnerable_bank/src/lib_original.rs")
MAX_PATCH_ITER = 3


# ── State ─────────────────────────────────────────────────────
class SecurityState(TypedDict):
    contract_code:      str
    contract_name:      str
    # Findings from each layer
    static_findings:    list
    ast_findings:       list
    cfg_findings:       list
    ai_findings:        list
    v3_findings:        list
    all_findings:       list
    # Exploit + scoring
    exploit_results:    dict
    score_results:      dict
    # Patch
    patched_contract:   str
    patch_errors:       str
    patch_iterations:   int
    patch_success:      bool
    patch_verified:     bool
    security_score:     float
    # New Week 4 agents
    invariants:         list
    taint_findings:     list
    reflection_score:   float
    reflection_notes:   str
    # Runtime
    runtime_deployed:   bool
    devnet_deployed:    bool
    network_results:    dict
    # Metrics
    tokens_used:        int
    errors:             list


# ── Node: Setup ───────────────────────────────────────────────
def setup_node(state: SecurityState) -> SecurityState:
    print("\n🚀 LANGGRAPH SECURITY PIPELINE STARTED\n")
    print("=" * 55)
    print("SETUP")
    print("=" * 55)
    if ORIGINAL_PATH.exists():
        shutil.copy(ORIGINAL_PATH, CONTRACT_PATH)
        print("[SETUP] ✅ Restored original vulnerable contract")
    contract = CONTRACT_PATH.read_text()
    print(f"[SETUP] Contract loaded ({len(contract)} chars)")
    return {**state,
            "contract_code":    contract,
            "contract_name":    "vulnerable_bank",
            "static_findings":  [],
            "ast_findings":     [],
            "cfg_findings":     [],
            "ai_findings":      [],
            "v3_findings":      [],
            "all_findings":     [],
            "exploit_results":  {},
            "score_results":    {},
            "patched_contract": "",
            "patch_errors":     "",
            "patch_iterations": 0,
            "patch_success":    False,
            "patch_verified":   False,
            "security_score":   0.0,
            "invariants":       [],
            "taint_findings":   [],
            "reflection_score": 0.0,
            "reflection_notes": "",
            "runtime_deployed": False,
            "devnet_deployed":  False,
            "network_results":  {},
            "tokens_used":      0,
            "errors":           []}


# ── Node: Static Analysis ─────────────────────────────────────
def static_analysis_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 1: STATIC ANALYSIS")
    print("=" * 55)
    contract = state["contract_code"]

    from analysis.static_checks.checks import run_all_checks
    from analysis.ast_parser.rust_ast_parser import parse_rust_ast, format_ast_findings
    from analysis.ast_parser.cfg_builder import analyze_cfg

    print("[NODE] Running KB static checks...")
    static = run_all_checks(contract)
    print(f"[NODE] Static: {len(static)} findings")

    print("[NODE] Running AST parser...")
    ast_result = parse_rust_ast(contract)
    print(format_ast_findings(ast_result))
    ast = [{"type": f["type"], "severity": f["severity"],
            "reason": f"{f['description']} (at {f['location']})",
            "line": f.get("line", 0), "source": "ast"}
           for f in ast_result.findings]
    print(f"[NODE] AST: {len(ast)} findings")

    print("[NODE] Running CFG analysis...")
    cfg_result = analyze_cfg(contract)
    print(cfg_result["summary"])
    cfg = [{"type": f["type"], "severity": f["severity"],
            "reason": f["description"], "line": f.get("line", 0),
            "source": "cfg"}
           for f in cfg_result["findings"]]
    print(f"[NODE] CFG: {len(cfg)} findings")

    return {**state,
            "static_findings": static,
            "ast_findings":    ast,
            "cfg_findings":    cfg}


# ── Node: AI Scan ─────────────────────────────────────────────
def ai_scan_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 2: AI SCAN")
    print("=" * 55)
    contract = state["contract_code"]

    from agents.scanner.scanner_agent import scan_contract
    from agents.scanner.scanner_v3 import scan_contract_v3

    print("[NODE] Running AI scanner...")
    scan_result = scan_contract(contract)
    ai = scan_result.get("risks", [])
    print(f"[NODE] AI: {len(ai)} findings")

    print("[NODE] Running V3 KB scanner...")
    v3_result = scan_contract_v3(contract)
    v3 = v3_result.get("risks", [])
    print(f"[NODE] V3: {len(v3)} findings")

    all_findings = (
        ai
        + [{"type": s["type"], "severity": s["severity"],
            "reason": s.get("description",""), "source": "static"}
           for s in state["static_findings"]]
        + state["ast_findings"]
        + state["cfg_findings"]
        + v3
    )
    print(f"\n[NODE] Total findings: {len(all_findings)}")

    return {**state,
            "ai_findings":  ai,
            "v3_findings":  v3,
            "all_findings": all_findings}


# ── Node: Taint Analysis (NEW Week 4) ─────────────────────────
def taint_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 2b: TAINT ANALYSIS")
    print("=" * 55)

    try:
        from agents.taint.taint_agent import analyze_taint
        taint_findings = analyze_taint(state["contract_code"])
        print(f"[NODE] Taint: {len(taint_findings)} findings")
        # Merge into all_findings
        all_findings = state["all_findings"] + taint_findings
        return {**state, "taint_findings": taint_findings,
                "all_findings": all_findings}
    except ImportError:
        print("[NODE] Taint agent not yet available — skipping")
        return state


# ── Node: Invariant Extraction (NEW Week 4) ───────────────────
def invariant_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 2c: INVARIANT EXTRACTION")
    print("=" * 55)

    try:
        from agents.invariant.invariant_agent import extract_invariants
        invariants = extract_invariants(state["contract_code"])
        print(f"[NODE] Extracted {len(invariants)} invariants")
        for inv in invariants:
            print(f"  → {inv.get('invariant','')}")
        return {**state, "invariants": invariants}
    except ImportError:
        print("[NODE] Invariant agent not yet available — skipping")
        return state


# ── Node: Exploit Validation ──────────────────────────────────
def exploit_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 3: EXPLOIT VALIDATION")
    print("=" * 55)

    from agents.exploit.exploit_agent import run_exploit_agent
    exploit_results = run_exploit_agent(
        findings=state["all_findings"],
        contract_code=state["contract_code"]
    )
    confirmed = exploit_results.get("confirmed", 0)
    total     = exploit_results.get("total", 0)
    print(f"[NODE] Exploit: {confirmed}/{total} confirmed")
    return {**state, "exploit_results": exploit_results}


# ── Node: Risk Scoring ────────────────────────────────────────
def score_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 4: RISK SCORING")
    print("=" * 55)

    from agents.scorer.scoring_engine import run_scoring
    score_results = run_scoring(
        findings=state["all_findings"],
        exploit_results=state["exploit_results"]
    )
    print(f"[NODE] Scored: {score_results.get('total',0)} findings")
    return {**state, "score_results": score_results}


# ── Node: Patch ───────────────────────────────────────────────
def patch_node(state: SecurityState) -> SecurityState:
    iteration = state["patch_iterations"] + 1
    print(f"\n--- Patch Iteration {iteration} / {MAX_PATCH_ITER} ---")

    from agents.patcher.patch_agent import patch_contract
    patched = patch_contract(
        state["patched_contract"] or state["contract_code"],
        state["patch_errors"]
    )
    if patched is None:
        return {**state, "patch_iterations": iteration,
                "errors": state["errors"] + ["Patcher returned None"]}
    return {**state, "patched_contract": patched,
            "patch_iterations": iteration}


# ── Node: Validate ────────────────────────────────────────────
def validate_node(state: SecurityState) -> SecurityState:
    from agents.validator.validator_agent import validate_contract
    result = validate_contract(state["patched_contract"])
    success = result.get("success", False)
    if success:
        print("[NODE] ✅ cargo check passed")
    else:
        print("[NODE] ❌ cargo check failed")
    return {**state,
            "patch_success": success,
            "patch_errors":  result.get("stderr","")[-1200:] if not success else ""}


# ── Node: Patch Verify (NEW Week 4) ───────────────────────────
def patch_verify_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 5b: PATCH VERIFICATION")
    print("=" * 55)

    try:
        from agents.verifier.patch_verifier import verify_patch
        verified, blocked, total = verify_patch(
            patched_contract=state["patched_contract"],
            exploit_results=state["exploit_results"]
        )
        print(f"[NODE] Patch verified: {blocked}/{total} exploits blocked")
        return {**state, "patch_verified": verified}
    except ImportError:
        print("[NODE] Patch verifier not yet available — skipping")
        # Fallback: rescan
        from analysis.static_checks.checks import run_all_checks
        from analysis.ast_parser.rust_ast_parser import parse_rust_ast
        from analysis.ast_parser.cfg_builder import analyze_cfg
        remaining = (
            len(run_all_checks(state["patched_contract"]))
            + len(parse_rust_ast(state["patched_contract"]).findings)
            + len(analyze_cfg(state["patched_contract"])["findings"])
        )
        original  = len(state["all_findings"])
        score     = round((original - remaining) / max(original, 1) * 100, 2)
        print(f"[NODE] Security score: {score}% ({remaining} remaining)")
        return {**state, "security_score": score,
                "patch_verified": remaining == 0}


# ── Node: Reflection (NEW Week 4) ─────────────────────────────
def reflection_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 5c: REFLECTION")
    print("=" * 55)

    try:
        from agents.reflection.reflection_agent import reflect_on_patch
        score, notes = reflect_on_patch(
            original_code=state["contract_code"],
            patched_code=state["patched_contract"],
            findings=state["all_findings"],
            exploit_results=state["exploit_results"]
        )
        print(f"[NODE] Reflection score: {score}/10")
        print(f"[NODE] Notes: {notes[:100]}")
        return {**state, "reflection_score": score,
                "reflection_notes": notes}
    except ImportError:
        print("[NODE] Reflection agent not yet available — skipping")
        return state


# ── Node: Runtime ─────────────────────────────────────────────
def runtime_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 6: RUNTIME VALIDATION")
    print("=" * 55)

    from runtime_validator.checker import run_runtime_validation
    result = run_runtime_validation(state["patched_contract"])
    deployed = result.get("deploy_success", False)
    print(f"[NODE] Runtime deployed: {deployed}")
    return {**state, "runtime_deployed": deployed}


# ── Node: Devnet ──────────────────────────────────────────────
def devnet_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 7: DEVNET DEPLOYMENT")
    print("=" * 55)

    from runtime_validator.devnet_checker import run_devnet_validation
    result = run_devnet_validation(state["patched_contract"], rebuild=True)
    deployed = result.get("deploy_success", False)
    if deployed:
        print(f"[NODE] ✅ Devnet: {result.get('explorer_url','')}")
    return {**state, "devnet_deployed": deployed}


# ── Node: Network ─────────────────────────────────────────────
def network_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("PHASE 8: NETWORK ANALYSIS")
    print("=" * 55)

    try:
        from agents.network.network_agent import run_network_agent as run_network_scan
        result = run_network_scan("devnet")
        print(f"[NODE] Network risk: {result.get('risk_score','?')}/10")
        return {**state, "network_results": result}
    except Exception as e:
        print(f"[NODE] Network scan error: {e}")
        return state


# ── Node: Save Output ─────────────────────────────────────────
def output_node(state: SecurityState) -> SecurityState:
    print("\n" + "=" * 55)
    print("SAVING OUTPUTS")
    print("=" * 55)

    from utils.file_writer import save_patched_contract

    if state["patched_contract"]:
        save_patched_contract(state["patched_contract"])
        print("[NODE] ✅ Patched contract saved")

    report = {
        "success":          state["patch_success"],
        "runtime_deployed": state["runtime_deployed"],
        "devnet_deployed":  state["devnet_deployed"],
        "patch_iterations": state["patch_iterations"],
        "patch_verified":   state["patch_verified"],
        "security_score":   state["security_score"],
        "reflection_score": state["reflection_score"],
        "findings": {
            "static": len(state["static_findings"]),
            "ast":    len(state["ast_findings"]),
            "cfg":    len(state["cfg_findings"]),
            "ai":     len(state["ai_findings"]),
            "v3":     len(state["v3_findings"]),
            "taint":  len(state["taint_findings"]),
            "total":  len(state["all_findings"]),
        },
        "exploit": state["exploit_results"],
        "scoring": state["score_results"],
        "invariants_count": len(state["invariants"]),
        "network": state["network_results"],
    }

    Path("outputs/reports").mkdir(parents=True, exist_ok=True)
    Path("outputs/reports/final_report.json").write_text(
        json.dumps(report, indent=2))
    print("[NODE] ✅ Final report saved")

    print("\n" + "=" * 55)
    print("FINAL RESULT")
    print("=" * 55)
    print(json.dumps({k: v for k, v in report.items()
                      if k not in ("exploit","scoring","network")},
                     indent=2))
    print("\n🏁 LANGGRAPH PIPELINE COMPLETED\n")
    return {**state}


# ── Routing Functions ─────────────────────────────────────────
def route_after_validate(state: SecurityState) -> str:
    if state["patch_success"]:
        return "patch_verify"
    if state["patch_iterations"] >= MAX_PATCH_ITER:
        print(f"\n⚠️  Max patch iterations ({MAX_PATCH_ITER}) reached\n")
        return "patch_verify"
    time.sleep(15)
    return "patch"


def route_after_exploit(state: SecurityState) -> str:
    confirmed = state["exploit_results"].get("confirmed", 0)
    if confirmed > 0:
        return "score"
    return "score"  # always score, even with 0 confirmed


# ── Build Graph ───────────────────────────────────────────────
def build_graph():
    g = StateGraph(SecurityState)

    # Add all nodes
    g.add_node("setup",           setup_node)
    g.add_node("static_analysis", static_analysis_node)
    g.add_node("ai_scan",         ai_scan_node)
    g.add_node("taint",           taint_node)
    g.add_node("invariant",       invariant_node)
    g.add_node("exploit",         exploit_node)
    g.add_node("score",           score_node)
    g.add_node("patch",           patch_node)
    g.add_node("validate",        validate_node)
    g.add_node("patch_verify",    patch_verify_node)
    g.add_node("reflection",      reflection_node)
    g.add_node("runtime",         runtime_node)
    g.add_node("devnet",          devnet_node)
    g.add_node("network",         network_node)
    g.add_node("output",          output_node)

    # Sequential edges
    g.add_edge(START,             "setup")
    g.add_edge("setup",           "static_analysis")
    g.add_edge("static_analysis", "ai_scan")
    g.add_edge("ai_scan",         "taint")
    g.add_edge("taint",           "invariant")
    g.add_edge("invariant",       "exploit")
    g.add_edge("exploit",         "score")
    g.add_edge("score",           "patch")
    g.add_edge("patch",           "validate")

    # Conditional: after validate → patch again or move forward
    g.add_conditional_edges("validate", route_after_validate, {
        "patch":       "patch",
        "patch_verify":"patch_verify",
    })

    g.add_edge("patch_verify", "reflection")
    g.add_edge("reflection",   "runtime")
    g.add_edge("runtime",      "devnet")
    g.add_edge("devnet",       "network")
    g.add_edge("network",      "output")
    g.add_edge("output",       END)

    return g.compile()


# ── Entry Point ───────────────────────────────────────────────
def run_pipeline():
    graph = build_graph()
    initial_state = {
        "contract_code": "", "contract_name": "",
        "static_findings": [], "ast_findings": [],
        "cfg_findings": [], "ai_findings": [],
        "v3_findings": [], "all_findings": [],
        "exploit_results": {}, "score_results": {},
        "patched_contract": "", "patch_errors": "",
        "patch_iterations": 0, "patch_success": False,
        "patch_verified": False, "security_score": 0.0,
        "invariants": [], "taint_findings": [],
        "reflection_score": 0.0, "reflection_notes": "",
        "runtime_deployed": False, "devnet_deployed": False,
        "network_results": {}, "tokens_used": 0, "errors": [],
    }
    graph.invoke(initial_state)


if __name__ == "__main__":
    run_pipeline()

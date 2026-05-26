from typing import TypedDict, Dict, Any
from langgraph.graph import StateGraph

from agents.scanner.scanner_agent import scan_contract
from agents.patcher.patch_agent import patch_contract
from agents.validator.validator_agent import validate_contract


# ---------------- STATE ----------------
class State(TypedDict):
    contract: str
    findings: Dict[str, Any]
    patched: str
    validation: Dict[str, Any]
    iteration: int
    max_iterations: int


# ---------------- NODES ----------------
def scanner_node(state: State):
    print("\n[SCANNER] Running vulnerability scan...\n")
    findings = scan_contract(state["contract"])
    print("[SCANNER] Completed\n")
    return {"findings": findings}


def patcher_node(state: State):
    print("\n[PATCHER] Generating secure patch...\n")

    # Use patched code as base if we already have one, else original
    base_contract = state.get("patched") or state["contract"]

    # Pull compiler errors cleanly — never inject into contract string
    errors = ""
    if state.get("validation") and not state["validation"].get("success", True):
        errors = state["validation"].get("stderr", "")[-1200:]
        print(f"[PATCHER] Retrying with compiler errors ({len(errors)} chars)")

    patched = patch_contract(base_contract, errors=errors)
    print("[PATCHER] Patch generated\n")
    return {"patched": patched}


def validator_node(state: State):
    print("\n[VALIDATOR] Building contract using Anchor...\n")
    validation = validate_contract(state["patched"])
    print("[VALIDATOR] Validation completed\n")
    return {
        "validation": validation,
        "iteration": state.get("iteration", 0) + 1
    }


# ---------------- ROUTING ----------------
def should_continue(state: State):
    if state["validation"]["success"]:
        return "end"
    if state["iteration"] >= state["max_iterations"]:
        return "end"
    return "patcher"


# ---------------- GRAPH ----------------
builder = StateGraph(State)

builder.add_node("scanner", scanner_node)
builder.add_node("patcher", patcher_node)
builder.add_node("validator", validator_node)

builder.set_entry_point("scanner")
builder.add_edge("scanner", "patcher")
builder.add_edge("patcher", "validator")

builder.add_conditional_edges(
    "validator",
    should_continue,
    {
        "patcher": "patcher",
        "end": None
    }
)

graph = builder.compile()
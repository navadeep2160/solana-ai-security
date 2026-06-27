"""
Symbolic Execution Engine
=========================
Lightweight symbolic execution inspired by SseRex.
Tracks path constraints and detects unchecked operations.
"""
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class SymbolicState:
    """Represents symbolic state at a program point."""
    function: str
    line: int
    path_constraints: List[str] = field(default_factory=list)
    checked_accounts: Set[str] = field(default_factory=set)
    unchecked_accounts: Set[str] = field(default_factory=set)
    operations: List[str] = field(default_factory=list)


@dataclass
class SymbolicFinding:
    vuln_type: str
    severity: str
    function: str
    line: int
    description: str
    path_constraint: str
    fix: str


class SymbolicEngine:
    """Lightweight symbolic execution for Solana contracts."""

    def __init__(self):
        self.states = []
        self.findings = []

    def analyze(self, facts: List[Dict]) -> List[SymbolicFinding]:
        """Analyze facts and generate symbolic findings."""
        self.findings = []

        # Group facts by function
        func_facts = {}
        for fact in facts:
            func = fact.get("function", "unknown")
            if func not in func_facts:
                func_facts[func] = []
            func_facts[func].append(fact)

        for func_name, facts_list in func_facts.items():
            self._analyze_function(func_name, facts_list)

        return self.findings

    def _analyze_function(self, func_name: str, facts: List[Dict]):
        """Analyze a single function symbolically."""
        checked = set()
        unchecked = set()
        has_signer_check = False
        has_owner_check = False
        has_arithmetic = False
        has_safe_math = False
        has_cpi = False
        has_transfer = False
        has_close = False

        for fact in facts:
            context = fact.get("context", {})

            if fact.get("layer") == "ast":
                has_signer_check = has_signer_check or context.get("has_signer", False)
                has_owner_check = has_owner_check or context.get("has_owner_check", False)
                has_safe_math = has_safe_math or context.get("has_checked_math", False)
                body = context.get("body", "")
                if body and any(op in body for op in ["-", "+", "*", "/"]):
                    has_arithmetic = True
                if "invoke" in body:
                    has_cpi = True

            elif fact.get("layer") == "symbolic":
                checked.update(context.get("checks_found", []))
                unchecked.update(context.get("unchecked_accounts", []))
                actions = context.get("actions_found", [])
                has_transfer = has_transfer or "transfer" in actions
                has_cpi = has_cpi or "cpi" in actions
                has_close = has_close or "close" in actions

        # Generate findings based on symbolic analysis
        if not has_signer_check and (has_cpi or has_transfer or has_close):
            self.findings.append(SymbolicFinding(
                vuln_type="Missing Signer Check",
                severity="CRITICAL",
                function=func_name,
                line=0,
                description=f"Function '{func_name}' performs critical operations without signer verification",
                path_constraint="signer_check == false",
                fix="Add ctx.accounts.<account>.is_signer check before critical operations"
            ))

        if not has_owner_check and has_transfer:
            self.findings.append(SymbolicFinding(
                vuln_type="Missing Owner Check",
                severity="HIGH",
                function=func_name,
                line=0,
                description=f"Function '{func_name}' may transfer funds without ownership verification",
                path_constraint="owner_check == false",
                fix="Verify account ownership before transfers"
            ))

        if has_arithmetic and not has_safe_math:
            self.findings.append(SymbolicFinding(
                vuln_type="Integer Overflow/Underflow",
                severity="HIGH",
                function=func_name,
                line=0,
                description=f"Function '{func_name}' has unchecked arithmetic operations",
                path_constraint="safe_math == false",
                fix="Use checked_add(), checked_sub(), checked_mul() instead of raw operators"
            ))

        if has_cpi and not has_signer_check:
            self.findings.append(SymbolicFinding(
                vuln_type="Arbitrary CPI",
                severity="CRITICAL",
                function=func_name,
                line=0,
                description=f"Function '{func_name}' performs CPI without signer verification",
                path_constraint="signer_check == false AND cpi == true",
                fix="Verify signer before invoke() or invoke_signed() calls"
            ))

        if unchecked and (has_transfer or has_cpi or has_close):
            for acc in unchecked:
                self.findings.append(SymbolicFinding(
                    vuln_type="Unchecked Account Usage",
                    severity="HIGH",
                    function=func_name,
                    line=0,
                    description=f"Account '{acc}' used without proper verification in '{func_name}'",
                    path_constraint=f"{acc} not in checked_accounts",
                    fix=f"Add validation for ctx.accounts.{acc} before use"
                ))

    def to_dict_list(self) -> List[Dict]:
        """Convert findings to dict list."""
        return [{
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "function": f.function,
            "line": f.line,
            "description": f.description,
            "path_constraint": f.path_constraint,
            "fix": f.fix,
            "source": "symbolic_engine",
            "confidence": 0.85,
        } for f in self.findings]

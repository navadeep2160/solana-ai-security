import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from analysis.ast_parser.rust_ast_parser import parse_rust_ast, FunctionInfo


@dataclass
class CFGNode:
    id: str
    kind: str          # entry, check, operation, exit, error
    code: str
    line: int
    successors: List[str] = field(default_factory=list)
    is_security_check: bool = False
    can_bypass: bool = False


@dataclass
class CFGGraph:
    function_name: str
    nodes: Dict[str, CFGNode] = field(default_factory=dict)
    entry: str = ""
    exits: List[str] = field(default_factory=list)
    security_findings: List[dict] = field(default_factory=list)


def build_cfg(function_name: str, function_body: str, start_line: int) -> CFGGraph:
    graph = CFGGraph(function_name=function_name)
    lines = function_body.strip().split("\n")

    entry_id = f"{function_name}_entry"
    graph.nodes[entry_id] = CFGNode(
        id=entry_id,
        kind="entry",
        code=f"fn {function_name}()",
        line=start_line
    )
    graph.entry = entry_id

    prev_id = entry_id
    node_counter = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped == "{" or stripped == "}":
            continue

        node_counter += 1
        node_id = f"{function_name}_node_{node_counter}"
        current_line = start_line + i

        # Determine node kind
        is_require = stripped.startswith("require!")
        is_check = any(kw in stripped for kw in [
            "require!", "if ", "assert!", ".is_signer", "== bank.owner"
        ])
        is_return = stripped.startswith("Ok(") or stripped.startswith("return") or stripped.startswith("Err(")
        is_math = any(op in stripped for op in ["+=", "-=", "checked_add", "checked_sub"])

        if is_require or is_check:
            kind = "check"
        elif is_return:
            kind = "exit"
        elif is_math:
            kind = "operation"
        else:
            kind = "operation"

        node = CFGNode(
            id=node_id,
            kind=kind,
            code=stripped[:80],
            line=current_line,
            is_security_check=is_check
        )

        # Connect previous node
        if prev_id in graph.nodes:
            graph.nodes[prev_id].successors.append(node_id)

        # require! has two successors: continue or error exit
        if is_require:
            error_id = f"{function_name}_error_{node_counter}"
            graph.nodes[error_id] = CFGNode(
                id=error_id,
                kind="error",
                code="return Err(ErrorCode)",
                line=current_line
            )
            node.successors.append(error_id)
            graph.exits.append(error_id)

        if is_return:
            graph.exits.append(node_id)

        graph.nodes[node_id] = node
        prev_id = node_id

    # Add final exit if not present
    exit_id = f"{function_name}_exit"
    graph.nodes[exit_id] = CFGNode(
        id=exit_id, kind="exit",
        code="return Ok(())",
        line=start_line + len(lines)
    )
    if prev_id != entry_id:
        graph.nodes[prev_id].successors.append(exit_id)
    graph.exits.append(exit_id)

    # Analyze security paths
    _analyze_security_paths(graph)

    return graph


def _analyze_security_paths(graph: CFGGraph):
    security_checks = [
        n for n in graph.nodes.values()
        if n.is_security_check
    ]
    operations = [
        n for n in graph.nodes.values()
        if n.kind == "operation"
    ]

    # Find operations that happen before any security check
    check_lines = [n.line for n in security_checks]
    op_lines = [n.line for n in operations]

    for op in operations:
        if not check_lines or op.line < min(check_lines):
            if any(x in op.code for x in ["balance", "amount", "transfer"]):
                graph.security_findings.append({
                    "type": "operation_before_check",
                    "severity": "critical",
                    "description": f"Operation '{op.code[:50]}' at line {op.line} executes before any security check.",
                    "line": op.line
                })

    # Check if sensitive functions have no security checks at all
    if not security_checks and graph.function_name in (
        "withdraw", "transfer", "close_account", "burn"
    ):
        graph.security_findings.append({
            "type": "no_security_checks",
            "severity": "critical",
            "description": f"Function '{graph.function_name}' has NO security checks in its execution path.",
            "line": 0
        })

    # Check for bypass paths — security check exists but can be skipped
    for node in security_checks:
        if len(node.successors) > 1:
            node.can_bypass = True


def extract_function_bodies(code: str) -> Dict[str, tuple]:
    functions = {}
    lines = code.split("\n")

    fn_pattern = re.compile(r'pub fn (\w+)\s*\(')
    for i, line in enumerate(lines):
        match = fn_pattern.search(line)
        if match:
            fn_name = match.group(1)
            # Find opening brace
            body_start = i
            depth = 0
            body_lines = []
            started = False
            for j in range(i, len(lines)):
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                if started:
                    body_lines.append(lines[j])
                if started and depth == 0:
                    break
            functions[fn_name] = ("\n".join(body_lines), i + 1)

    return functions


def analyze_cfg(code: str) -> dict:
    function_bodies = extract_function_bodies(code)
    graphs = {}
    all_findings = []

    for fn_name, (body, start_line) in function_bodies.items():
        graph = build_cfg(fn_name, body, start_line)
        graphs[fn_name] = graph
        all_findings.extend(graph.security_findings)

    return {
        "graphs": graphs,
        "findings": all_findings,
        "summary": _format_cfg_summary(graphs, all_findings)
    }


def _format_cfg_summary(graphs: Dict[str, CFGGraph], findings: list) -> str:
    lines = []
    lines.append(f"CFG Analysis — {len(graphs)} functions analyzed")
    lines.append("")

    for fn_name, graph in graphs.items():
        nodes = len(graph.nodes)
        checks = sum(1 for n in graph.nodes.values() if n.is_security_check)
        exits = len(graph.exits)
        lines.append(f"  fn {fn_name}():")
        lines.append(f"    nodes={nodes}, security_checks={checks}, exit_paths={exits}")
        if graph.security_findings:
            for f in graph.security_findings:
                lines.append(f"    ⚠️  [{f['severity'].upper()}] {f['description']}")

    lines.append("")
    lines.append(f"Total CFG findings: {len(findings)}")
    for f in findings:
        lines.append(f"  [{f['severity'].upper()}] {f['type']}: {f['description']}")

    return "\n".join(lines)

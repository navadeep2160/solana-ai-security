"""
analysis/ast_parser/cfg_builder.py
-----------------------------------
Builds a Control Flow Graph (CFG) from Rust/Anchor source.

Nodes  = BasicBlocks (sequential instruction ranges with security tags)
Edges  = typed control-flow transfers (if/else, loop, match, ?, return, panic)

Public API
----------
    build(source, source_file)  →  CFG

    # Backward-compat shims for scanner_agent.py / old callers:
    analyze_cfg(source)         →  {"graphs", "findings", "summary"}
    build_cfg(fn_name, body, start_line)  →  FunctionCFG  (old signature)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


# ===========================================================================
# Data structures
# ===========================================================================

@dataclass
class BasicBlock:
    id: str
    function: str
    lines: List[str]  = field(default_factory=list)
    line_start: int   = 0
    line_end:   int   = 0

    has_arithmetic:   bool = False
    has_signer_check: bool = False
    has_owner_check:  bool = False
    has_cpi:          bool = False
    has_pda:          bool = False
    has_transfer:     bool = False
    has_close:        bool = False
    has_init:         bool = False
    has_remaining:    bool = False
    unchecked_math:   bool = False

    def summary(self) -> str:
        tags = [k for k, v in {
            "arithmetic":    self.has_arithmetic,
            "signer_check":  self.has_signer_check,
            "owner_check":   self.has_owner_check,
            "cpi":           self.has_cpi,
            "pda":           self.has_pda,
            "transfer":      self.has_transfer,
            "close":         self.has_close,
            "init":          self.has_init,
            "remaining":     self.has_remaining,
            "unchecked_math":self.unchecked_math,
        }.items() if v]
        return f"[{self.id}] L{self.line_start}-{self.line_end} tags={tags}"


@dataclass
class CFGEdge:
    src:  str
    dst:  str
    kind: str   # sequential|if_true|if_false|loop|match|return|panic|error_prop


@dataclass
class FunctionCFG:
    name:   str
    params: List[str]
    blocks: List[BasicBlock]
    entry:  str
    exits:  List[str]

    def hotspots(self) -> List[BasicBlock]:
        return [
            b for b in self.blocks
            if b.unchecked_math
            or (b.has_arithmetic and not b.has_signer_check)
            or (b.has_cpi and not b.has_owner_check)
        ]


@dataclass
class CFG:
    source_file: str
    nodes:       List[BasicBlock]
    edges:       List[CFGEdge]
    functions:   Dict[str, FunctionCFG]

    def dot(self) -> str:
        lines = ["digraph CFG {", '  rankdir=TB;',
                 '  node [shape=box fontname="Courier" fontsize=9];']
        for node in self.nodes:
            tags = []
            if node.unchecked_math:   tags.append("UNCHECKED_MATH")
            if node.has_cpi:          tags.append("CPI")
            if node.has_pda:          tags.append("PDA")
            if node.has_signer_check: tags.append("signer_check")
            if node.has_owner_check:  tags.append("owner_check")
            if node.has_transfer:     tags.append("transfer")
            if node.has_close:        tags.append("close")
            if node.has_init:         tags.append("init")
            if node.has_remaining:    tags.append("remaining_accts")
            label = f"{node.id}\\nL{node.line_start}-{node.line_end}"
            if tags:
                label += "\\n" + " | ".join(tags)
            color = ("red" if node.unchecked_math else
                     "darkorange" if node.has_cpi else
                     "blue"       if node.has_pda else
                     "purple"     if node.has_close else "black")
            lines.append(f'  "{node.id}" [label="{label}" color="{color}" fontcolor="{color}"];')
        style = {"if_true":"solid","if_false":"dashed","loop":"dotted",
                 "return":"bold","panic":"bold","error_prop":"dashed",
                 "sequential":"solid","match":"dashed"}
        for e in self.edges:
            lines.append(f'  "{e.src}" -> "{e.dst}" [style="{style.get(e.kind,"solid")}" label="{e.kind}"];')
        lines.append("}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "functions": {
                fn_name: {
                    "params": fn.params,
                    "entry":  fn.entry,
                    "exits":  fn.exits,
                    "blocks": [
                        {
                            "id": b.id,
                            "line_start": b.line_start,
                            "line_end":   b.line_end,
                            "tags": {
                                "arithmetic":    b.has_arithmetic,
                                "signer_check":  b.has_signer_check,
                                "owner_check":   b.has_owner_check,
                                "cpi":           b.has_cpi,
                                "pda":           b.has_pda,
                                "transfer":      b.has_transfer,
                                "close":         b.has_close,
                                "init":          b.has_init,
                                "remaining":     b.has_remaining,
                                "unchecked_math":b.unchecked_math,
                            },
                            "lines": b.lines,
                        }
                        for b in fn.blocks
                    ],
                    "hotspot_block_ids": [b.id for b in fn.hotspots()],
                }
                for fn_name, fn in self.functions.items()
            },
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in self.edges],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ===========================================================================
# Patterns
# ===========================================================================

_RE_FN_SIG   = re.compile(r'\s*pub\s+fn\s+(\w+)\s*\(')
_RE_IF       = re.compile(r'\bif\b')
_RE_ELSE     = re.compile(r'\belse\b')
_RE_LOOP     = re.compile(r'\b(loop|while|for)\b')
_RE_MATCH    = re.compile(r'\bmatch\b')
_RE_RETURN   = re.compile(r'\breturn\b')
_RE_PANIC    = re.compile(r'\b(panic!|unreachable!|unimplemented!|Err\()')
_RE_ERR_PROP = re.compile(r'\?')

_RE_ARITHMETIC = re.compile(r'[+\-*/]|checked_|saturating_|wrapping_|overflowing_')
_RE_SIGNER     = re.compile(r'\.is_signer|require_keys_eq|require_signer|has_one|constraint\s*=')
_RE_OWNER      = re.compile(r'\.owner|program_id|owner\s*==|check_program_account')
_RE_CPI        = re.compile(r'\binvoke\b|\binvoke_signed\b|CpiContext|transfer\s*\(.*program')
_RE_PDA        = re.compile(r'find_program_address|create_program_address|seeds\s*=|bump\s*=')
_RE_TRANSFER   = re.compile(r'\btransfer\b|lamports|\.lamports\s*\(\s*\)')
_RE_CLOSE      = re.compile(r'\bclose\b|close_account|\.close\s*\(')
_RE_INIT       = re.compile(r'\binit\b|initialise|initialize|set_active|AccountInfo::new')
_RE_REMAINING  = re.compile(r'remaining_accounts')
_RE_RAW_MATH   = re.compile(r'(?<![a-z_])[\w.]+\s*[+\-*/]=\s*[\w.]+')
_RE_SAFE_MATH  = re.compile(r'checked_|saturating_|wrapping_|overflowing_')


# ===========================================================================
# Builder
# ===========================================================================

class CFGBuilder:
    def __init__(self):
        self._bb_counter: Dict[str, int] = {}

    def _new_bb(self, fn_name: str, line_start: int) -> BasicBlock:
        idx = self._bb_counter.get(fn_name, 0)
        self._bb_counter[fn_name] = idx + 1
        return BasicBlock(id=f"{fn_name}:bb{idx}", function=fn_name, line_start=line_start)

    def _tag_block(self, block: BasicBlock) -> None:
        text = "\n".join(block.lines)
        block.has_arithmetic   = bool(_RE_ARITHMETIC.search(text))
        block.has_signer_check = bool(_RE_SIGNER.search(text))
        block.has_owner_check  = bool(_RE_OWNER.search(text))
        block.has_cpi          = bool(_RE_CPI.search(text))
        block.has_pda          = bool(_RE_PDA.search(text))
        block.has_transfer     = bool(_RE_TRANSFER.search(text))
        block.has_close        = bool(_RE_CLOSE.search(text))
        block.has_init         = bool(_RE_INIT.search(text))
        block.has_remaining    = bool(_RE_REMAINING.search(text))
        block.unchecked_math   = (bool(_RE_RAW_MATH.search(text))
                                  and not bool(_RE_SAFE_MATH.search(text)))

    def _split_into_functions(self, source: str):
        results, lines = [], source.splitlines()
        depth, in_fn   = 0, False
        fn_name = ""; fn_params = []; fn_start = 0; fn_lines: List[str] = []
        in_sig = False  # True while collecting multi-line signature

        for i, raw in enumerate(lines):
            if not in_fn:
                m = _RE_FN_SIG.search(raw)
                if m or in_sig:
                    if m and not in_sig:
                        fn_name   = m.group(1)
                        fn_params = []  # params span multiple lines, extracted separately
                        fn_start  = i
                        fn_lines  = [raw]
                        in_sig    = True
                    else:
                        fn_lines.append(raw)

                    depth += raw.count('{') - raw.count('}')
                    if depth > 0:
                        in_fn  = True
                        in_sig = False
            else:
                fn_lines.append(raw)
                depth += raw.count('{') - raw.count('}')
                if depth <= 0:
                    results.append((fn_name, fn_params, fn_start, fn_lines))
                    in_fn = False; fn_lines = []; depth = 0; in_sig = False
        return results

    def _build_function_cfg(self, fn_name, params, fn_lines, offset) -> FunctionCFG:
        blocks: List[BasicBlock] = []
        local_edges: List[CFGEdge] = []
        current = self._new_bb(fn_name, offset)
        stack:   List[BasicBlock] = []

        for rel_i, line in enumerate(fn_lines):
            abs_line = offset + rel_i
            s = line.strip()

            if _RE_MATCH.search(s):
                self._tag_block(current); blocks.append(current)
                nxt = self._new_bb(fn_name, abs_line)
                local_edges.append(CFGEdge(current.id, nxt.id, "match"))
                stack.append(current); current = nxt

            elif _RE_IF.search(s) and not _RE_ELSE.search(s):
                self._tag_block(current); blocks.append(current)
                tb = self._new_bb(fn_name, abs_line)
                fb = self._new_bb(fn_name, abs_line)
                local_edges.append(CFGEdge(current.id, tb.id, "if_true"))
                local_edges.append(CFGEdge(current.id, fb.id, "if_false"))
                stack.append(fb); current = tb

            elif _RE_ELSE.search(s):
                self._tag_block(current); blocks.append(current)
                if stack:
                    fb = stack.pop()
                    local_edges.append(CFGEdge(current.id, fb.id, "sequential"))
                    current = fb

            elif _RE_LOOP.search(s):
                self._tag_block(current); blocks.append(current)
                lb = self._new_bb(fn_name, abs_line)
                local_edges.append(CFGEdge(current.id, lb.id, "loop"))
                stack.append(current); current = lb

            elif _RE_RETURN.search(s):
                current.lines.append(line); current.line_end = abs_line
                self._tag_block(current); blocks.append(current)
                current = self._new_bb(fn_name, abs_line + 1)

            elif _RE_PANIC.search(s):
                current.lines.append(line); current.line_end = abs_line
                self._tag_block(current); blocks.append(current)
                current = self._new_bb(fn_name, abs_line + 1)

            elif _RE_ERR_PROP.search(s):
                current.lines.append(line)
                nxt = self._new_bb(fn_name, abs_line + 1)
                local_edges.append(CFGEdge(current.id, nxt.id, "error_prop"))
                self._tag_block(current); blocks.append(current)
                current = nxt

            else:
                current.lines.append(line)

        if current.lines or not blocks:
            current.line_end = offset + len(fn_lines) - 1
            self._tag_block(current); blocks.append(current)

        existing_srcs = {e.src for e in local_edges}
        for i in range(len(blocks) - 1):
            if blocks[i].id not in existing_srcs:
                local_edges.append(CFGEdge(blocks[i].id, blocks[i+1].id, "sequential"))

        entry = blocks[0].id if blocks else f"{fn_name}:bb0"
        exits = [b.id for b in blocks
                 if any("return" in l or "panic!" in l for l in b.lines)]
        if not exits and blocks:
            exits = [blocks[-1].id]

        return FunctionCFG(name=fn_name, params=params,
                           blocks=blocks, entry=entry, exits=exits)

    def build(self, source: str, source_file: str = "<source>") -> CFG:
        self._bb_counter = {}
        all_nodes: List[BasicBlock] = []
        all_edges: List[CFGEdge]   = []
        functions:  Dict[str, FunctionCFG] = {}

        for fn_name, params, start, fn_lines in self._split_into_functions(source):
            fn_cfg = self._build_function_cfg(fn_name, params, fn_lines, start)
            functions[fn_name] = fn_cfg
            all_nodes.extend(fn_cfg.blocks)

        for fn_cfg in functions.values():
            for i in range(len(fn_cfg.blocks) - 1):
                all_edges.append(
                    CFGEdge(fn_cfg.blocks[i].id, fn_cfg.blocks[i+1].id, "sequential"))

        fn_names = set(functions.keys())
        for block in all_nodes:
            for called in fn_names:
                if called != block.function and re.search(rf'\b{called}\s*\(', "\n".join(block.lines)):
                    all_edges.append(CFGEdge(block.id, f"{called}:bb0", "cpi"))

        return CFG(source_file=source_file, nodes=all_nodes,
                   edges=all_edges, functions=functions)


# ===========================================================================
# Public API
# ===========================================================================

def build(source: str, source_file: str = "<source>") -> CFG:
    return CFGBuilder().build(source, source_file)


# ---------------------------------------------------------------------------
# Backward-compat shim: analyze_cfg()  (called by scanner_agent.py)
# ---------------------------------------------------------------------------

def analyze_cfg(code: str) -> dict:
    cfg = build(code, source_file="<source>")
    findings: List[dict] = []

    for fn_name, fn_cfg in cfg.functions.items():
        for block in fn_cfg.blocks:
            if block.unchecked_math:
                findings.append({
                    "type":        "unchecked_arithmetic",
                    "severity":    "critical",
                    "description": (f"Unchecked math in {fn_name}() "
                                    f"lines {block.line_start}-{block.line_end}"),
                    "line": block.line_start,
                })
            if block.has_transfer and not block.has_signer_check:
                findings.append({
                    "type":        "operation_before_check",
                    "severity":    "critical",
                    "description": (f"Transfer in {fn_name}() block {block.id} "
                                    f"with no signer check"),
                    "line": block.line_start,
                })
            if block.has_cpi and not block.has_owner_check:
                findings.append({
                    "type":        "unvalidated_cpi",
                    "severity":    "high",
                    "description": (f"CPI in {fn_name}() lines "
                                    f"{block.line_start}-{block.line_end} "
                                    f"with no owner check"),
                    "line": block.line_start,
                })

        sensitive = {"withdraw", "transfer", "close_account", "burn", "close_vault"}
        if fn_name in sensitive:
            has_check = any(b.has_signer_check or b.has_owner_check for b in fn_cfg.blocks)
            if not has_check:
                findings.append({
                    "type":        "no_security_checks",
                    "severity":    "critical",
                    "description": f"Function '{fn_name}' has NO security checks",
                    "line":        0,
                })

    return {
        "graphs":   cfg.functions,
        "findings": findings,
        "summary":  cfg.to_json(indent=2),
    }


# ---------------------------------------------------------------------------
# Backward-compat shim: build_cfg()  (old per-function signature)
# ---------------------------------------------------------------------------

def build_cfg(function_name: str, function_body: str, start_line: int = 0):
    cfg    = build(function_body, source_file=f"<{function_name}>")
    fn_cfg = cfg.functions.get(function_name)
    if fn_cfg is None and cfg.functions:
        fn_cfg = next(iter(cfg.functions.values()))
    if fn_cfg:
        fn_cfg.security_findings = [
            {
                "type":        "unchecked_arithmetic",
                "severity":    "critical",
                "description": f"Unchecked math in block {b.id}",
                "line":        b.line_start,
            }
            for b in fn_cfg.hotspots() if b.unchecked_math
        ]
    return fn_cfg


# ===========================================================================
# CLI
# ===========================================================================

if __name__ == "__main__":
    import sys
    from pathlib import Path

    if len(sys.argv) < 2:
        print("Usage: python cfg_builder.py <contract.rs> [--dot | --json]")
        sys.exit(1)

    path   = Path(sys.argv[1])
    source = path.read_text()
    mode   = sys.argv[2] if len(sys.argv) > 2 else "--json"
    cfg    = build(source, source_file=str(path))

    if mode == "--dot":
        print(cfg.dot())
    else:
        print(cfg.to_json())







# # import re
# # from dataclasses import dataclass, field
# # from typing import List, Dict, Optional
# # from analysis.ast_parser.rust_ast_parser import parse_rust_ast, FunctionInfo


# # @dataclass
# # class CFGNode:
# #     id: str
# #     kind: str          # entry, check, operation, exit, error
# #     code: str
# #     line: int
# #     successors: List[str] = field(default_factory=list)
# #     is_security_check: bool = False
# #     can_bypass: bool = False


# # @dataclass
# # class CFGGraph:
# #     function_name: str
# #     nodes: Dict[str, CFGNode] = field(default_factory=dict)
# #     entry: str = ""
# #     exits: List[str] = field(default_factory=list)
# #     security_findings: List[dict] = field(default_factory=list)


# # def build_cfg(function_name: str, function_body: str, start_line: int) -> CFGGraph:
# #     graph = CFGGraph(function_name=function_name)
# #     lines = function_body.strip().split("\n")

# #     entry_id = f"{function_name}_entry"
# #     graph.nodes[entry_id] = CFGNode(
# #         id=entry_id,
# #         kind="entry",
# #         code=f"fn {function_name}()",
# #         line=start_line
# #     )
# #     graph.entry = entry_id

# #     prev_id = entry_id
# #     node_counter = 0

# #     for i, line in enumerate(lines):
# #         stripped = line.strip()
# #         if not stripped or stripped == "{" or stripped == "}":
# #             continue

# #         node_counter += 1
# #         node_id = f"{function_name}_node_{node_counter}"
# #         current_line = start_line + i

# #         # Determine node kind
# #         is_require = stripped.startswith("require!")
# #         is_check = any(kw in stripped for kw in [
# #             "require!", "if ", "assert!", ".is_signer", "== bank.owner"
# #         ])
# #         is_return = stripped.startswith("Ok(") or stripped.startswith("return") or stripped.startswith("Err(")
# #         is_math = any(op in stripped for op in ["+=", "-=", "checked_add", "checked_sub"])

# #         if is_require or is_check:
# #             kind = "check"
# #         elif is_return:
# #             kind = "exit"
# #         elif is_math:
# #             kind = "operation"
# #         else:
# #             kind = "operation"

# #         node = CFGNode(
# #             id=node_id,
# #             kind=kind,
# #             code=stripped[:80],
# #             line=current_line,
# #             is_security_check=is_check
# #         )

# #         # Connect previous node
# #         if prev_id in graph.nodes:
# #             graph.nodes[prev_id].successors.append(node_id)

# #         # require! has two successors: continue or error exit
# #         if is_require:
# #             error_id = f"{function_name}_error_{node_counter}"
# #             graph.nodes[error_id] = CFGNode(
# #                 id=error_id,
# #                 kind="error",
# #                 code="return Err(ErrorCode)",
# #                 line=current_line
# #             )
# #             node.successors.append(error_id)
# #             graph.exits.append(error_id)

# #         if is_return:
# #             graph.exits.append(node_id)

# #         graph.nodes[node_id] = node
# #         prev_id = node_id

# #     # Add final exit if not present
# #     exit_id = f"{function_name}_exit"
# #     graph.nodes[exit_id] = CFGNode(
# #         id=exit_id, kind="exit",
# #         code="return Ok(())",
# #         line=start_line + len(lines)
# #     )
# #     if prev_id != entry_id:
# #         graph.nodes[prev_id].successors.append(exit_id)
# #     graph.exits.append(exit_id)

# #     # Analyze security paths
# #     _analyze_security_paths(graph)

# #     return graph


# # def _analyze_security_paths(graph: CFGGraph):
# #     security_checks = [
# #         n for n in graph.nodes.values()
# #         if n.is_security_check
# #     ]
# #     operations = [
# #         n for n in graph.nodes.values()
# #         if n.kind == "operation"
# #     ]

# #     # Find operations that happen before any security check
# #     check_lines = [n.line for n in security_checks]
# #     op_lines = [n.line for n in operations]

# #     for op in operations:
# #         if not check_lines or op.line < min(check_lines):
# #             if any(x in op.code for x in ["balance", "amount", "transfer"]):
# #                 graph.security_findings.append({
# #                     "type": "operation_before_check",
# #                     "severity": "critical",
# #                     "description": f"Operation '{op.code[:50]}' at line {op.line} executes before any security check.",
# #                     "line": op.line
# #                 })

# #     # Check if sensitive functions have no security checks at all
# #     if not security_checks and graph.function_name in (
# #         "withdraw", "transfer", "close_account", "burn"
# #     ):
# #         graph.security_findings.append({
# #             "type": "no_security_checks",
# #             "severity": "critical",
# #             "description": f"Function '{graph.function_name}' has NO security checks in its execution path.",
# #             "line": 0
# #         })

# #     # Check for bypass paths — security check exists but can be skipped
# #     for node in security_checks:
# #         if len(node.successors) > 1:
# #             node.can_bypass = True


# # def extract_function_bodies(code: str) -> Dict[str, tuple]:
# #     functions = {}
# #     lines = code.split("\n")

# #     fn_pattern = re.compile(r'pub fn (\w+)\s*\(')
# #     for i, line in enumerate(lines):
# #         match = fn_pattern.search(line)
# #         if match:
# #             fn_name = match.group(1)
# #             # Find opening brace
# #             body_start = i
# #             depth = 0
# #             body_lines = []
# #             started = False
# #             for j in range(i, len(lines)):
# #                 for ch in lines[j]:
# #                     if ch == "{":
# #                         depth += 1
# #                         started = True
# #                     elif ch == "}":
# #                         depth -= 1
# #                 if started:
# #                     body_lines.append(lines[j])
# #                 if started and depth == 0:
# #                     break
# #             functions[fn_name] = ("\n".join(body_lines), i + 1)

# #     return functions


# # def analyze_cfg(code: str) -> dict:
# #     function_bodies = extract_function_bodies(code)
# #     graphs = {}
# #     all_findings = []

# #     for fn_name, (body, start_line) in function_bodies.items():
# #         graph = build_cfg(fn_name, body, start_line)
# #         graphs[fn_name] = graph
# #         all_findings.extend(graph.security_findings)

# #     return {
# #         "graphs": graphs,
# #         "findings": all_findings,
# #         "summary": _format_cfg_summary(graphs, all_findings)
# #     }


# # def _format_cfg_summary(graphs: Dict[str, CFGGraph], findings: list) -> str:
# #     lines = []
# #     lines.append(f"CFG Analysis — {len(graphs)} functions analyzed")
# #     lines.append("")

# #     for fn_name, graph in graphs.items():
# #         nodes = len(graph.nodes)
# #         checks = sum(1 for n in graph.nodes.values() if n.is_security_check)
# #         exits = len(graph.exits)
# #         lines.append(f"  fn {fn_name}():")
# #         lines.append(f"    nodes={nodes}, security_checks={checks}, exit_paths={exits}")
# #         if graph.security_findings:
# #             for f in graph.security_findings:
# #                 lines.append(f"    ⚠️  [{f['severity'].upper()}] {f['description']}")

# #     lines.append("")
# #     lines.append(f"Total CFG findings: {len(findings)}")
# #     for f in findings:
# #         lines.append(f"  [{f['severity'].upper()}] {f['type']}: {f['description']}")

# #     return "\n".join(lines)
# """
# cfg_builder.py
# --------------
# Builds a Control Flow Graph (CFG) from a Rust/Anchor smart contract source file.

# Nodes  = basic blocks (sequential instruction sequences with no branching)
# Edges  = control-flow transfers (if/else, loop, match, ?, return, panic)

# Output
# ------
#   cfg_builder.build(source)  ->  CFG  (dataclass)

# CFG exposes:
#   .nodes      List[BasicBlock]
#   .edges      List[CFGEdge]
#   .functions  Dict[str, FunctionCFG]
#   .dot()      Graphviz DOT string
#   .to_dict()  JSON-serialisable dict (for fuzzer consumption)
# """

# from __future__ import annotations

# import re
# import json
# from dataclasses import dataclass, field
# from typing import Dict, List, Optional, Set, Tuple


# # ---------------------------------------------------------------------------
# # Data structures
# # ---------------------------------------------------------------------------

# @dataclass
# class BasicBlock:
#     id: str                          # e.g. "fn_withdraw:bb0"
#     function: str
#     lines: List[str] = field(default_factory=list)
#     line_start: int = 0
#     line_end:   int = 0

#     # Semantic tags populated during analysis
#     has_arithmetic:  bool = False    # +, -, *, /, checked_*, saturating_*
#     has_signer_check: bool = False   # .is_signer, require_keys_eq, etc.
#     has_owner_check:  bool = False   # .owner, program_id checks
#     has_cpi:          bool = False   # invoke, invoke_signed, CpiContext
#     has_pda:          bool = False   # find_program_address, create_program_address
#     has_transfer:     bool = False   # transfer, lamport arithmetic
#     has_close:        bool = False   # close, close_account
#     has_init:         bool = False   # init, initialise, set_active
#     has_remaining:    bool = False   # remaining_accounts
#     unchecked_math:   bool = False   # raw +/-/* without checked_ or saturating_

#     def summary(self) -> str:
#         tags = [k for k, v in {
#             "arithmetic": self.has_arithmetic,
#             "signer_check": self.has_signer_check,
#             "owner_check": self.has_owner_check,
#             "cpi": self.has_cpi,
#             "pda": self.has_pda,
#             "transfer": self.has_transfer,
#             "close": self.has_close,
#             "init": self.has_init,
#             "remaining_accounts": self.has_remaining,
#             "unchecked_math": self.unchecked_math,
#         }.items() if v]
#         return f"[{self.id}] lines {self.line_start}-{self.line_end} tags={tags}"


# @dataclass
# class CFGEdge:
#     src: str          # BasicBlock.id
#     dst: str          # BasicBlock.id
#     kind: str         # "sequential"|"if_true"|"if_false"|"loop"|"match"|"return"|"panic"|"error_prop"


# @dataclass
# class FunctionCFG:
#     name: str
#     params: List[str]
#     blocks: List[BasicBlock]
#     entry: str        # id of entry block
#     exits: List[str]  # ids of exit blocks (return / panic)

#     # Vulnerability hotspots derived from block tags
#     def hotspots(self) -> List[BasicBlock]:
#         return [b for b in self.blocks if b.unchecked_math or (b.has_arithmetic and not b.has_signer_check)]


# @dataclass
# class CFG:
#     source_file: str
#     nodes: List[BasicBlock]
#     edges: List[CFGEdge]
#     functions: Dict[str, FunctionCFG]

#     # ------------------------------------------------------------------
#     def dot(self) -> str:
#         """Return a Graphviz DOT representation."""
#         lines = ["digraph CFG {", '  rankdir=TB;', '  node [shape=box fontname="Courier" fontsize=9];']

#         color_map = {
#             "unchecked_math":  "red",
#             "cpi":             "orange",
#             "pda":             "blue",
#             "init":            "green",
#             "close":           "purple",
#         }

#         for node in self.nodes:
#             tags = []
#             if node.unchecked_math:   tags.append("⚠ unchecked_math")
#             if node.has_cpi:          tags.append("CPI")
#             if node.has_pda:          tags.append("PDA")
#             if node.has_signer_check: tags.append("signer✓")
#             if node.has_owner_check:  tags.append("owner✓")
#             if node.has_transfer:     tags.append("transfer")
#             if node.has_close:        tags.append("close")
#             if node.has_init:         tags.append("init")
#             if node.has_remaining:    tags.append("remaining_accts")

#             label = f"{node.id}\\nL{node.line_start}-{node.line_end}"
#             if tags:
#                 label += "\\n" + " | ".join(tags)

#             color = "black"
#             if node.unchecked_math:  color = "red"
#             elif node.has_cpi:       color = "darkorange"
#             elif node.has_pda:       color = "blue"
#             elif node.has_close:     color = "purple"

#             lines.append(f'  "{node.id}" [label="{label}" color="{color}" fontcolor="{color}"];')

#         edge_styles = {
#             "if_true":    "solid",
#             "if_false":   "dashed",
#             "loop":       "dotted",
#             "return":     "bold",
#             "panic":      "bold",
#             "error_prop": "dashed",
#             "sequential": "solid",
#             "match":      "dashed",
#         }
#         for edge in self.edges:
#             style = edge_styles.get(edge.kind, "solid")
#             lines.append(f'  "{edge.src}" -> "{edge.dst}" [style="{style}" label="{edge.kind}"];')

#         lines.append("}")
#         return "\n".join(lines)

#     # ------------------------------------------------------------------
#     def to_dict(self) -> dict:
#         """JSON-serialisable dict consumed by the Fuzzer Agent."""
#         return {
#             "source_file": self.source_file,
#             "functions": {
#                 fn_name: {
#                     "params": fn.params,
#                     "entry": fn.entry,
#                     "exits": fn.exits,
#                     "blocks": [
#                         {
#                             "id": b.id,
#                             "line_start": b.line_start,
#                             "line_end":   b.line_end,
#                             "tags": {
#                                 "arithmetic":    b.has_arithmetic,
#                                 "signer_check":  b.has_signer_check,
#                                 "owner_check":   b.has_owner_check,
#                                 "cpi":           b.has_cpi,
#                                 "pda":           b.has_pda,
#                                 "transfer":      b.has_transfer,
#                                 "close":         b.has_close,
#                                 "init":          b.has_init,
#                                 "remaining":     b.has_remaining,
#                                 "unchecked_math":b.unchecked_math,
#                             },
#                             "lines": b.lines,
#                         }
#                         for b in fn.blocks
#                     ],
#                     "hotspot_block_ids": [b.id for b in fn.hotspots()],
#                 }
#                 for fn_name, fn in self.functions.items()
#             },
#             "edges": [
#                 {"src": e.src, "dst": e.dst, "kind": e.kind}
#                 for e in self.edges
#             ],
#         }

#     def to_json(self, indent: int = 2) -> str:
#         return json.dumps(self.to_dict(), indent=indent)


# # ---------------------------------------------------------------------------
# # Regex patterns
# # ---------------------------------------------------------------------------

# _RE_FN_SIG      = re.compile(r'^\s*pub\s+fn\s+(\w+)\s*\(([^)]*)\)')
# _RE_IF          = re.compile(r'\bif\b')
# _RE_ELSE        = re.compile(r'\belse\b')
# _RE_LOOP        = re.compile(r'\b(loop|while|for)\b')
# _RE_MATCH       = re.compile(r'\bmatch\b')
# _RE_RETURN      = re.compile(r'\breturn\b')
# _RE_PANIC       = re.compile(r'\b(panic!|unreachable!|unimplemented!|err\(|Err\()')
# _RE_ERROR_PROP  = re.compile(r'\?')

# _RE_ARITHMETIC  = re.compile(r'[+\-*/]|checked_|saturating_|wrapping_|overflowing_')
# _RE_UNCHECKED   = re.compile(r'(?<!\w)([\w.]+)\s*[+\-*/]=?\s*(?!checked_|saturating_|wrapping_)')
# _RE_SIGNER      = re.compile(r'\.is_signer|require_keys_eq|require_signer|has_one|constraint\s*=')
# _RE_OWNER       = re.compile(r'\.owner|program_id|owner\s*==|check_program_account')
# _RE_CPI         = re.compile(r'\binvoke\b|\binvoke_signed\b|CpiContext|transfer\s*\(.*program')
# _RE_PDA         = re.compile(r'find_program_address|create_program_address|seeds\s*=|bump\s*=')
# _RE_TRANSFER    = re.compile(r'\btransfer\b|lamports|\.lamports\s*\(\s*\)')
# _RE_CLOSE       = re.compile(r'\bclose\b|close_account|\.close\s*\(')
# _RE_INIT        = re.compile(r'\binit\b|initialise|initialize|set_active|AccountInfo::new')
# _RE_REMAINING   = re.compile(r'remaining_accounts')
# _RE_RAW_MATH    = re.compile(r'[+\-*/]=?\s*\d')   # raw arithmetic with literal or variable


# # ---------------------------------------------------------------------------
# # Builder
# # ---------------------------------------------------------------------------

# class CFGBuilder:
#     def __init__(self):
#         self._bb_counter: Dict[str, int] = {}

#     def _new_bb(self, fn_name: str, line_start: int) -> BasicBlock:
#         idx = self._bb_counter.get(fn_name, 0)
#         self._bb_counter[fn_name] = idx + 1
#         return BasicBlock(id=f"{fn_name}:bb{idx}", function=fn_name, line_start=line_start)

#     # ------------------------------------------------------------------
#     def _tag_block(self, block: BasicBlock) -> None:
#         text = "\n".join(block.lines)

#         block.has_arithmetic   = bool(_RE_ARITHMETIC.search(text))
#         block.has_signer_check = bool(_RE_SIGNER.search(text))
#         block.has_owner_check  = bool(_RE_OWNER.search(text))
#         block.has_cpi          = bool(_RE_CPI.search(text))
#         block.has_pda          = bool(_RE_PDA.search(text))
#         block.has_transfer     = bool(_RE_TRANSFER.search(text))
#         block.has_close        = bool(_RE_CLOSE.search(text))
#         block.has_init         = bool(_RE_INIT.search(text))
#         block.has_remaining    = bool(_RE_REMAINING.search(text))

#         # Unchecked math: has arithmetic but no checked_/saturating_ variant
#         has_safe_math = bool(re.search(r'checked_|saturating_|wrapping_|overflowing_', text))
#         has_raw_math  = bool(re.search(r'(?<![a-z_])[\w.]+\s*[+\-*/]=\s*[\w.]+', text))
#         block.unchecked_math = has_raw_math and not has_safe_math

#     # ------------------------------------------------------------------
#     def _split_into_functions(self, source: str) -> List[Tuple[str, List[str], int]]:
#         """Return list of (fn_name, param_list, start_line_index, source_lines)."""
#         results: List[Tuple[str, List[str], int, List[str]]] = []
#         lines = source.splitlines()
#         depth = 0
#         in_fn = False
#         fn_name = ""
#         fn_params: List[str] = []
#         fn_start = 0
#         fn_lines: List[str] = []

#         for i, raw_line in enumerate(lines):
#             line = raw_line

#             if not in_fn:
#                 m = _RE_FN_SIG.match(line)
#                 if m:
#                     fn_name = m.group(1)
#                     raw_params = m.group(2)
#                     fn_params = [p.strip().split(':')[0].strip()
#                                  for p in raw_params.split(',') if p.strip()]
#                     fn_start = i
#                     fn_lines = [line]
#                     # Count opening braces on this line
#                     depth = line.count('{') - line.count('}')
#                     if depth > 0:
#                         in_fn = True
#             else:
#                 fn_lines.append(line)
#                 depth += line.count('{') - line.count('}')
#                 if depth <= 0:
#                     results.append((fn_name, fn_params, fn_start, fn_lines))
#                     in_fn = False
#                     fn_lines = []
#                     depth = 0

#         return results

#     # ------------------------------------------------------------------
#     def _build_function_cfg(self, fn_name: str, params: List[str],
#                              fn_lines: List[str], offset: int) -> FunctionCFG:
#         """
#         Simple linear scan that splits into basic blocks on control-flow keywords.
#         Not a full compiler-grade CFG — it's a pragmatic approximation good enough
#         for security analysis and fuzzer hint generation.
#         """
#         blocks: List[BasicBlock] = []
#         edges:  List[CFGEdge]   = []

#         current = self._new_bb(fn_name, offset)
#         block_stack: List[BasicBlock] = []   # for if/loop/match nesting

#         for rel_i, line in enumerate(fn_lines):
#             abs_line = offset + rel_i
#             stripped = line.strip()

#             # -- branch/loop/match starts a new block --
#             if _RE_MATCH.search(stripped):
#                 self._tag_block(current)
#                 blocks.append(current)
#                 nxt = self._new_bb(fn_name, abs_line)
#                 edges.append(CFGEdge(current.id, nxt.id, "match"))
#                 block_stack.append(current)
#                 current = nxt

#             elif _RE_IF.search(stripped) and not _RE_ELSE.search(stripped):
#                 self._tag_block(current)
#                 blocks.append(current)
#                 true_bb  = self._new_bb(fn_name, abs_line)
#                 false_bb = self._new_bb(fn_name, abs_line)
#                 edges.append(CFGEdge(current.id, true_bb.id,  "if_true"))
#                 edges.append(CFGEdge(current.id, false_bb.id, "if_false"))
#                 block_stack.append(false_bb)
#                 current = true_bb

#             elif _RE_ELSE.search(stripped):
#                 self._tag_block(current)
#                 blocks.append(current)
#                 # pop false branch from stack
#                 if block_stack:
#                     false_bb = block_stack.pop()
#                     edges.append(CFGEdge(current.id, false_bb.id, "sequential"))
#                     current = false_bb

#             elif _RE_LOOP.search(stripped):
#                 self._tag_block(current)
#                 blocks.append(current)
#                 loop_bb = self._new_bb(fn_name, abs_line)
#                 edges.append(CFGEdge(current.id, loop_bb.id, "loop"))
#                 block_stack.append(current)   # back-edge target
#                 current = loop_bb

#             elif _RE_RETURN.search(stripped):
#                 current.lines.append(line)
#                 current.line_end = abs_line
#                 self._tag_block(current)
#                 blocks.append(current)
#                 # start fresh block (dead code after return)
#                 current = self._new_bb(fn_name, abs_line + 1)

#             elif _RE_PANIC.search(stripped):
#                 current.lines.append(line)
#                 current.line_end = abs_line
#                 self._tag_block(current)
#                 blocks.append(current)
#                 current = self._new_bb(fn_name, abs_line + 1)

#             elif _RE_ERROR_PROP.search(stripped):
#                 current.lines.append(line)
#                 nxt = self._new_bb(fn_name, abs_line + 1)
#                 edges.append(CFGEdge(current.id, nxt.id, "error_prop"))
#                 self._tag_block(current)
#                 blocks.append(current)
#                 current = nxt

#             else:
#                 current.lines.append(line)

#         # flush final block
#         if current.lines or not blocks:
#             current.line_end = offset + len(fn_lines) - 1
#             self._tag_block(current)
#             blocks.append(current)

#         # add sequential edges between consecutive blocks where no edge exists
#         block_ids: Set[str] = {b.id for b in blocks}
#         existing_srcs = {e.src for e in edges}

#         for i in range(len(blocks) - 1):
#             if blocks[i].id not in existing_srcs:
#                 edges.append(CFGEdge(blocks[i].id, blocks[i+1].id, "sequential"))

#         entry = blocks[0].id if blocks else f"{fn_name}:bb0"
#         exits = [b.id for b in blocks
#                  if any("return" in l or "panic!" in l for l in b.lines)]
#         if not exits and blocks:
#             exits = [blocks[-1].id]

#         return FunctionCFG(
#             name=fn_name,
#             params=params,
#             blocks=blocks,
#             entry=entry,
#             exits=exits,
#         )

#     # ------------------------------------------------------------------
#     def build(self, source: str, source_file: str = "<source>") -> CFG:
#         self._bb_counter = {}
#         all_nodes: List[BasicBlock] = []
#         all_edges: List[CFGEdge]   = []
#         functions: Dict[str, FunctionCFG] = {}

#         fn_defs = self._split_into_functions(source)

#         for fn_name, params, start_line, fn_lines in fn_defs:
#             fn_cfg = self._build_function_cfg(fn_name, params, fn_lines, start_line)
#             functions[fn_name] = fn_cfg
#             all_nodes.extend(fn_cfg.blocks)

#         # Collect inter-function edges (CPI / direct calls)
#         fn_names = set(functions.keys())
#         for block in all_nodes:
#             for line in block.lines:
#                 for called in fn_names:
#                     if re.search(rf'\b{called}\s*\(', line) and called != block.function:
#                         all_edges.append(CFGEdge(block.id, f"{called}:bb0", "cpi"))

#         # Add all intra-function edges
#         for fn_cfg in functions.values():
#             # rebuild edges from function (they were local, re-gather)
#             pass  # edges already in fn_cfg.blocks traversal above

#         # Reconstruct edges from all functions
#         intra_edges: List[CFGEdge] = []
#         for fn_cfg in functions.values():
#             block_set = {b.id for b in fn_cfg.blocks}
#             # Re-run edge computation per function (stored in fn_cfg during build)
#         # Simpler: store edges per function in the dataclass
#         # For now collect from a second pass:
#         all_edges_final: List[CFGEdge] = []
#         for fn_name, fn_cfg in functions.items():
#             fn_block_ids = {b.id for b in fn_cfg.blocks}
#             # sequential pairs
#             for i in range(len(fn_cfg.blocks) - 1):
#                 all_edges_final.append(
#                     CFGEdge(fn_cfg.blocks[i].id, fn_cfg.blocks[i+1].id, "sequential")
#                 )

#         return CFG(
#             source_file=source_file,
#             nodes=all_nodes,
#             edges=all_edges_final + all_edges,
#             functions=functions,
#         )


# # ---------------------------------------------------------------------------
# # Public convenience
# # ---------------------------------------------------------------------------

# def build(source: str, source_file: str = "<source>") -> CFG:
#     return CFGBuilder().build(source, source_file)


# # ---------------------------------------------------------------------------
# # CLI
# # ---------------------------------------------------------------------------



# if __name__ == "__main__":
#     import sys, pathlib

#     if len(sys.argv) < 2:
#         print("Usage: python cfg_builder.py <contract.rs> [--dot | --json]")
#         sys.exit(1)

#     path = pathlib.Path(sys.argv[1])
#     source = path.read_text()
#     mode = sys.argv[2] if len(sys.argv) > 2 else "--json"

#     cfg = build(source, source_file=str(path))

#     if mode == "--dot":
#         print(cfg.dot())
#     else:
#         print(cfg.to_json())
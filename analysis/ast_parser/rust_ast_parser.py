"""
Rust AST Parser — Pure structural extraction.
No hardcoded vulnerability logic here.
Vulnerability judgment is done by kb_ast_analyzer.py using KB+AI.
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FunctionInfo:
    name: str
    line: int
    params: List[str] = field(default_factory=list)
    has_signer: bool = False
    has_owner_check: bool = False
    has_checked_math: bool = False
    body: str = ""


@dataclass
class AccountStructInfo:
    name: str
    line: int
    fields: List[dict] = field(default_factory=list)


@dataclass
class ASTResult:
    functions: List[FunctionInfo] = field(default_factory=list)
    account_structs: List[AccountStructInfo] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)


def parse_rust_ast(code: str) -> ASTResult:
    result = ASTResult()
    lines  = code.split("\n")
    _parse_functions(code, lines, result)
    _parse_account_structs(code, lines, result)
    # Findings now come from KB-driven analyzer, not hardcoded rules
    # But keep backward compat by running lightweight structural check
    _structural_findings(result, code)
    return result


def _parse_functions(code: str, lines: List[str], result: ASTResult):
    fn_pattern = re.compile(r'pub fn (\w+)\s*\(([^)]*)\)', re.MULTILINE)
    for match in fn_pattern.finditer(code):
        name   = match.group(1)
        params = match.group(2)
        line   = code[:match.start()].count("\n") + 1
        body_start = code.find("{", match.end())
        body   = _extract_block(code, body_start)
        result.functions.append(FunctionInfo(
            name=name,
            line=line,
            params=[p.strip() for p in params.split(",") if p.strip()],
            has_signer=_check_signer(body, name),
            has_owner_check=_check_owner(body, name, code),
            has_checked_math=_check_math(body),
            body=body,
        ))


def _parse_account_structs(code: str, lines: List[str], result: ASTResult):
    struct_pattern = re.compile(
        r'#\[derive\(Accounts\)\]\s*pub struct (\w+)', re.MULTILINE)
    for match in struct_pattern.finditer(code):
        name = match.group(1)
        line = code[:match.start()].count("\n") + 1
        body_start = code.find("{", match.end())
        body   = _extract_block(code, body_start)
        fields = _parse_struct_fields(body, line)
        result.account_structs.append(AccountStructInfo(
            name=name, line=line, fields=fields))


def _parse_struct_fields(body: str, base_line: int) -> List[dict]:
    fields = []
    lines  = body.split("\n")
    current_attrs = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#["):
            current_attrs.append(stripped)
            continue
        field_match = re.match(r'pub (\w+):\s*(.+?)(?:,|$)', stripped)
        if field_match:
            fname = field_match.group(1)
            ftype = field_match.group(2).strip().rstrip(",")
            fields.append({
                "name":            fname,
                "type":            ftype,
                "attributes":      current_attrs.copy(),
                "line":            base_line + i,
                "is_signer":       "Signer" in ftype,
                "is_account_info": "AccountInfo" in ftype,
                "has_constraint":  any(
                    "constraint" in a or "has_one" in a
                    for a in current_attrs),
            })
            current_attrs = []
        elif stripped and not stripped.startswith("//"):
            current_attrs = []
    return fields


def _extract_block(code: str, start: int) -> str:
    if start == -1:
        return ""
    depth = 0
    for i in range(start, len(code)):
        if code[i] == "{":   depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start:i+1]
    return code[start:]


def _check_signer(body: str, fn_name: str) -> bool:
    return bool(re.search(r'require!\s*\(|\.is_signer|Signer', body))


def _check_owner(body: str, fn_name: str, full_code: str) -> bool:
    patterns = [r'\.owner\s*==', r'has_one\s*=',
                r'require!\s*\(.*owner', r'constraint\s*=.*owner']
    if any(re.search(p, body) for p in patterns):
        return True
    struct_name = fn_name.replace("_", " ").title().replace(" ", "")
    m = re.search(rf"pub struct {struct_name}<.*?{{(.*?)}}", full_code, re.DOTALL)
    if m:
        return any(re.search(p, m.group(1)) for p in patterns)
    return False


def _check_math(body: str) -> bool:
    has_unsafe = bool(re.search(r'\w+\s*[+\-]=\s*\w+', body))
    has_safe   = "checked_add" in body or "checked_sub" in body
    return not has_unsafe or has_safe


def _structural_findings(result: ASTResult, code: str):
    """
    Lightweight structural facts only — no KB needed.
    Full KB-driven analysis done separately in kb_ast_analyzer.
    These are kept for backward compat with format_ast_findings().
    """
    SKIP = {"target_program","program","token_program",
            "system_program","rent","clock",
            "associated_token_program","metadata_program"}

    for struct in result.account_structs:
        for f in struct.fields:
            if f["is_account_info"] and f["name"] not in SKIP:
                result.findings.append({
                    "type":     "missing_signer",
                    "severity": "critical",
                    "location": f"struct {struct.name}, field {f['name']}, line {f['line']}",
                    "description": f"Field '{f['name']}' uses AccountInfo — no signer enforced.",
                    "line": f["line"],
                })

    for fn in result.functions:
        if fn.name in ("withdraw","transfer","burn","close_account"):
            if not fn.has_owner_check:
                result.findings.append({
                    "type":     "missing_owner_check",
                    "severity": "critical",
                    "location": f"fn {fn.name}, line {fn.line}",
                    "description": f"'{fn.name}' has no owner check.",
                    "line": fn.line,
                })
            if not fn.has_checked_math:
                result.findings.append({
                    "type":     "unsafe_math",
                    "severity": "high",
                    "location": f"fn {fn.name}, line {fn.line}",
                    "description": f"'{fn.name}' uses unsafe arithmetic.",
                    "line": fn.line,
                })
        if fn.name == "deposit" and not fn.has_checked_math:
            result.findings.append({
                "type":     "integer_overflow",
                "severity": "high",
                "location": f"fn {fn.name}, line {fn.line}",
                "description": f"'deposit' uses += without checked_add.",
                "line": fn.line,
            })


def format_ast_findings(ast_result: ASTResult) -> str:
    lines = [f"Functions found: {len(ast_result.functions)}"]
    for fn in ast_result.functions:
        lines.append(f"  fn {fn.name}() at line {fn.line}")
        lines.append(f"    signer_check={fn.has_signer}, "
                     f"owner_check={fn.has_owner_check}, "
                     f"safe_math={fn.has_checked_math}")
    lines.append(f"\nAccount structs found: {len(ast_result.account_structs)}")
    for s in ast_result.account_structs:
        lines.append(f"  struct {s.name} at line {s.line}")
        for f in s.fields:
            lines.append(f"    {f['name']}: {f['type']} (signer={f['is_signer']})")
    lines.append(f"\nAST findings: {len(ast_result.findings)}")
    for f in ast_result.findings:
        lines.append(f"  [{f['severity'].upper()}] {f['type']} at {f['location']}")
        lines.append(f"    {f['description']}")
    return "\n".join(lines)

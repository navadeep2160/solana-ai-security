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
    vulnerabilities: List[dict] = field(default_factory=list)


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
    lines = code.split("\n")

    _parse_functions(code, lines, result)
    _parse_account_structs(code, lines, result)
    _analyze_security(result, code)

    return result


def _parse_functions(code: str, lines: List[str], result: ASTResult):
    fn_pattern = re.compile(
        r'pub fn (\w+)\s*\(([^)]*)\)',
        re.MULTILINE
    )

    for match in fn_pattern.finditer(code):
        name = match.group(1)
        params = match.group(2)

        # Get line number
        line = code[:match.start()].count("\n") + 1

        # Extract function body
        body_start = code.find("{", match.end())
        body = _extract_block(code, body_start)

        fn_info = FunctionInfo(
            name=name,
            line=line,
            params=[p.strip() for p in params.split(",") if p.strip()],
            has_signer=_check_signer_in_body(body, name),
            has_owner_check=_check_owner_in_body(body, fn_name=name, full_code=code),
            has_checked_math=_check_math_safety(body),
        )

        result.functions.append(fn_info)


def _parse_account_structs(code: str, lines: List[str], result: ASTResult):
    struct_pattern = re.compile(
        r'#\[derive\(Accounts\)\]\s*pub struct (\w+)',
        re.MULTILINE
    )

    for match in struct_pattern.finditer(code):
        name = match.group(1)
        line = code[:match.start()].count("\n") + 1

        # Extract struct body
        body_start = code.find("{", match.end())
        body = _extract_block(code, body_start)

        fields = _parse_struct_fields(body, line)

        struct_info = AccountStructInfo(
            name=name,
            line=line,
            fields=fields
        )

        result.account_structs.append(struct_info)


def _parse_struct_fields(body: str, base_line: int) -> List[dict]:
    fields = []
    lines = body.split("\n")
    current_attrs = []

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Collect attributes
        if stripped.startswith("#["):
            current_attrs.append(stripped)
            continue

        # Detect field declaration
        field_match = re.match(
            r'pub (\w+):\s*(.+?)(?:,|$)',
            stripped
        )
        if field_match:
            field_name = field_match.group(1)
            field_type = field_match.group(2).strip().rstrip(",")

            fields.append({
                "name": field_name,
                "type": field_type,
                "attributes": current_attrs.copy(),
                "line": base_line + i,
                "is_signer": "Signer" in field_type,
                "is_account_info": "AccountInfo" in field_type,
                "has_constraint": any(
                    "constraint" in a or "has_one" in a
                    for a in current_attrs
                ),
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
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start:i+1]
    return code[start:]


def _check_signer_in_body(body: str, fn_name: str) -> bool:
    patterns = [
        r"require!\s*\(",
        r"\.is_signer",
        r"Signer",
    ]
    return any(re.search(p, body) for p in patterns)


def _check_owner_in_body(body: str, fn_name: str = "", full_code: str = "") -> bool:
    patterns = [
        r"\.owner\s*==",
        r"has_one\s*=",
        r"require!\s*\(.*owner",
        r"constraint\s*=.*owner",
    ]
    # Check function body first
    if any(re.search(p, body) for p in patterns):
        return True
    # Also check the matching Accounts struct definition
    # Each fn maps to a struct with the same capitalised name
    if fn_name and full_code:
        struct_name = fn_name.replace("_", " ").title().replace(" ", "")
        struct_pat = re.compile(
            rf"pub struct {struct_name}<.*?{{(.*?)}}",
            re.DOTALL
        )
        m = struct_pat.search(full_code)
        if m:
            struct_body = m.group(1)
            if any(re.search(p, struct_body) for p in patterns):
                return True
    return False


def _check_math_safety(body: str) -> bool:
    has_unsafe_add = bool(re.search(r'\w+\s*\+=', body))
    has_unsafe_sub = bool(re.search(r'\w+\s*-=', body))
    has_checked = "checked_add" in body or "checked_sub" in body

    if (has_unsafe_add or has_unsafe_sub) and not has_checked:
        return False
    return True


def _analyze_security(result: ASTResult, code: str):
    # Known CPI/program fields — intentionally AccountInfo, not authority fields
    SKIP_FIELDS = {
        "target_program", "program", "token_program",
        "system_program", "rent", "clock",
        "associated_token_program", "metadata_program"
    }
    # Analyze account structs for missing signers
    for struct in result.account_structs:
        for field in struct.fields:
            if field["is_account_info"]:
                if field["name"] in SKIP_FIELDS:
                    continue
                result.findings.append({
                    "type": "missing_signer",
                    "severity": "critical",
                    "location": f"struct {struct.name}, field {field['name']}, line {field['line']}",
                    "description": f"Field '{field['name']}' uses AccountInfo instead of Signer<'info'> — no authentication enforced.",
                    "line": field["line"]
                })

    # Analyze functions
    for fn in result.functions:
        if fn.name in ("withdraw", "transfer", "burn", "close_account"):
            if not fn.has_owner_check:
                result.findings.append({
                    "type": "missing_owner_check",
                    "severity": "critical",
                    "location": f"fn {fn.name}, line {fn.line}",
                    "description": f"Function '{fn.name}' does not verify the caller is the account owner.",
                    "line": fn.line
                })

            if not fn.has_checked_math:
                result.findings.append({
                    "type": "unsafe_math",
                    "severity": "high",
                    "location": f"fn {fn.name}, line {fn.line}",
                    "description": f"Function '{fn.name}' uses unsafe arithmetic without checked_add/checked_sub.",
                    "line": fn.line
                })

        if fn.name == "deposit":
            if not fn.has_checked_math:
                result.findings.append({
                    "type": "integer_overflow",
                    "severity": "high",
                    "location": f"fn {fn.name}, line {fn.line}",
                    "description": f"Function 'deposit' uses += without checked_add — may overflow.",
                    "line": fn.line
                })


def format_ast_findings(ast_result: ASTResult) -> str:
    lines = []
    lines.append(f"Functions found: {len(ast_result.functions)}")
    for fn in ast_result.functions:
        lines.append(f"  fn {fn.name}() at line {fn.line}")
        lines.append(f"    signer_check={fn.has_signer}, owner_check={fn.has_owner_check}, safe_math={fn.has_checked_math}")

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

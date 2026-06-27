"""
Fact Extractor
==============
Extracts security-relevant facts from AST/CFG without hardcoded rules.
Inspired by SseRex symbolic execution oracles.
"""
import re
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class SecurityFact:
    layer: str
    fact_type: str
    function: str
    line: int
    target: str
    context: Dict[str, Any]

    def to_dict(self):
        return {
            "layer": self.layer,
            "fact_type": self.fact_type,
            "function": self.function,
            "line": self.line,
            "target": self.target,
            "context": self.context,
        }


class FactExtractor:
    """Extract facts from source code for KB matching."""

    def extract_all(self, source_code: str, ast_result=None, cfg_result=None) -> List[Dict]:
        facts = []
        facts.extend(self._extract_ast_facts(source_code, ast_result))
        facts.extend(self._extract_cfg_facts(source_code, cfg_result))
        facts.extend(self._extract_symbolic_facts(source_code))
        return [f.to_dict() for f in facts]

    def _extract_ast_facts(self, code: str, ast_result) -> List[SecurityFact]:
        facts = []

        if ast_result and hasattr(ast_result, 'functions'):
            for func in ast_result.functions:
                attrs = func.__dict__ if hasattr(func, '__dict__') else (func if isinstance(func, dict) else {})

                fact = SecurityFact(
                    layer="ast",
                    fact_type="function_analysis",
                    function=attrs.get("name", "unknown"),
                    line=attrs.get("line", 0),
                    target=attrs.get("name", "unknown"),
                    context={
                        "has_signer": attrs.get("has_signer", False),
                        "has_owner_check": attrs.get("has_owner_check", False),
                        "has_checked_math": attrs.get("has_checked_math", False),
                        "body": attrs.get("body", "")[:200],
                    }
                )
                facts.append(fact)
        else:
            # Fallback: regex-based extraction
            lines = code.split('\n')
            for i, line in enumerate(lines):
                match = re.match(r'\s*pub\s+fn\s+(\w+)', line)
                if match:
                    func_name = match.group(1)
                    body = '\n'.join(lines[i:min(i+50, len(lines))])

                    fact = SecurityFact(
                        layer="ast",
                        fact_type="function_analysis",
                        function=func_name,
                        line=i+1,
                        target=func_name,
                        context={
                            "has_signer": "is_signer" in body or "Signer<" in body,
                            "has_owner_check": "owner" in body or "&id()" in body,
                            "has_checked_math": "checked_add" in body or "checked_sub" in body,
                            "body": body[:200],
                        }
                    )
                    facts.append(fact)

        return facts

    def _extract_cfg_facts(self, code: str, cfg_result) -> List[SecurityFact]:
        facts = []

        if cfg_result and isinstance(cfg_result, dict):
            for func_name, func_data in cfg_result.get("function_facts", {}).items():
                for block in func_data.get("blocks", []):
                    tags = block.get("tags", {})

                    fact = SecurityFact(
                        layer="cfg",
                        fact_type="block_analysis",
                        function=func_name,
                        line=block.get("line_start", 0),
                        target=f"block_{block.get('id', 'unknown')}",
                        context={
                            "signer_check": block.get("has_signer", False),
                            "owner_check": block.get("has_owner", False),
                            "unchecked_math": block.get("unchecked_math", False),
                            "has_arithmetic": block.get("has_arithmetic", False),
                            "transfer": block.get("has_transfer", False),
                            "close": block.get("has_close", False),
                            "init": block.get("has_init", False),
                            "cpi": block.get("has_cpi", False),
                            "lines": block.get("lines", [])[:5],
                        }
                    )
                    facts.append(fact)

        return facts

    def _extract_symbolic_facts(self, code: str) -> List[SecurityFact]:
        facts = []
        lines = code.split('\n')

        current_func = None
        func_accounts = set()
        func_checks = set()
        func_actions = set()
        func_start_line = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            func_match = re.match(r'pub\s+fn\s+(\w+)', stripped)
            if func_match:
                if current_func and func_accounts:
                    unchecked = func_accounts - func_checks
                    for acc in unchecked:
                        if func_actions:
                            facts.append(SecurityFact(
                                layer="symbolic",
                                fact_type="unchecked_account_usage",
                                function=current_func,
                                line=func_start_line,
                                target=acc,
                                context={
                                    "checks_found": list(func_checks),
                                    "actions_found": list(func_actions),
                                    "unchecked_accounts": list(unchecked),
                                }
                            ))

                current_func = func_match.group(1)
                func_start_line = i + 1
                func_accounts = set()
                func_checks = set()
                func_actions = set()

            if current_func:
                accounts = re.findall(r'ctx\.accounts\.(\w+)', line)
                func_accounts.update(accounts)

                if '.is_signer' in line or 'Signer<' in line:
                    func_checks.add('signer')
                if '.owner' in line or 'owner_check' in line:
                    func_checks.add('owner')
                if '.key' in line:
                    func_checks.add('key')

                if 'invoke(' in line or 'invoke_signed(' in line:
                    func_actions.add('cpi')
                if '.lamports' in line or 'transfer' in line:
                    func_actions.add('transfer')
                if '.close(' in line:
                    func_actions.add('close')
                if '.assign(' in line or '.data.borrow_mut()' in line:
                    func_actions.add('write')

        return facts

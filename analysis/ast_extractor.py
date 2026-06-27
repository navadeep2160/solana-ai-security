"""
AST Fact Extractor
==================
Extracts structured facts from Rust/Anchor AST for KB matching.
"""
import re
from typing import List, Dict, Any

class ASTFactExtractor:
    """Extract security-relevant facts from parsed AST."""

    def __init__(self):
        self.facts = []

    def extract(self, ast_result) -> List[Dict[str, Any]]:
        """Extract facts from AST parse result."""
        self.facts = []

        for func in getattr(ast_result, 'functions', []):
            self._extract_function_fact(func)

        for account in getattr(ast_result, 'accounts', []):
            self._extract_account_fact(account)

        return self.facts

    def _extract_function_fact(self, func):
        """Extract security facts from a FunctionInfo object."""
        # Handle both object attributes and dict access
        if hasattr(func, '__dict__'):
            attrs = func.__dict__
        elif isinstance(func, dict):
            attrs = func
        else:
            attrs = {}

        fact = {
            "type": "function",
            "name": attrs.get("name", "unknown"),
            "line": attrs.get("line", 0),
            "has_signer_check": attrs.get("has_signer", False),
            "has_owner_check": attrs.get("has_owner_check", False),
            "has_safe_math": attrs.get("has_checked_math", False),
            "operations": [],
            "risk_indicators": [],
        }

        body = attrs.get("body", "")
        if body:
            if "-=" in body or "+=" in body or "*=" in body:
                fact["operations"].append("arithmetic")
            if "invoke" in body or "cpi" in body.lower():
                fact["operations"].append("cpi")
            if ".close" in body or "close_account" in body:
                fact["operations"].append("close")
            if ".transfer" in body or "transfer_lamports" in body:
                fact["operations"].append("transfer")
            if "reinit" in body.lower() or "initialize" in body.lower():
                fact["operations"].append("init")

        if not fact["has_signer_check"]:
            fact["risk_indicators"].append("no_signer")
        if not fact["has_owner_check"]:
            fact["risk_indicators"].append("no_owner")
        if not fact["has_safe_math"] and "arithmetic" in fact["operations"]:
            fact["risk_indicators"].append("unchecked_math")
        if "cpi" in fact["operations"] and not fact["has_signer_check"]:
            fact["risk_indicators"].append("unchecked_cpi")
        if "transfer" in fact["operations"] and not fact["has_signer_check"]:
            fact["risk_indicators"].append("unchecked_transfer")
        if "close" in fact["operations"] and not fact["has_signer_check"]:
            fact["risk_indicators"].append("unchecked_close")
        if "init" in fact["operations"] and not fact["has_signer_check"]:
            fact["risk_indicators"].append("unchecked_init")

        self.facts.append(fact)

    def _extract_account_fact(self, account):
        """Extract security facts from an account struct."""
        if hasattr(account, '__dict__'):
            attrs = account.__dict__
        elif isinstance(account, dict):
            attrs = account
        else:
            attrs = {}

        fact = {
            "type": "account_struct",
            "name": attrs.get("name", "unknown"),
            "line": attrs.get("line", 0),
            "has_signer": attrs.get("signer", False),
            "account_type": attrs.get("type", "Account<'info>"),
            "risk_indicators": [],
        }

        if not fact["has_signer"]:
            if "AccountInfo" in fact["account_type"]:
                fact["risk_indicators"].append("unchecked_account_info")
            if "Account<'info" in fact["account_type"] and "init" not in str(attrs.get("constraints", "")).lower():
                fact["risk_indicators"].append("mutable_without_signer")

        self.facts.append(fact)

    def extract_raw_facts(self, source_code: str) -> List[Dict[str, Any]]:
        """Fallback: extract facts directly from source code."""
        facts = []
        lines = source_code.split('\n')

        for i, line in enumerate(lines):
            func_match = re.search(r'pub\s+fn\s+(\w+)\s*\(', line)
            if func_match:
                func_name = func_match.group(1)
                func_body = '\n'.join(lines[i:i+30])

                fact = {
                    "type": "function",
                    "name": func_name,
                    "line": i + 1,
                    "has_signer_check": "is_signer" in func_body or "signer" in func_body,
                    "has_owner_check": "owner" in func_body or "&id()" in func_body,
                    "has_safe_math": "checked_add" in func_body or "checked_sub" in func_body,
                    "operations": [],
                    "risk_indicators": [],
                }

                if any(op in func_body for op in ['-=', '+=', '*=']):
                    fact["operations"].append("arithmetic")
                if "invoke" in func_body:
                    fact["operations"].append("cpi")
                if ".close" in func_body:
                    fact["operations"].append("close")
                if ".transfer" in func_body:
                    fact["operations"].append("transfer")

                if not fact["has_signer_check"]:
                    fact["risk_indicators"].append("no_signer")
                if not fact["has_owner_check"]:
                    fact["risk_indicators"].append("no_owner")
                if not fact["has_safe_math"] and "arithmetic" in fact["operations"]:
                    fact["risk_indicators"].append("unchecked_math")

                facts.append(fact)

        return facts

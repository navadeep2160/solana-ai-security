import re


def detect_missing_signer(code: str):
    findings = []
    # Find AccountInfo without /// CHECK — means no signer validation
    account_info_blocks = re.findall(
        r'pub\s+\w+:\s*AccountInfo',
        code
    )
    if account_info_blocks:
        findings.append({
            "type": "missing_signer_check",
            "severity": "critical",
            "description": f"Found {len(account_info_blocks)} AccountInfo field(s) without signer validation — use Signer<'info> instead."
        })
    return findings


def detect_missing_owner_check(code: str):
    findings = []
    owner_patterns = [
        r"has_one\s*=",
        r"constraint\s*=.*owner",
        r"require!\(.*owner",
        r"\.owner\s*==",
    ]
    found = any(re.search(p, code) for p in owner_patterns)
    if not found:
        findings.append({
            "type": "missing_owner_check",
            "severity": "high",
            "description": "No owner validation found — add has_one constraint or require!(caller == owner)."
        })
    return findings


def detect_integer_underflow(code: str):
    findings = []
    if re.search(r'\w+\s*-=\s*\w+', code) and "checked_sub" not in code:
        findings.append({
            "type": "integer_underflow",
            "severity": "critical",
            "description": "Unsafe subtraction (-=) without checked_sub — may underflow to u64::MAX."
        })
    return findings


def detect_integer_overflow(code: str):
    findings = []
    if re.search(r'\w+\s*\+=\s*\w+', code) and "checked_add" not in code:
        findings.append({
            "type": "integer_overflow",
            "severity": "high",
            "description": "Unsafe addition (+=) without checked_add — may overflow to 0."
        })
    return findings


def detect_unchecked_account_closure(code: str):
    findings = []
    if "close_account" in code or "close =" not in code:
        if "balance = 0" in code and "close =" not in code:
            findings.append({
                "type": "unchecked_account_closure",
                "severity": "medium",
                "description": "Account closure sets balance=0 but missing close= constraint — rent not returned to owner."
            })
    return findings


def detect_missing_signer_on_withdraw(code: str):
    findings = []
    # Check if withdraw function exists and user is AccountInfo not Signer
    if "fn withdraw" in code:
        withdraw_block = re.search(
            r'pub struct Withdraw.*?(?=pub struct|\Z)',
            code, re.DOTALL
        )
        if withdraw_block:
            block = withdraw_block.group(0)
            if "AccountInfo" in block and "Signer" not in block:
                findings.append({
                    "type": "withdraw_missing_signer",
                    "severity": "critical",
                    "description": "Withdraw context uses AccountInfo instead of Signer — anyone can call withdraw."
                })
    return findings


def run_all_checks(code: str):
    findings = []
    findings.extend(detect_missing_signer(code))
    findings.extend(detect_missing_owner_check(code))
    findings.extend(detect_integer_underflow(code))
    findings.extend(detect_integer_overflow(code))
    findings.extend(detect_unchecked_account_closure(code))
    findings.extend(detect_missing_signer_on_withdraw(code))
    return findings

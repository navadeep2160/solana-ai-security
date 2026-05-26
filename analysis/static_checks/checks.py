import re


def detect_missing_signer(code: str):

    findings = []

    signer_patterns = [
        r"Signer<'info>",
        r"is_signer"
    ]

    found = any(
        re.search(pattern, code)
        for pattern in signer_patterns
    )

    if not found:

        findings.append({
            "type": "missing_signer_check",
            "severity": "critical",
            "description":
                "No signer validation detected."
        })

    return findings


def detect_owner_check(code: str):

    findings = []

    owner_patterns = [
        r"has_one",
        r"\.owner",
        r"owner\s*=="
    ]

    found = any(
        re.search(pattern, code)
        for pattern in owner_patterns
    )

    if not found:

        findings.append({
            "type": "missing_owner_check",
            "severity": "high",
            "description":
                "No owner validation detected."
        })

    return findings


def detect_underflow(code: str):

    findings = []

    if "-=" in code and "checked_sub" not in code:

        findings.append({
            "type": "integer_underflow",
            "severity": "critical",
            "description":
                "Unsafe subtraction may underflow."
        })

    return findings


def run_all_checks(code: str):

    findings = []

    findings.extend(
        detect_missing_signer(code)
    )

    findings.extend(
        detect_owner_check(code)
    )

    findings.extend(
        detect_underflow(code)
    )

    return findings
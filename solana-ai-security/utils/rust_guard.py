def looks_like_rust(code: str) -> bool:
    bad_patterns = [
        "here is",
        "this code",
        "explanation",
        "```",
        "markdown",
        "note:",
        "step ",
    ]
    for pattern in bad_patterns:
        if pattern.lower() in code.lower():
            return False

    required = [
        "use anchor_lang",
        "#[program]",
    ]
    for req in required:
        if req not in code:
            return False

    return True
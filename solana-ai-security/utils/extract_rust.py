import re


def extract_rust(text: str) -> str:
    # Try ```rust ... ``` block first
    match = re.search(r"```rust(.*?)```", text, re.DOTALL)
    if match:
        code = match.group(1).strip()
        return _auto_fix(code)

    # Fallback: any ``` block
    match2 = re.search(r"```(.*?)```", text, re.DOTALL)
    if match2:
        code = match2.group(1).strip()
        return _auto_fix(code)

    return _auto_fix(text.strip())


def _auto_fix(code: str) -> str:
    """Fix common Anchor type mistakes Gemini makes."""

    # Fix: .key() == &bank.owner  →  .key() == bank.owner
    code = re.sub(r'\.key\(\)\s*==\s*&(\w+\.owner)', r'.key() == \1', code)
    code = re.sub(r'\.key\(\)\s*==\s*&(\w+)', r'.key() == \1', code)

    # Fix: &ctx.accounts.X.key()  →  ctx.accounts.X.key()
    code = re.sub(r'&ctx\.accounts\.(\w+)\.key\(\)', r'ctx.accounts.\1.key()', code)

    return code

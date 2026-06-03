import re

def extract_rust_code(text: str) -> str:
    """
    Extract ONLY Rust code from LLM output.
    Removes markdown, explanations, and garbage text.
    """

    # Remove ```rust ... ``` blocks first
    code_blocks = re.findall(r"```(?:rust)?(.*?)```", text, re.DOTALL)

    if code_blocks:
        return "\n".join(block.strip() for block in code_blocks)

    # fallback: remove obvious markdown lines
    lines = text.splitlines()
    clean = []

    for line in lines:
        if line.strip().startswith("The contract"):
            continue
        if line.strip().startswith("This"):
            continue
        if "contract you provided" in line:
            continue
        if line.strip().startswith("```"):
            continue

        clean.append(line)

    return "\n".join(clean).strip()
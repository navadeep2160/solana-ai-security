import re

def detect_vulnerability(text):

    text = text.lower()

    if "is_signer" in text:
        return "signer_validation"

    if "invoke" in text:
        return "unsafe_cpi"

    if "owner" in text:
        return "owner_check"

    if "overflow" in text:
        return "integer_overflow"

    return "general"


def extract_metadata(repo, path, chunk):

    return {

        "repository": repo,

        "source_path": path,

        "vulnerability_type":
            detect_vulnerability(chunk),

        "language":
            "rust" if path.endswith(".rs")
            else "markdown",

        "anchor_context":
            "anchor" in path.lower()
    }
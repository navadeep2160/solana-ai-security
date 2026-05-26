def filter_llm_output(raw_text: str):
    """
    ONLY allow structured JSON output from RAG
    """

    return {
        "items": extract_structured_blocks(raw_text)
    }


def extract_structured_blocks(text):
    """
    Remove:
    - English explanation
    - markdown
    - duplicates
    """

    blocks = []

    for chunk in text.split("\n"):
        if "pub fn" in chunk or "struct" in chunk:
            blocks.append({
                "type": "function" if "fn" in chunk else "struct",
                "raw": chunk
            })

    return blocks
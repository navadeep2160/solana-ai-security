import json
import re

def extract_json(text: str):
    """
    Extract clean JSON from LLM output (handles ```json ... ```)
    """

    if not text:
        return None

    # remove ```json and ```
    text = text.replace("```json", "").replace("```", "").strip()

    # fallback: extract first JSON block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        return json.loads(text)
    except Exception as e:
        return {
            "error": "json_parse_failed",
            "raw": text[:2000],
            "exception": str(e)
        }

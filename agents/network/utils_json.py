import json
import re

def extract_json(text: str):
    """
    Robust JSON extractor for LLM outputs (Ollama safe)
    """

    if not text:
        return None

    # remove markdown fences
    text = text.replace("```json", "").replace("```", "")

    # find JSON block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None

    try:
        return json.loads(match.group())
    except:
        return None

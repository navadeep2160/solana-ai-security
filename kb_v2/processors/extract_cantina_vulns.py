import re
import json
from pathlib import Path

HTML_FILE = "kb_v2/sources/docs/cantina_guide.html"
META_FILE = "kb_v2/raw/training_data/cantina_metadata.json"
OUT_FILE = "kb_v2/raw/training_data/cantina_generated.json"

with open(HTML_FILE, "r", encoding="utf-8") as f:
    html = f.read()

with open(META_FILE, "r") as f:
    metadata = json.load(f)

sections = {}

pattern = r"<h3>(.*?)</h3>"
matches = list(re.finditer(pattern, html, re.DOTALL))

for i, match in enumerate(matches):
    title = re.sub(r"^\d+\.\s*", "", match.group(1)).strip()

    start = match.end()

    if i + 1 < len(matches):
        end = matches[i + 1].start()
    else:
        end = len(html)

    content = html[start:end]

    text = re.sub(r"<[^>]+>", " ", content)
    text = re.sub(r"\s+", " ", text).strip()

    sections[title] = text

records = []

for idx, (name, meta) in enumerate(metadata.items(), start=1):

    explanation = sections.get(name, "")

    record = {
        "record_id": f"CAN-{idx:03d}",
        "vulnerability": name,
        "category": meta["category"],
        "severity": meta["severity"],
        "explanation": explanation[:3000],
        "references": [
            "Cantina Guide"
        ]
    }

    records.append(record)

with open(OUT_FILE, "w") as f:
    json.dump(records, f, indent=4)

print(f"Generated {len(records)} records")
print(f"Saved to {OUT_FILE}")

import json
from pathlib import Path

ROOT = Path("kb_v2/sources/github/sealevel-attacks/programs")

OUT = Path("kb_v2/raw/training_data/sealevel_generated.json")

META_FILE = Path("kb_v2/raw/training_data/sealevel_metadata.json")

with open(META_FILE) as f:
    metadata = json.load(f)

with open("kb_v2/raw/training_data/sealevel_explanations.json") as f:
    explanations = json.load(f)

records = []

for idx, folder in enumerate(sorted(ROOT.iterdir()), start=1):

    if not folder.is_dir():
        continue

    insecure = folder / "insecure" / "src" / "lib.rs"
    secure = folder / "secure" / "src" / "lib.rs"
    recommended = folder / "recommended" / "src" / "lib.rs"

    if not insecure.exists():
        continue

    meta = metadata.get(folder.name, {})

    record = {
        "record_id": f"AUTO-SEA-{idx:03}",
        "folder": folder.name,

        "vulnerability": meta.get("vulnerability", "Unknown"),
        "category": meta.get("category", "unknown"),
        "severity": meta.get("severity", "unknown"),
        "explanation": explanations.get(
    folder.name,
    "No explanation available."
),


        "bad_code": insecure.read_text(errors="ignore"),

        "fixed_code": secure.read_text(errors="ignore")
        if secure.exists()
        else "",

        "recommended_code": recommended.read_text(errors="ignore")
        if recommended.exists()
        else "",

        "references": [
            f"Sealevel-Attacks/{folder.name}"
        ]
    }

    records.append(record)

OUT.parent.mkdir(parents=True, exist_ok=True)

with open(OUT, "w") as f:
    json.dump(records, f, indent=2)

print(f"Generated {len(records)} enriched records")
print(f"Saved to {OUT}")

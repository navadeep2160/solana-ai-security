import json
import os
from datetime import datetime

def save_report(data: dict, folder="reports"):
    os.makedirs(folder, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"{folder}/solana_report_{ts}.json"

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    return path
